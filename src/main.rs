//! Rift — Phase 1a: Opaque RakNet termination relay.
//!
//! Unlike Phase 0 (raw UDP relay), the proxy now **owns the RakNet layer**.
//! `rust-raknet`'s `RaknetListener` terminates client connections, and for each
//! client a separate RakNet connection is opened to the downstream via
//! `RaknetSocket::connect_with_version`, forwarding the game-packet byte stream
//! opaquely in both directions.
//!
//! This phase does not parse Bedrock game packets. The login/encryption handshake
//! is negotiated transparently between client and server (the proxy shuttles bytes),
//! producing a working connection identical to Phase 0. The key difference is that
//! we now own the RakNet termination — a prerequisite for Phase 1b (encryption
//! termination and packet interception).

// Global allocator: mimalloc (preferred for proxies with frequent per-packet/session allocations).
// Optional feature — omitted in musl static builds (--no-default-features), falling back to the system allocator.
// In profiling builds (--features profiling) the counting allocator takes priority to measure alloc counts/bytes.
#[cfg(all(feature = "mimalloc", not(feature = "profiling")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Counting allocator for profiling only. Validates the "Hot Path Allocation = 0" goal via /metrics alloc_count.
#[cfg(feature = "profiling")]
mod profiling;
#[cfg(feature = "profiling")]
#[global_allocator]
static GLOBAL_PROF: profiling::CountingAllocator = profiling::CountingAllocator;

mod compression;
mod config;
mod console;
mod crypto;
mod downstream;
mod framing;
mod intercept;
mod jwt;
mod login;
mod metrics;
mod packets;
mod packs;
mod registry;
mod web;

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rift_raknet::{RaknetListener, RaknetSocket, Reliability};

use crate::config::Config;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rift=info".into()),
        )
        .init();

    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".into());
    let cfg = Arc::new(Config::load(&cfg_path).with_context(|| format!("failed to load config: {cfg_path}"))?);

    // Multi-core runtime. Defaults to tokio's default (logical core count) if worker_threads is unset; tunable via config.
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = cfg.runtime.worker_threads {
        if n > 0 {
            builder.worker_threads(n);
        }
    }
    let rt = builder.build().context("failed to build tokio runtime")?;
    rt.block_on(run(cfg))
}

async fn run(cfg: Arc<Config>) -> Result<()> {
    let listen_addr = cfg.listen_addr()?;
    let downstream_addr = cfg.default_server_addr()?;

    // Apply MTU cap (default 1200 for stability). Applies to both client↔proxy and proxy↔downstream negotiation.
    rift_raknet::set_mtu(cfg.listener.mtu);
    tracing::info!(mtu = cfg.listener.mtu, "MTU cap applied");

    let mut listener = RaknetListener::bind(&listen_addr)
        .await
        .map_err(|e| anyhow!("listener bind failed {listen_addr}: {e:?}"))?;

    // MOTD: if [motd] is set in config, advertise it directly (no downstream query needed).
    // Otherwise, query the default_server MOTD at startup and advertise it as-is.
    match &cfg.motd {
        Some(motd) => {
            let s = motd.to_motd_string(listen_addr.port());
            tracing::info!(motd = %s, "using static proxy MOTD");
            if let Err(e) = listener.set_full_motd(s) {
                tracing::warn!("set_full_motd failed: {e:?}");
            }
        }
        None => {
            // Timeout is required — without it, an unreachable backend causes ping to block indefinitely,
            // preventing proxy startup.
            let probe = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                RaknetSocket::ping(&downstream_addr),
            )
            .await;
            match probe {
                Ok(Ok((latency, motd))) => {
                    tracing::info!(latency_ms = latency, motd = %motd, "downstream MOTD fetched");
                    if let Err(e) = listener.set_full_motd(motd) {
                        tracing::warn!("set_full_motd failed: {e:?}");
                    }
                }
                other => {
                    tracing::warn!("downstream MOTD fetch failed/timeout ({other:?}) — using default MOTD");
                    listener
                        .set_motd("Rift", 1001, "1.26.30", "1.26.30", "Survival", listen_addr.port())
                        .await;
                }
            }
        }
    }

    let force_vv = cfg.features.force_vibrant_visuals;
    let channel_transfer = cfg.features.channel_transfer;

    // Resource packs: if enabled, load from the packs/ directory. Falls back to disabled if load fails or yields 0 packs,
    // since this is on the handshake critical path.
    let packs: Option<Arc<packs::PackStore>> = if cfg.resource_packs.enabled {
        match packs::load(&cfg.resource_packs.folder, cfg.resource_packs.force) {
            Ok(store) if !store.is_empty() => {
                tracing::info!(count = store.packs.len(), folder = %cfg.resource_packs.folder, "resource pack serving enabled");
                Some(Arc::new(store))
            }
            Ok(_) => {
                tracing::warn!(folder = %cfg.resource_packs.folder, "resource_packs.enabled but 0 packs loaded — serving disabled");
                None
            }
            Err(e) => {
                tracing::error!("resource pack load failed: {e} — serving disabled");
                None
            }
        }
    } else {
        None
    };

    let metrics = Arc::new(metrics::Metrics::default());
    metrics.spawn_logger(cfg.metrics.log_interval_secs);
    // Optional time-series metrics collection. Can be left enabled on production servers for later analysis.
    if let Some(hist) = &cfg.metrics.history_file {
        metrics.spawn_history(hist.clone(), cfg.metrics.history_interval_secs);
        tracing::info!(file = %hist, "metrics history recording started (JSONL)");
    }

    // Session registry (single source of truth for console/web queries and control) + shutdown signal for console stop.
    let registry = Arc::new(registry::Registry::default());
    let shutdown = Arc::new(tokio::sync::Notify::new());

    // Optional web monitoring: exposes HTTP dashboard/JSON when [metrics] web_addr is set.
    if let Some(wa) = &cfg.metrics.web_addr {
        match wa.parse::<std::net::SocketAddr>() {
            Ok(addr) => web::spawn(metrics.clone(), registry.clone(), addr),
            Err(e) => tracing::warn!(web_addr = %wa, "web_addr parse failed — web monitoring disabled: {e}"),
        }
    }

    // Console commands (stdin). Exits silently on EOF when running in the background.
    console::spawn(registry.clone(), metrics.clone(), shutdown.clone());

    listener.listen().await;
    tracing::info!(
        %listen_addr,
        default_server = %cfg.listener.default_server,
        %downstream_addr,
        force_vibrant_visuals = force_vv,
        channel_transfer,
        "Rift Phase 1b-A (plaintext termination + interception) started"
    );

    loop {
        let client = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal (Ctrl+C) received — stopping accept loop");
                break;
            }
            _ = shutdown.notified() => {
                tracing::info!("console stop — stopping accept loop");
                break;
            }
            accept = listener.accept() => match accept {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("accept failed: {e:?}");
                    continue;
                }
            },
        };
        let peer = client.peer_addr().ok();
        // Connect to downstream using the RakNet version negotiated by the client for compatibility.
        let version = client.raknet_version().unwrap_or(11);
        tracing::info!(?peer, raknet_version = version, "client connection accepted");

        let cfg = cfg.clone();
        let packs = packs.clone();
        let metrics = metrics.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let server = match RaknetSocket::connect_with_version(&downstream_addr, version).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(?peer, "downstream connection failed: {e:?}");
                    let _ = client.close().await;
                    return;
                }
            };
            tracing::info!(?peer, %downstream_addr, "downstream connected, starting relay");
            relay(client, server, cfg, version, packs, metrics, registry).await;
            tracing::info!(?peer, "session closed");
        });
    }
    Ok(())
}

/// Relays game packets between client and server.
/// - up (client→server): opaque pass-through (+ one-time Login capture for transfer replay).
/// - down (server→client): decode on VV flip / TransferPacket detection; otherwise opaque pass-through.
/// If either side disconnects (recv error), both sockets are closed and the session ends.
async fn relay(
    client: RaknetSocket,
    mut server: RaknetSocket,
    cfg: Arc<Config>,
    version: u8,
    packs: Option<Arc<packs::PackStore>>,
    metrics: Arc<metrics::Metrics>,
    registry: Arc<registry::Registry>,
) {
    use intercept::Outcome;
    let force_vv = cfg.features.force_vibrant_visuals;
    let channel_transfer = cfg.features.channel_transfer;
    let mut state = intercept::SessionState::default();
    let mut current_server = cfg.listener.default_server.clone();
    metrics.on_connect(&current_server);

    // Register session (for console/web queries and control). The control channel injects console transfer/kick
    // commands into the select loop.
    let peer = client
        .peer_addr()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::channel::<registry::Control>(8);
    let session_id = registry.register(peer, current_server.clone(), ctl_tx);
    let mut identity_set = false;
    // Periodically update the client↔proxy RTT (ping) in the registry for web/console display.
    let mut rtt_tick = tokio::time::interval(std::time::Duration::from_secs(3));

    loop {
        let mut transfer_to: Option<String> = None;
        tokio::select! {
            _ = rtt_tick.tick() => {
                let rtt = client.rtt().await;
                registry.set_rtt(session_id, rtt.max(0) as u32);
            }
            cmd = ctl_rx.recv() => match cmd {
                Some(registry::Control::Transfer(t)) => {
                    tracing::info!(session_id, target = %t, "console transfer requested");
                    transfer_to = Some(t);
                }
                Some(registry::Control::Kick) => {
                    tracing::info!(session_id, "console kick");
                    break;
                }
                None => {}
            },
            up = client.recv() => match up {
                Ok(data) => {
                    metrics.on_bytes_up(data.len());
                    match intercept::intercept_up(&mut state, &data, packs.as_deref()) {
                        Outcome::Forward => {
                            // zero-copy: forward the received Bytes to downstream without copying.
                            if server.send_bytes(data, Reliability::ReliableOrdered).await.is_err() {
                                break;
                            }
                        }
                        Outcome::Replace(out) => {
                            if server.send(&out, Reliability::ReliableOrdered).await.is_err() {
                                break;
                            }
                        }
                        Outcome::Inject { to_client, to_server } => {
                            if !send_all(&client, &to_client).await || !send_all(&server, &to_server).await {
                                break;
                            }
                        }
                        Outcome::Transfer(_) => {} // never occurs on the upstream path
                    }
                }
                Err(_) => break,
            },
            down = server.recv() => match down {
                Ok(data) => {
                    let fwd_t0 = std::time::Instant::now();
                    metrics.on_bytes_down(data.len());
                    match intercept::intercept_down(&mut state, &data, force_vv, channel_transfer, packs.as_deref()) {
                        Outcome::Forward => {
                            // zero-copy: forward the received Bytes to the client without copying.
                            if client.send_bytes(data, Reliability::ReliableOrdered).await.is_err() {
                                break;
                            }
                            metrics.on_forward(fwd_t0.elapsed());
                        }
                        Outcome::Replace(out) => {
                            if client.send(&out, Reliability::ReliableOrdered).await.is_err() {
                                break;
                            }
                        }
                        Outcome::Inject { to_client, to_server } => {
                            if !send_all(&client, &to_client).await || !send_all(&server, &to_server).await {
                                break;
                            }
                        }
                        Outcome::Transfer(target) => {
                            // Handle after the select! borrow is released (requires swapping server).
                            transfer_to = Some(target);
                        }
                    }
                }
                // Current downstream disconnected. End the session unless a transfer is in progress.
                Err(_) => break,
            },
        }

        // Extract name/XUID from the captured Login packet once and populate the registry (for console list and web display).
        if !identity_set {
            if let Some(login) = state.captured_login() {
                let id = login::extract(login);
                if id.name.is_some() || id.xuid.is_some() {
                    registry.set_identity(session_id, id.name, id.xuid);
                }
                identity_set = true; // skip re-parsing even if extraction failed
            }
        }

        if let Some(target) = transfer_to {
            match do_transfer(&cfg, &mut state, &target, version, &client, &mut server).await {
                Ok(true) => {
                    tracing::info!(%target, "transfer complete");
                    metrics.on_transfer(&current_server, &target);
                    registry.set_server(session_id, target.clone());
                    current_server = target;
                }
                Ok(false) => {
                    // Transfer cancelled (target unreachable, rejected, lobby redirect, etc.).
                    // Player remains on the current server — no disconnect.
                    metrics.on_transfer_failed();
                    tracing::info!(%target, current = %current_server, "transfer cancelled — keeping current server");
                }
                Err(e) => {
                    // Fatal failure after the swap (unrecoverable) — end the session.
                    metrics.on_transfer_failed();
                    tracing::warn!(%target, "fatal error during transfer: {e} — closing session");
                    break;
                }
            }
        }
    }
    registry.remove(session_id);
    metrics.on_disconnect(&current_server);
    let _ = client.close().await;
    let _ = server.close().await;
}

/// Sends multiple game-packet messages in order. Returns false on the first failure.
async fn send_all(sock: &RaknetSocket, msgs: &[Vec<u8>]) -> bool {
    for m in msgs {
        if sock.send(m, Reliability::ReliableOrdered).await.is_err() {
            return false;
        }
    }
    true
}

/// Compresses a single game packet (zlib) and sends it over the socket (used for transfer sequence injection).
async fn send_pkt(sock: &RaknetSocket, pkt: &[u8]) -> Result<()> {
    let msg = packets::frame_game_packet(pkt, true, compression::ZLIB)?;
    sock.send(&msg, Reliability::ReliableOrdered)
        .await
        .map_err(|e| anyhow!("packet send failed: {e:?}"))?;
    Ok(())
}

/// Performs a transparent channel transfer (connect-before-disconnect). Ported from the Spectrum verification sequence.
///
/// Key steps: ① Drive the new server (B) through **full spawn** rather than stopping at StartGame
/// (RequestChunkRadius → chunk stream buffer → PlayStatus). ② Send the client a **dimension flip**
/// (must differ from the current dimension) to flush the old world (chunk/entity cache) and fill the
/// loading screen with empty chunks. ③ After the swap, trigger doFirstSpawn on B via
/// SetLocalPlayerAsInitialized. ④ Return to overworld and replay the buffered real spawn stream.
///
/// No entity ID rewriting — the deterministic ID plugin (crc32(XUID)) guarantees the same ID on both A and B.
async fn do_transfer(
    cfg: &Arc<Config>,
    state: &mut intercept::SessionState,
    target: &str,
    version: u8,
    client: &RaknetSocket,
    server: &mut RaknetSocket,
) -> Result<bool> {
    // Returns: Ok(true)=transfer complete, Ok(false)=transfer cancelled (current server kept, no disconnect),
    // Err=fatal failure after swap (session closed).
    // Failures before std::mem::replace (swap) leave the old server connection intact and are fully recoverable → Ok(false).
    let Some(login) = state.captured_login().map(|l| l.to_vec()) else {
        tracing::warn!(%target, "Login not captured — transfer cancelled (keeping current server)");
        return Ok(false);
    };
    let addr = match cfg.resolve_server(target) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(%target, "failed to resolve transfer target ({e}) — transfer cancelled (keeping current server)");
            return Ok(false);
        }
    };
    tracing::info!(%target, %addr, "transfer started — performing full spawn handshake with new downstream");

    // Handshake failure (target unreachable / lobby immediately redirects, etc.): keep old server, player stays.
    let ready = match downstream::connect_and_handshake(addr, version, &login).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%target, "handshake with transfer target failed ({e}) — transfer cancelled (keeping current server)");
            return Ok(false);
        }
    };
    let runtime_id = ready.runtime_id;
    let pos = ready.spawn_pos;
    let gamemode = ready.gamemode;
    let spawn_cx = (pos[0].floor() as i32) >> 4;
    let spawn_cz = (pos[2].floor() as i32) >> 4;
    tracing::info!(
        %target,
        runtime_id,
        gamemode,
        spawn_msgs = ready.spawn_buffer.len(),
        "new downstream ready for spawn — sending client transfer sequence"
    );

    // Dimension: all downstream worlds are assumed to be overworld (0). Mirroring Spectrum:
    // flip to Nether (must differ from the current dimension for the client to actually switch),
    // then restore to Overworld.
    let final_dim = packets::DIM_OVERWORLD;
    let flip_dim = packets::DIM_NETHER;
    let empty = packets::empty_chunk_payload(packets::dimension_biome_sections(final_dim));

    // (1) Play: flip to dummy dimension → client flushes old world (chunk/entity cache).
    send_pkt(client, &packets::change_dimension(flip_dim, pos, false)).await?;
    send_pkt(
        client,
        &packets::player_action(runtime_id, packets::PLAYER_ACTION_DIMENSION_CHANGE_DONE),
    )
    .await?;

    // (2) Loading screen filler for the flip dimension: 9×9 empty chunks around the spawn chunk.
    for dx in -4..=4 {
        for dz in -4..=4 {
            send_pkt(
                client,
                &packets::level_chunk(spawn_cx + dx, spawn_cz + dz, final_dim, 1, &empty),
            )
            .await?;
        }
    }

    // Gamemode HUD sync: since StartGame is not forwarded to the client, the gamemode (health bar display, etc.)
    // would remain at the old server's value — explicitly notify the client of the new server's gamemode.
    send_pkt(client, &packets::set_player_game_type(gamemode)).await?;

    // Game rule sync (best-effort): apply new server game rules (e.g. show coordinates). Transfer continues even if extraction fails.
    match packets::extract_start_game_gamerules(&ready.start_game) {
        Ok(body) => send_pkt(client, &packets::game_rules_changed(&body)).await?,
        Err(e) => tracing::warn!(%target, "game rule extraction failed (skipping): {e}"),
    }

    // Old server state teardown: remove tracked boss bars and scoreboards from the client
    // (residual state not cleared by the dimension flip).
    let (old_bossbars, old_objectives) = state.take_tracked();
    for id in &old_bossbars {
        send_pkt(client, &packets::boss_event_hide(*id)).await?;
    }
    for name in &old_objectives {
        send_pkt(client, &packets::remove_objective(name)).await?;
    }
    if !old_bossbars.is_empty() || !old_objectives.is_empty() {
        tracing::info!(
            bossbars = old_bossbars.len(),
            objectives = old_objectives.len(),
            "old server state torn down"
        );
    }

    // (3) Swap downstream A→B, close old A. ← Commit point: failures from here are unrecoverable (fatal).
    let old = std::mem::replace(server, ready.socket);
    let _ = old.close().await;

    // (4) DoSpawn → B: triggers doFirstSpawn (entity/chunk streaming).
    send_pkt(server, &packets::set_local_player_as_initialized(runtime_id)).await?;

    // (5) Clear: restore overworld + spawn.
    send_pkt(client, &packets::play_status(packets::PLAY_STATUS_PLAYER_SPAWN)).await?;
    send_pkt(client, &packets::change_dimension(final_dim, pos, true)).await?;
    send_pkt(
        client,
        &packets::player_action(runtime_id, packets::PLAYER_ACTION_DIMENSION_CHANGE_DONE),
    )
    .await?;
    send_pkt(client, &packets::play_status(packets::PLAY_STATUS_PLAYER_SPAWN)).await?;

    // (6) Replay buffered real spawn stream (chunks/inventory/entities) — messages are already framed, send as-is.
    //     The client is now in overworld and will accept chunks.
    for msg in &ready.spawn_buffer {
        client
            .send(msg, Reliability::ReliableOrdered)
            .await
            .map_err(|e| anyhow!("spawn stream replay failed: {e:?}"))?;
    }

    // Seed tracked state with the new server's initial boss bars/scoreboards (for the next transfer teardown).
    state.seed_tracked(ready.bossbars, ready.objectives);

    tracing::info!(%target, "transfer sequence sent");
    Ok(true)
}
