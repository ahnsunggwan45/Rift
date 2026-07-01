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

    // RakNet ACK/retransmit tick (ms). Default 10 (WaterdogPE parity); lower = tighter ACK/loss recovery.
    let ack_tick = cfg.runtime.ack_tick_ms.unwrap_or(10);
    rift_raknet::set_ack_tick_ms(ack_tick);
    tracing::info!(ack_tick_ms = ack_tick, "RakNet ACK/retransmit tick configured");

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

    // Diagnostic stream: if [metrics] diag_log_secs > 0, print every session's backend-connection reliability
    // state to the console on a fixed interval — a live feed to watch a stall form/hit while reproducing a
    // freeze (ordered_idx should keep climbing and wrap past 16,777,216; recvq_backlog/ordered_dropped/
    // sendq_unacked should stay 0). Off in production.
    if cfg.metrics.diag_log_secs > 0 {
        let reg = registry.clone();
        let secs = cfg.metrics.diag_log_secs.max(1);
        tracing::info!(interval_secs = secs, "diagnostic console stream ENABLED — per-session reliability lines follow (tag: diag)");
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
            loop {
                tick.tick().await;
                let sessions = reg.snapshot();
                if sessions.is_empty() {
                    tracing::info!("diag: no connected sessions");
                }
                for s in sessions {
                    tracing::info!(
                        session = s.id,
                        name = ?s.name,
                        server = %s.server,
                        rtt_ms = s.rtt_ms,
                        conn_s = s.connected_secs,
                        ordered_idx = s.ordered_index,
                        recvq_backlog = s.ordered_backlog,
                        fragment_queue = s.fragment_queue,
                        ordered_dropped = s.ordered_dropped,
                        sendq_unacked = s.sendq_unacked,
                        cli_sendq_unacked = s.cli_sendq_unacked,
                        cli_ordered_backlog = s.cli_ordered_backlog,
                        "diag"
                    );
                }
            }
        });
    }

    // Stall watchdog: logs any session whose relay loop stops progressing (a proxy-side hang), with the
    // stage it was stuck in — so an in-the-wild freeze is localized (stage=intercept_down ⇒ decompression,
    // send_client ⇒ RakNet send window, idle ⇒ no inbound packets). Silent unless a stall occurs.
    {
        let reg = registry.clone();
        tokio::spawn(async move {
            use std::collections::{HashMap, HashSet};
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.tick().await; // consume the immediate first tick
            let mut last_beat: HashMap<u64, u64> = HashMap::new();
            let mut frozen_scans: HashMap<u64, u32> = HashMap::new();
            let mut reported: HashSet<u64> = HashSet::new();
            loop {
                tick.tick().await;
                let snap = reg.health_snapshot();
                let live: HashSet<u64> = snap.iter().map(|h| h.id).collect();
                last_beat.retain(|k, _| live.contains(k));
                frozen_scans.retain(|k, _| live.contains(k));
                reported.retain(|k| live.contains(k));
                for h in &snap {
                    if last_beat.insert(h.id, h.loop_beat) == Some(h.loop_beat) {
                        let c = frozen_scans.entry(h.id).or_insert(0);
                        *c += 1;
                        // 3 consecutive unchanged 5s scans ≈ 15s with no loop progress → stalled.
                        if *c >= 3 && reported.insert(h.id) {
                            tracing::error!(
                                session = h.id,
                                name = ?h.name,
                                stage = registry::stage::name(h.stage),
                                "RELAY STALL: loop has not progressed for ~15s (proxy-side hang)"
                            );
                        }
                    } else {
                        frozen_scans.insert(h.id, 0);
                        reported.remove(&h.id);
                    }
                }
            }
        });
    }

    listener.listen().await;
    tracing::info!(
        %listen_addr,
        default_server = %cfg.listener.default_server,
        %downstream_addr,
        force_vibrant_visuals = force_vv,
        channel_transfer,
        max_decode_batch_bytes = cfg.features.max_decode_batch_bytes,
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
    let max_decode = cfg.features.max_decode_batch_bytes;
    let mut state = intercept::SessionState::default();
    let mut current_server = cfg.listener.default_server.clone();
    metrics.on_connect(&current_server);

    // Register session (for console/web queries and control). The control channel injects console transfer/kick
    // commands into the select loop.
    let peer = client
        .peer_addr()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::channel::<registry::Control>(8);
    // Per-session health for the stall watchdog (records the current stage + a loop heartbeat).
    let health = std::sync::Arc::new(registry::Health::default());
    let session_id = registry.register(peer, current_server.clone(), ctl_tx, health.clone());
    let mut identity_set = false;
    // Periodically update the client↔proxy RTT (ping) in the registry for web/console display.
    let mut rtt_tick = tokio::time::interval(std::time::Duration::from_secs(3));
    // Frozen-session detection: track when data last actually flowed each way. If downstream data stops
    // reaching the client while the client is still sending (a silent freeze), dump the RakNet queue depths.
    let mut last_down_fwd = std::time::Instant::now();
    let mut last_up_fwd = std::time::Instant::now();
    // One seamless auto-recovery attempt per freeze episode (reset once downstream flows again).
    let mut auto_recovered = false;

    loop {
        let mut transfer_to: Option<String> = None;
        // Watchdog heartbeat: one beat per loop iteration; stage resets to idle while waiting in select.
        health.beat();
        health.set_stage(registry::stage::IDLE);
        tokio::select! {
            _ = rtt_tick.tick() => {
                health.set_stage(registry::stage::RTT);
                let rtt = client.rtt().await;
                registry.set_rtt(session_id, rtt.max(0) as u32);
                // Sample the backend connection's ordered-delivery state for the dashboard (stall watching).
                let (oi, ob, _od_delivered, odrop, su, ofrag) = server.reliability_diag();
                let cd = client.reliability_diag(); // (_, backlog, _, _, sendq_unacked, _)
                health.set_diag(oi, ob, ofrag, odrop, su, cd.4, cd.1);
                // Silent-freeze detector: downstream data has stopped reaching the client for a while, yet the
                // client is still actively sending. Dump the RakNet queue depths so the stalled layer shows up
                // (server_recvq_* deep = backend→proxy ordered/fragment stall; client_sendq_* deep = client not
                // ACKing; all ~0 = backend stopped sending; usize::MAX = that lock was held).
                if last_down_fwd.elapsed().as_secs() >= 10 && last_up_fwd.elapsed().as_secs() < 8 {
                    let c = client.queue_stats();
                    let s = server.queue_stats();
                    let down_starved = last_down_fwd.elapsed().as_secs();
                    tracing::warn!(
                        session_id,
                        down_starved_s = down_starved,
                        up_age_s = last_up_fwd.elapsed().as_secs(),
                        client_recvq_ordered = c.0, client_recvq_frag = c.1, client_recvq_pending = c.2,
                        client_sendq_unacked = c.3, client_sendq_queued = c.4,
                        server_recvq_ordered = s.0, server_recvq_frag = s.1, server_recvq_pending = s.2,
                        server_sendq_unacked = s.3, server_sendq_queued = s.4,
                        "SESSION FROZEN: no downstream data reaching client while client is active — queue snapshot"
                    );
                    // Recovery: downstream dead for 45s+ while the client is still actively sending is a real
                    // stall, not an idle player. The user confirmed a console transfer un-sticks it (a fresh
                    // proxy↔backend connection), so first automate exactly that — re-transfer to the *current*
                    // server (seamless; the client connection is preserved). If that doesn't take (e.g. the
                    // backend rejects the duplicate login → Ok(false), still frozen), force a clean disconnect
                    // on the next check so the player relogs. Either way no session stays frozen indefinitely.
                    if down_starved >= 45 {
                        if !auto_recovered {
                            auto_recovered = true;
                            tracing::error!(session_id, down_starved_s = down_starved, %current_server, "SESSION FROZEN 45s — auto-reconnecting backend (re-transfer to current server)");
                            transfer_to = Some(current_server.clone());
                        } else {
                            tracing::error!(session_id, down_starved_s = down_starved, "SESSION FROZEN — auto-reconnect did not restore flow, forcing disconnect");
                            break;
                        }
                    }
                }
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
                    health.set_stage(registry::stage::INTERCEPT_UP);
                    last_up_fwd = std::time::Instant::now();
                    metrics.on_bytes_up(data.len());
                    match intercept::intercept_up(&mut state, &data, packs.as_deref()) {
                        Outcome::Forward => {
                            // zero-copy: forward the received Bytes to downstream without copying.
                            health.set_stage(registry::stage::SEND_SERVER);
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
                    health.set_stage(registry::stage::INTERCEPT_DOWN);
                    last_down_fwd = std::time::Instant::now();
                    auto_recovered = false; // downstream is flowing again — re-arm auto-recovery
                    let fwd_t0 = std::time::Instant::now();
                    metrics.on_bytes_down(data.len());
                    match intercept::intercept_down(&mut state, &data, force_vv, channel_transfer, max_decode, packs.as_deref()) {
                        Outcome::Forward => {
                            // zero-copy: forward the received Bytes to the client without copying.
                            health.set_stage(registry::stage::SEND_CLIENT);
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
            health.set_stage(registry::stage::TRANSFER);
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

/// NetworkChunkPublisherUpdate radius sent during a transfer dimension change (mirrors WaterdogPE's
/// small value — the filler chunks cover it, so the client finalizes the transition immediately).
const CHUNK_PUBLISH_RADIUS: u32 = 3;

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

    // Tear down the old server's actor entities BEFORE the dimension flip — RemoveActor is reliably
    // honored while the client is still in the entity's dimension. (A dimension change does NOT
    // despawn actor entities client-side, so without this they ghost after transfer.)
    let (old_bossbars, old_objectives, old_entities) = state.take_tracked();
    // Always-on diagnostic: confirms this build is live and reports how many entities were tracked.
    tracing::info!(
        tracked_entities = old_entities.len(),
        bossbars = old_bossbars.len(),
        objectives = old_objectives.len(),
        %target,
        "transfer teardown — removing tracked entities before flip"
    );
    let mut removed_entities = 0usize;
    for uid in &old_entities {
        if *uid as u64 == runtime_id {
            continue; // never despawn the player's own entity (crc32(XUID) identical on both servers)
        }
        send_pkt(client, &packets::remove_actor(*uid)).await?;
        removed_entities += 1;
    }

    // Dimension: all downstream worlds are assumed to be overworld (0). Mirroring Spectrum:
    // flip to Nether (must differ from the current dimension for the client to actually switch),
    // then restore to Overworld.
    let final_dim = packets::DIM_OVERWORLD;
    let flip_dim = packets::DIM_NETHER;
    // Filler chunks must match the dimension the client is currently in (the flip dimension), not the
    // final one. A mismatched dimension/biome-section count (24 overworld vs 8 nether) corrupts the
    // chunk parse during the transition and destabilizes the client renderer (glyph/HUD glitches).
    let empty = packets::empty_chunk_payload(packets::dimension_biome_sections(flip_dim));

    // (1) Flip to the dummy dimension — full WaterdogPE injectDimensionChange sequence so the client
    //     actually COMPLETES the transition (and re-initializes its render state, incl. font glyph
    //     atlases). The previously-missing NetworkChunkPublisherUpdate + the server-sent
    //     DIMENSION_CHANGE_ACK PlayerAction are what let the client finish; without them it stays
    //     half-transitioned and custom unicode glyphs render blank on the new server.
    send_pkt(client, &packets::change_dimension(flip_dim, pos, true)).await?;
    send_pkt(client, &packets::network_chunk_publisher_update(pos, CHUNK_PUBLISH_RADIUS)).await?;
    for dx in -3..=3 {
        for dz in -3..=3 {
            send_pkt(
                client,
                &packets::level_chunk(spawn_cx + dx, spawn_cz + dz, flip_dim, 1, &empty),
            )
            .await?;
        }
    }
    // Force the client out of the dimension loading screen, then the Mojang-quirk server-side ACK.
    send_pkt(client, &packets::play_status(packets::PLAY_STATUS_PLAYER_SPAWN)).await?;
    send_pkt(
        client,
        &packets::player_action(runtime_id, packets::PLAYER_ACTION_DIMENSION_CHANGE_DONE),
    )
    .await?;

    // No blocking ack-wait: it froze the relay (and the player) for up to the timeout while do_transfer
    // ran. The publisher update + server-side ACK above let the client complete the flip on its own;
    // the client's own ack flows through normally once the relay resumes.

    // Gamemode HUD sync: since StartGame is not forwarded to the client, the gamemode (health bar display, etc.)
    // would remain at the old server's value — explicitly notify the client of the new server's gamemode.
    send_pkt(client, &packets::set_player_game_type(gamemode)).await?;

    // Game rule sync (best-effort): apply new server game rules (e.g. show coordinates). Transfer continues even if extraction fails.
    match packets::extract_start_game_gamerules(&ready.start_game) {
        Ok(body) => send_pkt(client, &packets::game_rules_changed(&body)).await?,
        Err(e) => tracing::warn!(%target, "game rule extraction failed (skipping): {e}"),
    }

    // Boss bar / scoreboard teardown (entities were already despawned before the flip, above).
    for id in &old_bossbars {
        send_pkt(client, &packets::boss_event_hide(*id)).await?;
    }
    for name in &old_objectives {
        send_pkt(client, &packets::remove_objective(name)).await?;
    }
    // Clear weather (rain/thunder) carried over from the old server — matches WaterdogPE injectClearWeather.
    send_pkt(client, &packets::level_event(packets::LEVEL_EVENT_STOP_RAIN, 10000)).await?;
    send_pkt(client, &packets::level_event(packets::LEVEL_EVENT_STOP_THUNDER, 0)).await?;
    if !old_bossbars.is_empty() || !old_objectives.is_empty() || removed_entities > 0 {
        tracing::info!(
            bossbars = old_bossbars.len(),
            objectives = old_objectives.len(),
            entities = removed_entities,
            "old server state torn down"
        );
    }

    // (3) Swap downstream A→B, close old A. ← Commit point: failures from here are unrecoverable (fatal).
    let old = std::mem::replace(server, ready.socket);
    let _ = old.close().await;

    // (4) DoSpawn → B: triggers doFirstSpawn (entity/chunk streaming).
    send_pkt(server, &packets::set_local_player_as_initialized(runtime_id)).await?;

    // (5) Restore the real (target) dimension — same full sequence: ChangeDimension →
    //     ChunkPublisherUpdate → real chunks (B's spawn buffer) → PlayStatus → server-side ACK.
    send_pkt(client, &packets::change_dimension(final_dim, pos, true)).await?;
    send_pkt(client, &packets::network_chunk_publisher_update(pos, CHUNK_PUBLISH_RADIUS)).await?;

    // (6) Replay buffered real spawn stream (chunks/inventory/entities) — messages are already framed, send as-is.
    //     The client is now in the target dimension and will accept these chunks.
    for msg in &ready.spawn_buffer {
        client
            .send(msg, Reliability::ReliableOrdered)
            .await
            .map_err(|e| anyhow!("spawn stream replay failed: {e:?}"))?;
    }
    send_pkt(client, &packets::play_status(packets::PLAY_STATUS_PLAYER_SPAWN)).await?;
    send_pkt(
        client,
        &packets::player_action(runtime_id, packets::PLAYER_ACTION_DIMENSION_CHANGE_DONE),
    )
    .await?;

    // No blocking ack-wait (see the flip phase above) — the transfer no longer freezes player movement.

    // Seed tracked state with the new server's initial boss bars/scoreboards/entities (for the next transfer teardown).
    state.seed_tracked(ready.bossbars, ready.objectives, ready.entities);

    tracing::info!(%target, "transfer sequence sent");
    Ok(true)
}
