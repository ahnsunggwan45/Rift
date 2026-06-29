//! Rift — Phase 1a: RakNet 종단 불투명 릴레이.
//!
//! Phase 0(raw UDP 릴레이)과 달리, 이제 프록시가 **RakNet 레이어를 소유**한다.
//! `rust-raknet` 의 `RaknetListener` 로 클라 연결을 종단하고, 각 클라마다
//! `RaknetSocket::connect_with_version` 으로 다운스트림에 별도 RakNet 연결을 연 뒤,
//! 게임패킷 바이트스트림을 양방향으로 그대로(opaque) 중계한다.
//!
//! 이 단계에선 Bedrock 게임패킷을 해석하지 않는다. 로그인/암호화 핸드셰이크는
//! 클라↔서버 사이에서 그대로 성립하고(프록시는 바이트만 셔틀), 결과적으로
//! Phase 0 과 동일하게 "동작하는 연결"이 나온다. 핵심 차이는 RakNet 종단을
//! 우리가 쥐었다는 것 — 이게 Phase 1b(암호화 종단·패킷 가로채기)의 전제다.

// 전역 할당자: mimalloc (docs/performance.md #12). 매 패킷·세션 할당이 잦은 프록시에 유리.
// optional feature — musl 정적 빌드(--no-default-features)에선 빠지고 system 할당자 사용.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    let cfg = Arc::new(Config::load(&cfg_path).with_context(|| format!("설정 로드 실패: {cfg_path}"))?);

    // 멀티코어 런타임. worker_threads 미지정이면 tokio 기본(논리코어 수)을 쓴다. config 로 튜닝 가능.
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = cfg.runtime.worker_threads {
        if n > 0 {
            builder.worker_threads(n);
        }
    }
    let rt = builder.build().context("tokio 런타임 생성 실패")?;
    rt.block_on(run(cfg))
}

async fn run(cfg: Arc<Config>) -> Result<()> {
    let listen_addr = cfg.listen_addr()?;
    let downstream_addr = cfg.default_server_addr()?;

    // MTU 상한 적용(기본 1200, 안정성). 클라↔프록시·프록시↔다운스트림 협상 모두에 반영.
    rift_raknet::set_mtu(cfg.listener.mtu);
    tracing::info!(mtu = cfg.listener.mtu, "MTU 상한 설정");

    let mut listener = RaknetListener::bind(&listen_addr)
        .await
        .map_err(|e| anyhow!("리스너 bind 실패 {listen_addr}: {e:?}"))?;

    // MOTD: config 에 [motd] 가 있으면 그걸 직접 광고(다운스트림 조회 불필요).
    // 없으면 시작 시 default_server 의 MOTD 를 조회해 그대로 광고.
    match &cfg.motd {
        Some(motd) => {
            let s = motd.to_motd_string(listen_addr.port());
            tracing::info!(motd = %s, "프록시 고정 MOTD 사용");
            if let Err(e) = listener.set_full_motd(s) {
                tracing::warn!("set_full_motd 실패: {e:?}");
            }
        }
        None => match RaknetSocket::ping(&downstream_addr).await {
            Ok((latency, motd)) => {
                tracing::info!(latency_ms = latency, motd = %motd, "다운스트림 MOTD 조회 성공");
                if let Err(e) = listener.set_full_motd(motd) {
                    tracing::warn!("set_full_motd 실패: {e:?}");
                }
            }
            Err(e) => {
                tracing::warn!("다운스트림 MOTD 조회 실패({e:?}), 기본 MOTD 사용");
                listener
                    .set_motd("Rift", 1000, "1.21.0", "1.21.0", "Survival", listen_addr.port())
                    .await;
            }
        },
    }

    let force_vv = cfg.features.force_vibrant_visuals;
    let channel_transfer = cfg.features.channel_transfer;

    // 리소스팩: enabled 면 packs/ 폴더 로드. 핸드셰이크 임계 경로라 로드 실패/0개면 비활성으로 폴백.
    let packs: Option<Arc<packs::PackStore>> = if cfg.resource_packs.enabled {
        match packs::load(&cfg.resource_packs.folder, cfg.resource_packs.force) {
            Ok(store) if !store.is_empty() => {
                tracing::info!(count = store.packs.len(), folder = %cfg.resource_packs.folder, "리소스팩 서빙 활성");
                Some(Arc::new(store))
            }
            Ok(_) => {
                tracing::warn!(folder = %cfg.resource_packs.folder, "resource_packs.enabled 이나 로드된 팩 0개 — 서빙 비활성");
                None
            }
            Err(e) => {
                tracing::error!("리소스팩 로드 실패: {e} — 서빙 비활성");
                None
            }
        }
    } else {
        None
    };

    let metrics = Arc::new(metrics::Metrics::default());
    metrics.spawn_logger(cfg.metrics.log_interval_secs);

    // 세션 레지스트리(콘솔/웹의 조회·조작 단일 출처) + 콘솔 stop 용 종료 신호.
    let registry = Arc::new(registry::Registry::default());
    let shutdown = Arc::new(tokio::sync::Notify::new());

    // 웹 모니터링(선택): [metrics] web_addr 지정 시 HTTP 대시보드/JSON 노출.
    if let Some(wa) = &cfg.metrics.web_addr {
        match wa.parse::<std::net::SocketAddr>() {
            Ok(addr) => web::spawn(metrics.clone(), registry.clone(), addr),
            Err(e) => tracing::warn!(web_addr = %wa, "web_addr 파싱 실패 — 웹 모니터링 비활성: {e}"),
        }
    }

    // 콘솔 명령(stdin). 백그라운드 실행이면 EOF 로 조용히 끝난다.
    console::spawn(registry.clone(), metrics.clone(), shutdown.clone());

    listener.listen().await;
    tracing::info!(
        %listen_addr,
        default_server = %cfg.listener.default_server,
        %downstream_addr,
        force_vibrant_visuals = force_vv,
        channel_transfer,
        "Rift Phase 1b-A (평문 종단 + 인터셉션) 시작"
    );

    loop {
        let client = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("종료 신호(Ctrl+C) 수신 — 새 연결 수락 중단, 종료");
                break;
            }
            _ = shutdown.notified() => {
                tracing::info!("콘솔 stop — 새 연결 수락 중단, 종료");
                break;
            }
            accept = listener.accept() => match accept {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("accept 실패: {e:?}");
                    continue;
                }
            },
        };
        let peer = client.peer_addr().ok();
        // 클라가 협상한 RakNet 버전으로 다운스트림에 연결해야 호환된다.
        let version = client.raknet_version().unwrap_or(11);
        tracing::info!(?peer, raknet_version = version, "클라 연결 수락");

        let cfg = cfg.clone();
        let packs = packs.clone();
        let metrics = metrics.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let server = match RaknetSocket::connect_with_version(&downstream_addr, version).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(?peer, "다운스트림 연결 실패: {e:?}");
                    let _ = client.close().await;
                    return;
                }
            };
            tracing::info!(?peer, %downstream_addr, "다운스트림 연결 성립, 릴레이 시작");
            relay(client, server, cfg, version, packs, metrics, registry).await;
            tracing::info!(?peer, "세션 종료");
        });
    }
    Ok(())
}

/// 클라↔서버 게임패킷을 중계한다.
/// - up(클라→서버): 불투명 통과 (+ 전환 리플레이용 Login 1회 캡처).
/// - down(서버→클라): VV flip / TransferPacket 감지 시 디코드, 그 외 불투명 통과.
/// 한쪽이 끊기면(recv 에러) 양쪽을 닫고 종료한다.
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

    // 세션 등록(콘솔/웹 조회·조작용). control 채널로 콘솔 transfer/kick 을 select 루프에 주입.
    let peer = client
        .peer_addr()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::channel::<registry::Control>(8);
    let session_id = registry.register(peer, current_server.clone(), ctl_tx);
    let mut identity_set = false;

    loop {
        let mut transfer_to: Option<String> = None;
        tokio::select! {
            cmd = ctl_rx.recv() => match cmd {
                Some(registry::Control::Transfer(t)) => {
                    tracing::info!(session_id, target = %t, "콘솔 전환 요청");
                    transfer_to = Some(t);
                }
                Some(registry::Control::Kick) => {
                    tracing::info!(session_id, "콘솔 kick");
                    break;
                }
                None => {}
            },
            up = client.recv() => match up {
                Ok(data) => {
                    metrics.on_bytes_up(data.len());
                    match intercept::intercept_up(&mut state, &data, packs.as_deref()) {
                        Outcome::Forward => {
                            // zero-copy: recv 한 Bytes 를 복사 없이 그대로 다운스트림으로.
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
                        Outcome::Transfer(_) => {} // up 에선 발생 안 함
                    }
                }
                Err(_) => break,
            },
            down = server.recv() => match down {
                Ok(data) => {
                    metrics.on_bytes_down(data.len());
                    match intercept::intercept_down(&mut state, &data, force_vv, channel_transfer, packs.as_deref()) {
                        Outcome::Forward => {
                            // zero-copy: recv 한 Bytes 를 복사 없이 그대로 클라로.
                            if client.send_bytes(data, Reliability::ReliableOrdered).await.is_err() {
                                break;
                            }
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
                            // select! borrow 해제 후 처리 (server 교체 필요).
                            transfer_to = Some(target);
                        }
                    }
                }
                // 현재 다운스트림이 끊김. 전환 중이 아니면 세션 종료.
                Err(_) => break,
            },
        }

        // Login 캡처 직후 이름/XUID 를 1회 추출해 레지스트리에 채운다(콘솔 list·웹 표시용).
        if !identity_set {
            if let Some(login) = state.captured_login() {
                let id = login::extract(login);
                if id.name.is_some() || id.xuid.is_some() {
                    registry.set_identity(session_id, id.name, id.xuid);
                }
                identity_set = true; // 추출 실패해도 재파싱 안 함
            }
        }

        if let Some(target) = transfer_to {
            match do_transfer(&cfg, &mut state, &target, version, &client, &mut server).await {
                Ok(()) => {
                    tracing::info!(%target, "채널이동 스위치 완료");
                    metrics.on_transfer(&current_server, &target);
                    registry.set_server(session_id, target.clone());
                    current_server = target;
                }
                Err(e) => {
                    metrics.on_transfer_failed();
                    tracing::warn!(%target, "채널이동 실패: {e} — 세션 종료");
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

/// 여러 게임패킷 메시지를 순서대로 보낸다. 하나라도 실패하면 false.
async fn send_all(sock: &RaknetSocket, msgs: &[Vec<u8>]) -> bool {
    for m in msgs {
        if sock.send(m, Reliability::ReliableOrdered).await.is_err() {
            return false;
        }
    }
    true
}

/// 단일 게임패킷을 압축(zlib)해 소켓으로 보낸다 (전환 시퀀스 주입용).
async fn send_pkt(sock: &RaknetSocket, pkt: &[u8]) -> Result<()> {
    let msg = packets::frame_game_packet(pkt, true, compression::ZLIB)?;
    sock.send(&msg, Reliability::ReliableOrdered)
        .await
        .map_err(|e| anyhow!("패킷 전송 실패: {e:?}"))?;
    Ok(())
}

/// 투명 채널이동 수행 (connect-before-disconnect). Spectrum 검증 시퀀스 이식.
///
/// 핵심: ① 새 서버(B)를 StartGame 에서 멈추지 말고 **풀 스폰까지** 구동(RequestChunkRadius →
/// 청크 스트림 버퍼 → PlayStatus). ② 클라에 **차원 플립**(현재≠다른 차원이어야 실제 전환됨)으로
/// 옛 월드를 비우고 빈 청크로 로딩 화면을 채운다. ③ 스왑 후 B 에 SetLocalPlayerAsInitialized 로
/// doFirstSpawn 트리거. ④ overworld 복귀 + 버퍼된 실제 스폰 스트림 재생.
///
/// 엔티티 ID 재작성은 없음 — 결정론 ID 플러그인(crc32(XUID))이 A·B 에서 같은 id 를 보장한다.
async fn do_transfer(
    cfg: &Arc<Config>,
    state: &mut intercept::SessionState,
    target: &str,
    version: u8,
    client: &RaknetSocket,
    server: &mut RaknetSocket,
) -> Result<()> {
    let login = state
        .captured_login()
        .ok_or_else(|| anyhow!("Login 미캡처 — 전환 불가"))?
        .to_vec();
    let addr = cfg.resolve_server(target)?;
    tracing::info!(%target, %addr, "채널이동 시작 — 새 다운스트림 풀 스폰 핸드셰이크");

    let ready = downstream::connect_and_handshake(addr, version, &login).await?;
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
        "새 다운스트림 스폰 준비 — 클라 전환 시퀀스"
    );

    // 차원: 다운스트림 월드는 전부 overworld(0) 가정. Spectrum 과 동일하게
    // Play=Nether(현재와 달라야 클라가 실제 전환)로 플립, Clear=Overworld 복귀.
    let final_dim = packets::DIM_OVERWORLD;
    let flip_dim = packets::DIM_NETHER;
    let empty = packets::empty_chunk_payload(packets::dimension_biome_sections(final_dim));

    // (1) Play: 더미 차원으로 플립 → 클라가 옛 월드(청크/엔티티 캐시)를 비운다.
    send_pkt(client, &packets::change_dimension(flip_dim, pos, false)).await?;
    send_pkt(
        client,
        &packets::player_action(runtime_id, packets::PLAYER_ACTION_DIMENSION_CHANGE_DONE),
    )
    .await?;

    // (2) 플립 차원 로딩 필러: 스폰 청크 주변 9×9 빈 청크.
    for dx in -4..=4 {
        for dz in -4..=4 {
            send_pkt(
                client,
                &packets::level_chunk(spawn_cx + dx, spawn_cz + dz, final_dim, 1, &empty),
            )
            .await?;
        }
    }

    // 게임모드 HUD 동기화: StartGame 을 클라에 안 보내므로 게임모드(체력바 표시 등)가 옛 서버
    // 값에 머문다 → 새 서버 gamemode 를 명시적으로 알려준다.
    send_pkt(client, &packets::set_player_game_type(gamemode)).await?;

    // 게임룰 동기화 (best-effort): 좌표표시 등 새 서버 게임룰 적용. 추출 실패해도 전환은 계속.
    match packets::extract_start_game_gamerules(&ready.start_game) {
        Ok(body) => send_pkt(client, &packets::game_rules_changed(&body)).await?,
        Err(e) => tracing::warn!(%target, "게임룰 추출 실패(스킵): {e}"),
    }

    // 옛 서버 상태 teardown: 추적한 보스바/스코어보드를 클라에서 제거(차원 플립으로 안 지워지는 잔재).
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
            "옛 서버 상태 teardown"
        );
    }

    // (3) 다운스트림 스왑 A→B, 옛 A 닫기.
    let old = std::mem::replace(server, ready.socket);
    let _ = old.close().await;

    // (4) DoSpawn → B: doFirstSpawn(엔티티/후속 청크 스트리밍) 트리거.
    send_pkt(server, &packets::set_local_player_as_initialized(runtime_id)).await?;

    // (5) Clear: overworld 복귀 + 스폰.
    send_pkt(client, &packets::play_status(packets::PLAY_STATUS_PLAYER_SPAWN)).await?;
    send_pkt(client, &packets::change_dimension(final_dim, pos, true)).await?;
    send_pkt(
        client,
        &packets::player_action(runtime_id, packets::PLAYER_ACTION_DIMENSION_CHANGE_DONE),
    )
    .await?;
    send_pkt(client, &packets::play_status(packets::PLAY_STATUS_PLAYER_SPAWN)).await?;

    // (6) 버퍼된 실제 스폰 스트림(청크/인벤/엔티티) 재생 — 이미 프레이밍된 메시지라 그대로 전송.
    //     이제 클라가 overworld 라 청크를 수용한다.
    for msg in &ready.spawn_buffer {
        client
            .send(msg, Reliability::ReliableOrdered)
            .await
            .map_err(|e| anyhow!("스폰 스트림 재생 실패: {e:?}"))?;
    }

    // 새 서버 초기 보스바/스코어보드로 추적 시드 (다음 전환 teardown 대비).
    state.seed_tracked(ready.bossbars, ready.objectives);

    tracing::info!(%target, "채널이동 시퀀스 전송 완료");
    Ok(())
}
