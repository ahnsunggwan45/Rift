//! 콘솔 명령 — 실서버 운영 조작(stdin). 블로킹 stdin 읽기라 별도 std 스레드에서 줄 단위로 처리.
//!
//! foreground/screen/tmux/systemd(tty) 로 띄우면 PMMP 콘솔처럼 명령을 친다. stdin 이 없으면
//! (백그라운드/파이프 EOF) 루프가 조용히 끝난다 — 프록시 본체엔 영향 없음.

use std::io::BufRead;
use std::sync::Arc;

use tokio::sync::Notify;

use crate::metrics::Metrics;
use crate::registry::{Control, Registry};

/// 콘솔 리더를 띄운다. `stop` 입력 시 `shutdown` 을 통지해 accept 루프를 종료시킨다.
pub fn spawn(registry: Arc<Registry>, metrics: Arc<Metrics>, shutdown: Arc<Notify>) {
    let _ = std::thread::Builder::new()
        .name("console".into())
        .spawn(move || run(registry, metrics, shutdown));
}

fn run(registry: Arc<Registry>, metrics: Arc<Metrics>, shutdown: Arc<Notify>) {
    print_help();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // stdin 닫힘/EOF
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        match cmd {
            "help" | "?" => print_help(),
            "info" | "status" => {
                let s = metrics.snapshot();
                println!(
                    "● 가동 {}s | 접속 {} (누적 {}) | 이동 {} (실패 {})",
                    s.uptime_secs, s.active, s.connections_total, s.transfers, s.transfers_failed
                );
                println!("  ↑{} KiB  ↓{} KiB", s.bytes_up / 1024, s.bytes_down / 1024);
                let mut sv: Vec<_> = s.per_server.into_iter().collect();
                sv.sort_by(|a, b| b.1.cmp(&a.1));
                for (k, v) in sv {
                    println!("  {k}: {v}명");
                }
            }
            "list" | "plist" | "players" => {
                let snap = registry.snapshot();
                if snap.is_empty() {
                    println!("(접속자 없음)");
                } else {
                    for p in snap {
                        println!(
                            "  #{} {} {} → {}",
                            p.id,
                            p.name.as_deref().unwrap_or("?"),
                            p.peer,
                            p.server
                        );
                    }
                }
            }
            "transfer" | "send" => match (it.next(), it.next()) {
                (Some(who), Some(server)) => match registry.find_control(who) {
                    Some((id, tx)) => {
                        if tx.try_send(Control::Transfer(server.to_string())).is_ok() {
                            println!("→ #{id} 을(를) '{server}' 로 이동 요청");
                        } else {
                            println!("✗ #{id} 제어 채널이 막혀 전송 실패");
                        }
                    }
                    None => println!("✗ '{who}' 세션을 찾을 수 없음 (이름 또는 번호 확인)"),
                },
                _ => println!("사용법: transfer <이름|번호> <서버>"),
            },
            "kick" => match it.next() {
                Some(who) => match registry.find_control(who) {
                    Some((id, tx)) => {
                        let _ = tx.try_send(Control::Kick);
                        println!("→ #{id} 강제 종료 요청");
                    }
                    None => println!("✗ '{who}' 세션을 찾을 수 없음"),
                },
                None => println!("사용법: kick <이름|번호>"),
            },
            "stop" | "shutdown" | "exit" => {
                println!("종료 신호 전송 — 새 연결 수락 중단");
                shutdown.notify_one();
                break;
            }
            other => println!("알 수 없는 명령: '{other}'  (help 입력)"),
        }
    }
}

fn print_help() {
    println!("Rift 콘솔 명령:");
    println!("  info                      상태/처리량/서버별 인원");
    println!("  list                      접속자 목록 (#번호 이름 IP → 서버)");
    println!("  transfer <이름|번호> <서버>   채널이동");
    println!("  kick <이름|번호>            세션 강제 종료");
    println!("  stop                      프록시 graceful 종료");
}
