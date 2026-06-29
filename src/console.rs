//! Console commands — live server administration via stdin. Blocking stdin reads are handled on a
//! dedicated std thread, processing input line by line.
//!
//! When launched in the foreground (screen/tmux/systemd tty), commands can be typed as in a standard
//! server console. When stdin is absent (background/pipe EOF) the loop exits silently — the proxy
//! itself is unaffected.

use std::io::BufRead;
use std::sync::Arc;

use tokio::sync::Notify;

use crate::metrics::Metrics;
use crate::registry::{Control, Registry};

/// Spawns the console reader. Notifies `shutdown` on `stop`, which terminates the accept loop.
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
            Err(_) => break, // stdin closed / EOF
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
                    "● uptime {}s | players {} (total {}) | transfers {} (failed {})",
                    s.uptime_secs, s.active, s.connections_total, s.transfers, s.transfers_failed
                );
                println!("  ↑{} KiB  ↓{} KiB", s.bytes_up / 1024, s.bytes_down / 1024);
                let mut sv: Vec<_> = s.per_server.into_iter().collect();
                sv.sort_by(|a, b| b.1.cmp(&a.1));
                for (k, v) in sv {
                    println!("  {k}: {v} players");
                }
            }
            "list" | "plist" | "players" => {
                let snap = registry.snapshot();
                if snap.is_empty() {
                    println!("(no players connected)");
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
                            println!("→ transferring #{id} to '{server}'");
                        } else {
                            println!("✗ #{id} control channel is full — send failed");
                        }
                    }
                    None => println!("✗ session '{who}' not found (check name or id)"),
                },
                _ => println!("usage: transfer <name|id> <server>"),
            },
            "kick" => match it.next() {
                Some(who) => match registry.find_control(who) {
                    Some((id, tx)) => {
                        let _ = tx.try_send(Control::Kick);
                        println!("→ kick requested for #{id}");
                    }
                    None => println!("✗ session '{who}' not found"),
                },
                None => println!("usage: kick <name|id>"),
            },
            "stop" | "shutdown" | "exit" => {
                println!("shutdown signal sent — stopping accept loop");
                shutdown.notify_one();
                break;
            }
            other => println!("unknown command: '{other}'  (type help)"),
        }
    }
}

fn print_help() {
    println!("Rift console commands:");
    println!("  info                       status / throughput / players per server");
    println!("  list                       connected players (#id name IP → server)");
    println!("  transfer <name|id> <server>  transfer player to server");
    println!("  kick <name|id>             kick player (close session)");
    println!("  stop                       graceful proxy shutdown");
}
