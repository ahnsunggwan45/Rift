//! Out-of-band control channel (TCP).
//!
//! A trusted local backend (e.g. the RiftSupport plugin) connects here to trigger seamless transfers
//! and kicks WITHOUT putting anything into the Minecraft game stream. This is what lets the down-stream
//! relay stay a pure pass-through: the proxy never has to scan/decode the game stream looking for a
//! `TransferPacket`, because the transfer intent arrives here instead.
//!
//! Line protocol (one command per line, whitespace-separated), reply is one line:
//!   `<token> transfer <name|xuid> <server>`  → `ok …` / `err …`
//!   `<token> kick <name|xuid>`               → `ok …` / `err …`
//!
//! Bind to localhost (proxy and backends are co-located); the shared token gates access. Commands are
//! delivered through the same per-session `Control` channel the console uses — no direct socket access.

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::registry::{Control, Registry};

/// Runs the control listener until the process exits. Each connection may issue many commands.
pub async fn serve(addr: String, token: String, registry: Arc<Registry>) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "out-of-band control channel listening (transfer/kick trigger)");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("control accept failed: {e}");
                continue;
            }
        };
        let registry = registry.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let (rd, mut wr) = stream.into_split();
            let mut lines = BufReader::new(rd).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let reply = handle_line(&line, &token, &registry).await;
                        if wr.write_all(reply.as_bytes()).await.is_err() || wr.write_all(b"\n").await.is_err() {
                            break;
                        }
                    }
                    _ => break, // EOF or read error
                }
            }
            tracing::debug!(%peer, "control connection closed");
        });
    }
}

/// Parses and executes one control line. Returns a one-line reply.
async fn handle_line(line: &str, token: &str, registry: &Registry) -> String {
    let mut it = line.split_whitespace();
    // Constant-time-ish token check is unnecessary on a localhost-only channel; a plain compare is fine.
    if it.next() != Some(token) {
        return "err bad-token".into();
    }
    match it.next() {
        Some("transfer") => {
            let who = it.next().unwrap_or("");
            let server = it.next().unwrap_or("");
            if who.is_empty() || server.is_empty() {
                return "err usage: <token> transfer <name|xuid> <server>".into();
            }
            match registry.find_control(who) {
                Some((id, ctl)) => match ctl.send(Control::Transfer(server.to_string())).await {
                    Ok(()) => {
                        tracing::info!(session = id, %server, %who, "control: transfer requested");
                        format!("ok transfer session={id} server={server}")
                    }
                    Err(_) => "err session-control-closed".into(),
                },
                None => format!("err no-session who={who}"),
            }
        }
        Some("kick") => {
            let who = it.next().unwrap_or("");
            if who.is_empty() {
                return "err usage: <token> kick <name|xuid>".into();
            }
            match registry.find_control(who) {
                Some((id, ctl)) => match ctl.send(Control::Kick).await {
                    Ok(()) => format!("ok kick session={id}"),
                    Err(_) => "err session-control-closed".into(),
                },
                None => format!("err no-session who={who}"),
            }
        }
        other => format!("err unknown-command {}", other.unwrap_or("")),
    }
}
