//! Lightweight HTTP monitoring endpoints.
//!
//! Implements minimal HTTP/1.1 responses on top of a tokio `TcpListener` with no extra
//! dependencies (no axum/hyper). Keeping with the proxy's lightweight identity, responses are
//! read-only and short; connections are closed after each response (no keep-alive).
//! - `GET /metrics` → JSON snapshot (for external dashboards/scripts, CORS enabled)
//! - `GET /players` → session list JSON (name/IP/server; backed by the registry)
//! - `GET /`        → auto-refreshing HTML dashboard (open directly in a browser)

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::metrics::Metrics;
use crate::registry::Registry;

/// Spawn the web monitoring server as a background task. Bind failures do not affect the proxy.
pub fn spawn(metrics: Arc<Metrics>, registry: Arc<Registry>, addr: SocketAddr) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%addr, "web monitoring bind failed: {e} — monitoring disabled");
                return;
            }
        };
        tracing::info!(%addr, "web monitoring started (GET / dashboard, /metrics, /players)");
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let m = metrics.clone();
                    let r = registry.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, m, r).await {
                            tracing::debug!("web connection error: {e}");
                        }
                    });
                }
                Err(e) => tracing::warn!("web accept failed: {e}"),
            }
        }
    });
}

async fn handle_conn(
    mut stream: TcpStream,
    metrics: Arc<Metrics>,
    registry: Arc<Registry>,
) -> std::io::Result<()> {
    // Only the request line is needed. Read up to 8 KB until the header end (\r\n\r\n),
    // then extract the method and path from the first line.
    // Drop if the full request is not received within 5 seconds — prevents idle/slow-loris
    // connections from holding a task open.
    let mut buf = [0u8; 8192];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut n = 0usize;
        loop {
            let r = stream.read(&mut buf[n..]).await?;
            if r == 0 {
                break;
            }
            n += r;
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                break;
            }
        }
        std::io::Result::Ok(n)
    })
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(()), // timeout — drop silently
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, ctype, body) = match path {
        "/metrics" => {
            let json = serde_json::to_string(&metrics.snapshot()).unwrap_or_else(|_| "{}".into());
            ("200 OK", "application/json", json)
        }
        "/players" => {
            let json = serde_json::to_string(&registry.snapshot()).unwrap_or_else(|_| "[]".into());
            ("200 OK", "application/json", json)
        }
        "/" => ("200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.to_string()),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found".to_string()),
    };

    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}

/// Self-contained dashboard. Polls /metrics + /players every 2 seconds (no external dependencies).
const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rift Monitoring</title>
<style>
:root{--bg:#0e1116;--card:#171b22;--line:#262b34;--fg:#e6edf3;--mut:#8b949e;--accent:#ff7ab6;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}
h1{font-size:17px;margin:0}.dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.wrap{padding:24px;max-width:1000px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:26px;font-weight:600;margin-top:6px;font-variant-numeric:tabular-nums}
.card .v small{font-size:13px;color:var(--mut);font-weight:400}
h2{font-size:13px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin:24px 0 10px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:500;font-size:12px}td{font-variant-numeric:tabular-nums}
tr:last-child td{border-bottom:none}.num{text-align:right}.mut{color:var(--mut)}
.pill{background:#21262d;border-radius:20px;padding:2px 10px;font-size:12px}
</style></head>
<body>
<header><span class="dot"></span><h1>Rift Monitoring</h1><span class="mut" id="up"></span></header>
<div class="wrap">
  <div class="grid">
    <div class="card"><div class="k">Online</div><div class="v" id="active">–</div></div>
    <div class="card"><div class="k">Total Connections</div><div class="v" id="total">–</div></div>
    <div class="card"><div class="k">Transfers</div><div class="v" id="tx">–</div></div>
    <div class="card"><div class="k">Upload</div><div class="v" id="up_r">–<small> KiB/s</small></div></div>
    <div class="card"><div class="k">Download</div><div class="v" id="dn_r">–<small> KiB/s</small></div></div>
    <div class="card"><div class="k">Packets/s</div><div class="v" id="pps">–</div></div>
    <div class="card"><div class="k">Avg Packet</div><div class="v" id="avg">–<small> B</small></div></div>
    <div class="card" id="alloc_card" style="display:none"><div class="k">Alloc (total)</div><div class="v" id="alloc">–</div></div>
    <div class="card"><div class="k">Peak Concurrent</div><div class="v" id="peak">–</div></div>
    <div class="card"><div class="k">Total Bytes</div><div class="v" id="total_bytes">–</div></div>
    <div class="card"><div class="k">Forward Latency</div><div class="v" id="fwd">–<small> μs</small></div><div class="k" id="fwdpct" style="margin-top:3px">p50/95/99 –</div></div>
  </div>
  <h2>Players per Server</h2>
  <table><thead><tr><th>Server</th><th class="num">Players</th></tr></thead><tbody id="servers"></tbody></table>
  <h2>Connected Players</h2>
  <table><thead><tr><th>Name</th><th>IP</th><th>Server</th><th class="num">Ping</th><th class="num">Connected</th></tr></thead><tbody id="players"></tbody></table>
  <p class="mut" id="err"></p>
</div>
<script>
let prev=null,prevT=0;
function fmtUp(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return (d?d+"d ":"")+(h?h+"h ":"")+m+"m";}
function fmtBytes(b){const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++;}return b.toFixed(i?1:0)+' '+u[i];}
function fmtDur(s){if(s<60)return s+'s';const m=Math.floor(s/60);if(m<60)return m+'m';return Math.floor(m/60)+'h '+(m%60)+'m';}
async function tick(){
  try{
    const [m,p]=await Promise.all([fetch('/metrics').then(r=>r.json()),fetch('/players').then(r=>r.json())]);
    const now=Date.now();
    document.getElementById('active').textContent=m.active;
    document.getElementById('total').textContent=m.connections_total;
    document.getElementById('peak').textContent=m.peak_active;
    document.getElementById('tx').textContent=m.transfers+(m.transfers_failed?` (failed: ${m.transfers_failed})`:'');
    document.getElementById('up').textContent='uptime '+fmtUp(m.uptime_secs);
    if(prev){const dt=(now-prevT)/1000||1;
      document.getElementById('up_r').innerHTML=Math.max(0,Math.round((m.bytes_up-prev.bytes_up)/1024/dt))+'<small> KiB/s</small>';
      document.getElementById('dn_r').innerHTML=Math.max(0,Math.round((m.bytes_down-prev.bytes_down)/1024/dt))+'<small> KiB/s</small>';
      document.getElementById('pps').textContent=Math.max(0,Math.round(((m.msgs_up+m.msgs_down)-(prev.msgs_up+prev.msgs_down))/dt));}
    prev=m;prevT=now;
    document.getElementById('avg').innerHTML=m.avg_packet_size_bytes+'<small> B</small>';
    document.getElementById('total_bytes').innerHTML=fmtBytes(m.bytes_up+m.bytes_down);
    document.getElementById('fwd').innerHTML=m.avg_forward_us+'<small> μs avg</small>';
    document.getElementById('fwdpct').textContent='p50 '+m.forward_p50_us+' · p95 '+m.forward_p95_us+' · p99 '+m.forward_p99_us+' μs';
    if(m.alloc_count>0){document.getElementById('alloc_card').style.display='';
      document.getElementById('alloc').innerHTML=m.alloc_count.toLocaleString()+'<small> ('+Math.round(m.alloc_bytes/1048576)+' MiB)</small>';}
    const sv=Object.entries(m.per_server).sort((a,b)=>b[1]-a[1]);
    document.getElementById('servers').innerHTML=sv.length?sv.map(([k,v])=>`<tr><td>${k}</td><td class="num">${v}</td></tr>`).join(''):'<tr><td colspan=2 class="mut">none</td></tr>';
    document.getElementById('players').innerHTML=p.length?p.map(x=>`<tr><td>${x.name||'<span class=mut>?</span>'}</td><td class="mut">${x.peer}</td><td><span class="pill">${x.server}</span></td><td class="num">${x.rtt_ms?x.rtt_ms+'ms':'–'}</td><td class="num mut">${fmtDur(x.connected_secs)}</td></tr>`).join(''):'<tr><td colspan=5 class="mut">none</td></tr>';
    document.getElementById('err').textContent='';
  }catch(e){document.getElementById('err').textContent='Connection lost — retrying…';}
}
tick();setInterval(tick,2000);
</script>
</body></html>"#;
