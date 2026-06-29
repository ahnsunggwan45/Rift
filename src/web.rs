//! 경량 HTTP 모니터링 엔드포인트.
//!
//! 의존성 추가 없이(axum/hyper 미사용) tokio `TcpListener` 위에 최소 HTTP/1.1 응답만 구현한다.
//! 프록시 정체성("경량")에 맞춰 읽기 전용 + 짧은 응답이라 keep-alive 없이 응답마다 연결 종료.
//! - `GET /metrics` → JSON 스냅샷 (외부 대시보드/스크립트용, CORS 허용)
//! - `GET /players` → 세션 목록 JSON (이름/IP/서버; 레지스트리 기반)
//! - `GET /`        → 자동 갱신 HTML 대시보드 (브라우저에서 바로 확인)

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::metrics::Metrics;
use crate::registry::Registry;

/// 웹 모니터링 서버를 백그라운드 태스크로 띄운다. bind 실패해도 프록시 본체는 계속 돈다.
pub fn spawn(metrics: Arc<Metrics>, registry: Arc<Registry>, addr: SocketAddr) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%addr, "웹 모니터링 bind 실패: {e} — 모니터링 비활성");
                return;
            }
        };
        tracing::info!(%addr, "웹 모니터링 시작 (GET / 대시보드, /metrics, /players)");
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let m = metrics.clone();
                    let r = registry.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, m, r).await {
                            tracing::debug!("웹 연결 처리 오류: {e}");
                        }
                    });
                }
                Err(e) => tracing::warn!("웹 accept 실패: {e}"),
            }
        }
    });
}

async fn handle_conn(
    mut stream: TcpStream,
    metrics: Arc<Metrics>,
    registry: Arc<Registry>,
) -> std::io::Result<()> {
    // 요청 라인만 필요하다. 헤더 끝(\r\n\r\n)까지 최대 8KB 읽고 첫 줄에서 메서드/경로 추출.
    // 5초 안에 요청을 다 못 받으면 드롭 — 유휴/slow-loris 연결이 태스크를 붙잡지 못하게.
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
        Err(_) => return Ok(()), // 타임아웃 → 조용히 드롭
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

/// 자체 포함 대시보드. /metrics + /players 를 2초마다 폴링해 렌더링한다(외부 의존 없음).
const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rift 모니터링</title>
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
<header><span class="dot"></span><h1>Rift 모니터링</h1><span class="mut" id="up"></span></header>
<div class="wrap">
  <div class="grid">
    <div class="card"><div class="k">접속 중</div><div class="v" id="active">–</div></div>
    <div class="card"><div class="k">누적 접속</div><div class="v" id="total">–</div></div>
    <div class="card"><div class="k">채널이동</div><div class="v" id="tx">–</div></div>
    <div class="card"><div class="k">업로드</div><div class="v" id="up_r">–<small> KiB/s</small></div></div>
    <div class="card"><div class="k">다운로드</div><div class="v" id="dn_r">–<small> KiB/s</small></div></div>
    <div class="card"><div class="k">패킷/초</div><div class="v" id="pps">–</div></div>
    <div class="card"><div class="k">평균 패킷</div><div class="v" id="avg">–<small> B</small></div></div>
    <div class="card" id="alloc_card" style="display:none"><div class="k">할당(누적)</div><div class="v" id="alloc">–</div></div>
    <div class="card"><div class="k">최대 동시</div><div class="v" id="peak">–</div></div>
    <div class="card"><div class="k">누적 송수신</div><div class="v" id="total_bytes">–</div></div>
    <div class="card"><div class="k">포워드 지연</div><div class="v" id="fwd">–<small> μs</small></div></div>
  </div>
  <h2>서버별 인원</h2>
  <table><thead><tr><th>서버</th><th class="num">인원</th></tr></thead><tbody id="servers"></tbody></table>
  <h2>접속자</h2>
  <table><thead><tr><th>이름</th><th>IP</th><th>서버</th><th class="num">핑</th><th class="num">접속</th></tr></thead><tbody id="players"></tbody></table>
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
    document.getElementById('tx').textContent=m.transfers+(m.transfers_failed?` (실패 ${m.transfers_failed})`:'');
    document.getElementById('up').textContent='가동 '+fmtUp(m.uptime_secs);
    if(prev){const dt=(now-prevT)/1000||1;
      document.getElementById('up_r').innerHTML=Math.max(0,Math.round((m.bytes_up-prev.bytes_up)/1024/dt))+'<small> KiB/s</small>';
      document.getElementById('dn_r').innerHTML=Math.max(0,Math.round((m.bytes_down-prev.bytes_down)/1024/dt))+'<small> KiB/s</small>';
      document.getElementById('pps').textContent=Math.max(0,Math.round(((m.msgs_up+m.msgs_down)-(prev.msgs_up+prev.msgs_down))/dt));}
    prev=m;prevT=now;
    document.getElementById('avg').innerHTML=m.avg_packet_size_bytes+'<small> B</small>';
    document.getElementById('total_bytes').innerHTML=fmtBytes(m.bytes_up+m.bytes_down);
    document.getElementById('fwd').innerHTML=m.avg_forward_us+'<small> μs</small>';
    if(m.alloc_count>0){document.getElementById('alloc_card').style.display='';
      document.getElementById('alloc').innerHTML=m.alloc_count.toLocaleString()+'<small> ('+Math.round(m.alloc_bytes/1048576)+' MiB)</small>';}
    const sv=Object.entries(m.per_server).sort((a,b)=>b[1]-a[1]);
    document.getElementById('servers').innerHTML=sv.length?sv.map(([k,v])=>`<tr><td>${k}</td><td class="num">${v}</td></tr>`).join(''):'<tr><td colspan=2 class="mut">없음</td></tr>';
    document.getElementById('players').innerHTML=p.length?p.map(x=>`<tr><td>${x.name||'<span class=mut>?</span>'}</td><td class="mut">${x.peer}</td><td><span class="pill">${x.server}</span></td><td class="num">${x.rtt_ms?x.rtt_ms+'ms':'–'}</td><td class="num mut">${fmtDur(x.connected_secs)}</td></tr>`).join(''):'<tr><td colspan=5 class="mut">없음</td></tr>';
    document.getElementById('err').textContent='';
  }catch(e){document.getElementById('err').textContent='연결 끊김 — 재시도 중…';}
}
tick();setInterval(tick,2000);
</script>
</body></html>"#;
