use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// 프록시 전체 설정. `config.toml`에서 로드한다.
///
/// Phase 0에서는 `listener.default_server`가 가리키는 단일 다운스트림으로만
/// 투명 중계한다. `servers` 맵은 Phase 2(채널 레지스트리)에서 그대로 재사용된다.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listener: Listener,
    #[serde(default)]
    pub servers: HashMap<String, ServerEntry>,
    /// 프록시가 직접 광고할 MOTD. 지정하면 다운스트림 MOTD 조회를 건너뛴다.
    /// 생략하면 시작 시 default_server 의 MOTD 를 조회해 그대로 광고한다.
    pub motd: Option<Motd>,
    #[serde(default)]
    pub features: Features,
    #[serde(default)]
    pub resource_packs: ResourcePacks,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub metrics: MetricsCfg,
}

/// 런타임 튜닝. worker_threads 미지정이면 tokio 기본(논리코어 수)을 사용한다.
#[derive(Debug, Deserialize, Default)]
pub struct Runtime {
    /// tokio 워커 스레드 수 (멀티코어 튜닝). 미지정/0 이면 코어 수 자동.
    pub worker_threads: Option<usize>,
}

/// 메트릭/관측. 측정 기반 하드닝의 게이트.
#[derive(Debug, Deserialize, Default)]
pub struct MetricsCfg {
    /// 주기 메트릭 로깅 간격(초). 0 이면 끔.
    #[serde(default)]
    pub log_interval_secs: u64,
    /// 웹 모니터링 HTTP 바인드 주소(예: "0.0.0.0:8080"). 미지정이면 웹 모니터링 끔.
    /// GET / 대시보드, GET /metrics·/players JSON 노출.
    #[serde(default)]
    pub web_addr: Option<String>,
    /// 성능 데이터 수집용 — 지정하면 N초마다 메트릭 스냅샷을 이 파일에 JSONL 한 줄씩 append.
    /// 실서버에서 켜두고 나중에 이 파일을 받아 시계열 분석(상황별 핫패스 판단)에 쓴다.
    #[serde(default)]
    pub history_file: Option<String>,
    /// history 기록 간격(초). 0/미지정이면 10.
    #[serde(default)]
    pub history_interval_secs: u64,
}

/// 프록시 리소스팩 서빙 설정 (WDPE 방식 replace — 프록시가 packs/ 의 팩을 클라에 서빙,
/// 다운스트림 팩은 무시, 전 서버에 동일 적용). 핸드셰이크 임계 경로라 기본 off — 검증 후 켤 것.
#[derive(Debug, Deserialize)]
pub struct ResourcePacks {
    /// 켜면 프록시가 클라 리소스팩 단계를 직접 소유해 packs/ 의 팩을 서빙한다.
    #[serde(default)]
    pub enabled: bool,
    /// 팩 폴더 경로 (cwd 기준). .mcpack/.zip 파일을 로드.
    #[serde(default = "default_packs_folder")]
    pub folder: String,
    /// 클라가 팩을 강제로 받게 한다(mustAccept=true → 거부 시 접속 불가).
    #[serde(default)]
    pub force: bool,
}

impl Default for ResourcePacks {
    fn default() -> Self {
        Self { enabled: false, folder: default_packs_folder(), force: false }
    }
}

fn default_packs_folder() -> String {
    "packs".to_string()
}

/// 프록시 기능 토글.
#[derive(Debug, Deserialize)]
pub struct Features {
    /// 다운스트림이 강제로 끄는 Vibrant Visuals 를 프록시가 되살린다
    /// (ResourcePacksInfoPacket 의 forceDisableVibrantVisuals 를 false 로 flip).
    #[serde(default = "default_true")]
    pub force_vibrant_visuals: bool,
    /// 다운스트림 TransferPacket(서버명)을 가로채 투명 채널이동으로 처리.
    #[serde(default = "default_true")]
    pub channel_transfer: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self { force_vibrant_visuals: true, channel_transfer: true }
    }
}

fn default_true() -> bool {
    true
}

/// 프록시가 서버 목록에 표시할 MOTD. 다운스트림과 무관하게 직접 정한다.
#[derive(Debug, Deserialize)]
pub struct Motd {
    /// 서버명 (목록 첫 줄). 색코드(§) 사용 가능.
    pub name: String,
    /// 둘째 줄 (바닐라에선 "level name" 위치). 비우면 빈 줄.
    #[serde(default)]
    pub sub: String,
    /// 표시할 현재 인원수.
    #[serde(default)]
    pub players: u32,
    /// 표시할 최대 인원수.
    #[serde(default = "default_max_players")]
    pub max_players: u32,
    /// MC 게임 프로토콜 번호. 클라 버전과 맞아야 "호환"으로 표시됨 (안 맞아도 접속은 보통 됨).
    #[serde(default = "default_protocol")]
    pub protocol: u32,
    /// 표시 버전 문자열. 예: "1.26.30"
    #[serde(default = "default_version")]
    pub version: String,
    /// 게임 타입. "Survival" | "Creative" 등.
    #[serde(default = "default_gametype")]
    pub gametype: String,
}

fn default_max_players() -> u32 {
    500
}
fn default_protocol() -> u32 {
    // 현 서버 기준(1.26.30). MC 업데이트 시 config 에서 덮어쓰면 됨.
    1001
}
fn default_version() -> String {
    "1.26.30".to_string()
}
fn default_gametype() -> String {
    "Survival".to_string()
}

impl Motd {
    /// Bedrock unconnected-pong MOTD 문자열을 만든다.
    /// 형식: MCPE;line1;protocol;version;players;max;guid;line2;gametype;1;portV4;portV6;
    pub fn to_motd_string(&self, port: u16) -> String {
        // guid 는 클라가 서버 항목을 식별하는 값. 고정값이면 충분하다.
        const MOTD_GUID: u64 = 0x424E_4E59_5052_5859; // "BNNYPRXY"
        format!(
            "MCPE;{};{};{};{};{};{};{};{};1;{};{};",
            self.name,
            self.protocol,
            self.version,
            self.players,
            self.max_players,
            MOTD_GUID,
            self.sub,
            self.gametype,
            port,
            port,
        )
    }
}

#[derive(Debug, Deserialize)]
pub struct Listener {
    /// 프록시가 바인드할 주소. 예: "0.0.0.0:19132"
    pub host: String,
    /// 모든 트래픽을 중계할 기본 채널 이름. `servers`의 키여야 한다.
    /// (Phase 2에서 채널 레지스트리/`/server` 전환이 들어오면 "초기 채널"이 된다.)
    pub default_server: String,
    /// 협상 MTU 상한(바이트). 안정성 위해 기본 1200. RakNet 576~1500 로 클램프.
    /// 클라↔프록시 reply + 프록시↔다운스트림 요청 + 인바운드 캡 모두에 적용.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_mtu() -> u16 {
    1200
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerEntry {
    /// 다운스트림 서버 주소. 예: "play.example.com:19132"
    pub address: String,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("설정 파일을 읽을 수 없음: {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("설정 파일 파싱 실패: {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        // listen 주소가 유효해야 한다.
        self.listen_addr()?;
        // 기본 채널이 servers 맵에 존재하고, 그 주소가 파싱돼야 한다.
        self.default_server_addr()?;
        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listener
            .host
            .parse()
            .with_context(|| format!("listener.host 파싱 실패: {}", self.listener.host))
    }

    /// 기본 채널의 다운스트림 주소를 해석한다.
    pub fn default_server_addr(&self) -> Result<SocketAddr> {
        self.resolve_server(&self.listener.default_server)
    }

    /// 등록된 서버명을 주소로 해석한다(호스트네임/동적 DNS 지원). 채널이동 대상 해석에 쓴다.
    /// (IP가 바뀌는 동적 DNS의 재해석은 추후 과제 — 현재 호출 시점에 해석)
    pub fn resolve_server(&self, name: &str) -> Result<SocketAddr> {
        let entry = self
            .servers
            .get(name)
            .ok_or_else(|| anyhow!("서버명 '{name}' 가 servers 맵에 없음"))?;
        entry
            .address
            .to_socket_addrs()
            .with_context(|| format!("servers.{name}.address DNS 해석 실패: {}", entry.address))?
            .next()
            .ok_or_else(|| anyhow!("servers.{name}.address 해석 결과 없음: {}", entry.address))
    }
}
