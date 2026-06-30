use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// Top-level proxy configuration. Loaded from `config.toml`.
///
/// In Phase 0, all traffic is transparently forwarded to the single downstream
/// identified by `listener.default_server`. The `servers` map is reused as-is
/// in Phase 2 (channel registry).
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listener: Listener,
    #[serde(default)]
    pub servers: HashMap<String, ServerEntry>,
    /// MOTD the proxy advertises directly. If set, the proxy skips querying the downstream MOTD.
    /// If omitted, the downstream's MOTD is fetched at startup and advertised verbatim.
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

/// Runtime tuning. If `worker_threads` is unset, Tokio defaults to the number of logical cores.
#[derive(Debug, Deserialize, Default)]
pub struct Runtime {
    /// Number of Tokio worker threads (multi-core tuning). Unset or 0 means auto-detect by core count.
    pub worker_threads: Option<usize>,
    /// RakNet ACK/retransmit tick interval (ms). Unset = 10 (WaterdogPE parity). Lower = tighter ACK and
    /// loss recovery for high-ping players, at the cost of more per-connection wakeups. Data is never
    /// gated by this (packets flush immediately). Clamped to [1, 1000].
    pub ack_tick_ms: Option<u64>,
}

/// Metrics and observability. Gate for measurement-driven hardening.
#[derive(Debug, Deserialize, Default)]
pub struct MetricsCfg {
    /// Periodic metrics logging interval in seconds. 0 disables logging.
    #[serde(default)]
    pub log_interval_secs: u64,
    /// HTTP bind address for the web monitoring server (e.g. `"0.0.0.0:8080"`). Unset disables the web server.
    /// Exposes a GET / dashboard and GET /metrics · /players JSON endpoints.
    #[serde(default)]
    pub web_addr: Option<String>,
    /// Performance data collection — if set, appends a metrics snapshot as one JSONL line every N seconds.
    /// Leave enabled in production and retrieve the file later for time-series analysis to identify hot paths.
    #[serde(default)]
    pub history_file: Option<String>,
    /// History recording interval in seconds. 0 or unset defaults to 10.
    #[serde(default)]
    pub history_interval_secs: u64,
}

/// Proxy resource-pack serving configuration (WDPE-style replace — the proxy serves packs from `packs/`
/// to clients, ignoring downstream packs, applied uniformly across all servers).
/// Disabled by default because it sits on the handshake critical path — enable only after verification.
#[derive(Debug, Deserialize)]
pub struct ResourcePacks {
    /// When true, the proxy takes ownership of the client resource-pack phase and serves packs from `packs/`.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the packs directory (relative to cwd). Loads `.mcpack`/`.zip` files.
    #[serde(default = "default_packs_folder")]
    pub folder: String,
    /// Forces clients to accept the packs (`mustAccept=true` — clients that decline cannot connect).
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

/// Proxy feature toggles.
#[derive(Debug, Deserialize)]
pub struct Features {
    /// Re-enables Vibrant Visuals that the downstream forcibly disables
    /// (flips `forceDisableVibrantVisuals` in `ResourcePacksInfoPacket` to `false`).
    #[serde(default = "default_true")]
    pub force_vibrant_visuals: bool,
    /// Intercepts downstream `TransferPacket` (server name) and handles it as a transparent channel transfer.
    #[serde(default = "default_true")]
    pub channel_transfer: bool,
    /// Max compressed batch size (bytes) the down path will decompress + decode to scan for TransferPackets /
    /// entity Add-Remove / resource-pack packets. Larger batches (chunk data) are forwarded opaquely with no
    /// decode. `0` disables the cap (decode every batch). Lower is cheaper but risks missing large entity-spawn
    /// batches (→ ghost entities, as the historic 512 did once entity tracking was added); higher decodes more.
    #[serde(default = "default_max_decode_batch_bytes")]
    pub max_decode_batch_bytes: usize,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            force_vibrant_visuals: true,
            channel_transfer: true,
            max_decode_batch_bytes: default_max_decode_batch_bytes(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_decode_batch_bytes() -> usize {
    crate::intercept::MAX_DECODE_BATCH_BYTES
}

/// MOTD the proxy presents in the server list. Defined independently of the downstream.
#[derive(Debug, Deserialize)]
pub struct Motd {
    /// Server name (first line in the server list). Supports color codes (§).
    pub name: String,
    /// Second line (the "level name" position in vanilla). Leave empty for a blank line.
    #[serde(default)]
    pub sub: String,
    /// Current player count to display.
    #[serde(default)]
    pub players: u32,
    /// Maximum player count to display.
    #[serde(default = "default_max_players")]
    pub max_players: u32,
    /// MC game protocol number. Must match the client version to show as "compatible" (mismatches usually still connect).
    #[serde(default = "default_protocol")]
    pub protocol: u32,
    /// Display version string, e.g. `"1.26.30"`.
    #[serde(default = "default_version")]
    pub version: String,
    /// Game type, e.g. `"Survival"` or `"Creative"`.
    #[serde(default = "default_gametype")]
    pub gametype: String,
}

fn default_max_players() -> u32 {
    500
}
fn default_protocol() -> u32 {
    // Based on server version 1.26.30. Override in config when updating MC.
    1001
}
fn default_version() -> String {
    "1.26.30".to_string()
}
fn default_gametype() -> String {
    "Survival".to_string()
}

impl Motd {
    /// Builds the Bedrock unconnected-pong MOTD string.
    /// Format: `MCPE;line1;protocol;version;players;max;guid;line2;gametype;1;portV4;portV6;`
    pub fn to_motd_string(&self, port: u16) -> String {
        // guid identifies the server entry to the client; a fixed value is sufficient.
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
    /// Address the proxy binds to, e.g. `"0.0.0.0:19132"`.
    pub host: String,
    /// Name of the default channel all traffic is forwarded to. Must be a key in `servers`.
    /// (Becomes the "initial channel" when the Phase 2 channel registry / `/server` switching lands.)
    pub default_server: String,
    /// Negotiated MTU cap in bytes. Defaults to 1200 for stability; clamped to the RakNet range 576–1500.
    /// Applied to the client↔proxy reply, the proxy↔downstream request, and the inbound cap.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_mtu() -> u16 {
    1200
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerEntry {
    /// Downstream server address, e.g. `"play.example.com:19132"`.
    pub address: String,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        // The listen address must be valid.
        self.listen_addr()?;
        // The default channel must exist in the servers map and its address must be resolvable.
        self.default_server_addr()?;
        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listener
            .host
            .parse()
            .with_context(|| format!("failed to parse listener.host: {}", self.listener.host))
    }

    /// Resolves the downstream address of the default channel.
    pub fn default_server_addr(&self) -> Result<SocketAddr> {
        self.resolve_server(&self.listener.default_server)
    }

    /// Resolves a registered server name to a socket address (supports hostnames and dynamic DNS).
    /// Used to resolve channel-transfer targets.
    /// (Re-resolving on IP change for dynamic DNS is a future improvement — currently resolved at call time.)
    pub fn resolve_server(&self, name: &str) -> Result<SocketAddr> {
        let entry = self
            .servers
            .get(name)
            .ok_or_else(|| anyhow!("server name '{name}' not found in servers map"))?;
        entry
            .address
            .to_socket_addrs()
            .with_context(|| format!("failed to resolve servers.{name}.address: {}", entry.address))?
            .next()
            .ok_or_else(|| anyhow!("servers.{name}.address resolved to no addresses: {}", entry.address))
    }
}
