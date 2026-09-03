// Configuration — YAML schema + routing resolution.
// Mirrors packages/proxy/src/config.ts from the TypeScript implementation.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Root config loaded from ~/.anubis/config.yaml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANUBISConfig {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub scanner: ScannerConfig,
    /// Per-install token guarding mutating /__anubis/* admin routes and
    /// secret-bearing GETs (/config, /models). Generated on first load and
    /// persisted — a browser page or unprivileged local process cannot
    /// flip routing/scanner config (which would exfiltrate prompts + keys)
    /// without reading this file (go-public-graveyard BLOCKER-2).
    #[serde(default)]
    pub api_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    7878
}

/// Routing mode — determines where the daemon forwards traffic.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    Sleev,
    Direct,
    Custom,
}

impl Default for RoutingMode {
    fn default() -> Self {
        RoutingMode::Sleev
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub mode: RoutingMode,
    #[serde(default)]
    pub custom_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_scanner_model")]
    pub model: String,
    #[serde(default = "default_scanner_url")]
    pub base_url: String,
    /// Optional: dedicated API key for the scanner LLM endpoint.
    /// If empty, falls back to the inbound request's Bearer token.
    #[serde(default)]
    pub api_key: String,
    /// When true, hallucinated tool calls are blocked — the proxy buffers
    /// the upstream response, scans it, and replaces the response with a
    /// synthetic assistant message containing the reasoning if a
    /// hallucination is detected in a tool call.
    ///
    /// Off by default — preserves the advisor-only behavior. Toggle via
    /// dashboard or POST /__anubis/scanner.
    #[serde(default)]
    pub block_on_hallucination: bool,

    /// When true, the proxy parses the incoming request body for library
    /// references (imports, requires, use, includes) and injects a focused
    /// doc snippet from the cached symbol store as a system message before
    /// forwarding to upstream. Prevents hallucinations at the source by
    /// giving the model current API surface for the libraries it's using.
    ///
    /// Off by default — adds tokens to every request. Toggle via dashboard
    /// or POST /__anubis/scanner.
    #[serde(default)]
    pub auto_inject_docs: bool,

    /// When true, the streaming response is scanned incrementally as chunks
    /// arrive (not just at the 500-char midstream threshold). If a
    /// hallucination is detected with high confidence before the response
    /// completes, the upstream request is aborted mid-stream and replaced
    /// with a synthetic block response. Saves the tokens that would have
    /// been spent completing the hallucinated response.
    ///
    /// Off by default — aborts lose legitimate content if scanner has false
    /// positives. Only engage when block_on_hallucination is also on.
    /// Toggle via dashboard or POST /__anubis/scanner.
    #[serde(default)]
    pub preemptive_scan: bool,

    /// When true, the proxy detects file edit/write tool calls in the
    /// response, runs the language-appropriate verifier (tsc, cargo check,
    /// py_compile, dotnet build) on the affected file, and injects the
    /// verification result as a synthetic tool result on the next turn.
    /// Catches hallucinations that survive static analysis.
    ///
    /// Off by default — verification commands add latency and require the
    /// project's build toolchain to be installed. Toggle via dashboard
    /// or POST /__anubis/scanner.
    #[serde(default)]
    pub post_edit_verify: bool,

    /// Maximum number of concurrent deep-scan tasks (each ~90s bounded
    /// by DEEP_SCAN_TIMEOUT). Without this cap, a burst of N concurrent
    /// proxy requests spawns N×90s deep-scan tasks plus N×MAX_CONCURRENT_L3
    /// LLM calls — saturating tokio workers and upstream LLM quota.
    /// Defaults to 8. Set lower for rate-limited providers or lower-spec
    /// hosts; higher for team/CI deployments with ample headroom.
    #[serde(default)]
    pub max_concurrent_scans: Option<usize>,

    /// Extra TypeScript/JavaScript export names to treat as always-valid
    /// (skip FORGE hallucinated-import check). Supplements the built-in
    /// COMMON_TS_EXPORTS allow-list (~120 names covering React/Express/
    /// Zod/Vue/Node stdlib/DOM API). Useful for projects using internal
    /// component libraries, custom hooks, or build-time-generated exports
    /// that aren't in static package exports.
    ///
    /// Names are matched case-sensitively. Example:
    ///   scanner.extra_ts_exports = ["MyInternalComponent", "useCustomHook"]
    #[serde(default)]
    pub extra_ts_exports: Vec<String>,

    /// Extra Go framework package names to recognize (e.g. internal routers,
    /// ORM wrappers). When combined with `extra_go_framework_funcs`, methods
    /// called on these packages are skipped by the FORGE hallucinated-method
    /// check. Built-in set: gin/gorm/echo/fiber/chi/gorilla/mux.
    ///
    /// Example:
    ///   scanner.extra_go_framework_pkgs = ["myrouter", "myorm"]
    #[serde(default)]
    pub extra_go_framework_pkgs: Vec<String>,

    /// Extra Go framework function names to skip when called on a known
    /// framework package (built-in OR `extra_go_framework_pkgs`). Also
    /// applies to bare-function calls. Built-in set covers gin middleware
    /// + HTTP verbs + GORM methods (~50 names).
    ///
    /// Example:
    ///   scanner.extra_go_framework_funcs = ["MyMiddleware", "CustomQuery"]
    #[serde(default)]
    pub extra_go_framework_funcs: Vec<String>,

    /// Extra Rust ecosystem type names to treat as always-defined (skip
    /// FORGE undefined-variable check). Supplements the built-in
    /// COMMON_RUST_ECOSYSTEM_TYPES list (~110 names covering chrono/serde/
    /// clap/tokio/uuid/std::collections/std::sync/std::io/std::fs/etc.).
    /// Useful for projects with internal crates (custom error types,
    /// framework traits) that aren't in the static list.
    ///
    /// Names are matched case-sensitively. Example:
    ///   scanner.extra_rust_ecosystem_types = ["MyError", "AppResult"]
    #[serde(default)]
    pub extra_rust_ecosystem_types: Vec<String>,

    /// User-provided extensions to the built-in L1 fuzzy-match skip list
    /// (COMMON_NAMES in project_index.rs). Names listed here never trigger
    /// "Hallucinated API: X() (did you mean Y?)" warnings. Useful for
    /// domain-specific jargon, internal method names that fuzzy-match
    /// project tokens, or legacy identifiers known to be valid. Built-in
    /// list: ~80 names (Rust keywords, common verbs add/get/set, is_*
    /// predicates, fmt/from/into/as_ref, find/filter/map, validate/verify).
    /// Case-sensitive matching.
    #[serde(default)]
    pub extra_l1_skip_names: Vec<String>,

    /// Master switch for code-EXECUTING gates (go-public-graveyard
    /// BLOCKER-1): the output-prediction exec gate (python/node on LLM
    /// response code) AND the C# gate's auto-restore of NuGet packages
    /// derived from `using` lines (arbitrary package download + MSBuild
    /// target execution). Both are RCE-by-design surfaces — they run
    /// model-controlled code/builds on the scanner host.
    ///
    /// OFF by default. Opt in via config (`scanner.execution_gate: true`)
    /// or env `ANUBIS_EXECUTION_GATE=1`, only on hosts where the tradeoff
    /// is understood. The deterministic compiler/AST gates never execute
    /// response code and are unaffected.
    #[serde(default)]
    pub execution_gate: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            model: default_scanner_model(),
            base_url: default_scanner_url(),
            api_key: String::new(),
            block_on_hallucination: false,
            auto_inject_docs: false,
            preemptive_scan: false,
            post_edit_verify: false,
            max_concurrent_scans: None,
            extra_ts_exports: Vec::new(),
            extra_go_framework_pkgs: Vec::new(),
            extra_go_framework_funcs: Vec::new(),
            extra_rust_ecosystem_types: Vec::new(),
            extra_l1_skip_names: Vec::new(),
            execution_gate: false,
        }
    }
}

fn default_scanner_model() -> String {
    // Oracle fix #4: glm-4.7 (full) as default judge model.
    //
    // Previous: glm-4.7-flash — fast/cheap but made confident knowledge
    // errors (claimed std::setw doesn't exist, marked streamlit.text_field
    // as verified). glm-4.7 (full) catches canonical method hallucinations
    // (e.g., text_input vs text_field on streamlit) that flash misses.
    //
    // Cost: ~10x slower + 10x more expensive than flash, but quality bar
    // for hallucination detection requires it. Users wanting speed can
    // override via config (scanner.model = "glm-4.7-flash").
    "glm-4.7".to_string()
}

fn default_scanner_url() -> String {
    "https://api.z.ai/api/coding/paas/v4".to_string()
}

impl Default for ANUBISConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            routing: RoutingConfig::default(),
            scanner: ScannerConfig::default(),
            api_token: String::new(),
        }
    }
}

/// Generate a per-install admin token. Two time samples + PID + address
/// entropy through a hasher — not a cryptographic secret, but sufficient
/// defense against browser CSRF and unprivileged local processes (the
/// graveyard threat model: attackers who cannot read ~/.anubis/config.yaml).
pub fn generate_api_token() -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let a = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::thread::sleep(std::time::Duration::from_micros(50));
    let b = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    a.hash(&mut h);
    b.hash(&mut h);
    std::process::id().hash(&mut h);
    (&a as *const u128 as usize).hash(&mut h);
    format!("{:016x}{:016x}", h.finish(), b as u64)
}

impl ANUBISConfig {
    /// Resolve the target URL based on routing mode.
    /// - Sleev: auto-discover from gateway-runtime.json
    /// - Direct: empty — `x-anubis-target` header (set per-provider by harness
    ///   installer) is the sole authority. Direct mode MUST be the only proxy
    ///   hop between harness and model endpoint, so we never fall back to Sleev.
    /// - Custom: use custom_url (Sleev fallback if unset for backward compat)
    pub fn target_url(&self) -> String {
        match self.routing.mode {
            RoutingMode::Sleev => discover_sleev_url(),
            RoutingMode::Direct => String::new(),
            RoutingMode::Custom => {
                if self.routing.custom_url.is_empty() {
                    discover_sleev_url()
                } else {
                    self.routing.custom_url.clone()
                }
            }
        }
    }

    /// Resolve target headers — Sleev mode adds harness tags.
    pub fn target_headers(&self) -> Vec<(String, String)> {
        match self.routing.mode {
            RoutingMode::Sleev => vec![
                ("sleeve-provider".to_string(), "zai-coding-plan".to_string()),
                ("sleeve-harness".to_string(), "opencode".to_string()),
            ],
            _ => vec![],
        }
    }

    /// Build the proxy URL (http://host:port).
    pub fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.proxy.host, self.proxy.port)
    }

    /// Check if scanner endpoint is Sleev.
    pub fn scanner_is_sleev(&self) -> bool {
        let url = &self.scanner.base_url;
        url.contains("127.0.0.1:17321") || url.contains("localhost:17321")
    }

    /// Scanner target headers — injects Sleev tags when scanner hits Sleev.
    pub fn scanner_headers(&self) -> Vec<(String, String)> {
        if self.scanner_is_sleev() {
            vec![
                ("sleeve-provider".to_string(), "zai-coding-plan".to_string()),
                ("sleeve-harness".to_string(), "opencode".to_string()),
            ]
        } else {
            vec![]
        }
    }
}

/// Config file path: ~/.anubis/config.yaml
pub fn config_path() -> PathBuf {
    config_dir().join("config.yaml")
}

/// Version string (same as main.rs VERSION).
pub fn config_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// ~/.anubis/ directory.
pub fn config_dir() -> PathBuf {
    home_dir().join(".anubis")
}

/// Home directory (cross-platform).
pub fn home_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }
}

/// Load config from disk. Creates default if missing.
pub fn load_config() -> ANUBISConfig {
    let path = config_path();
    let mut cfg = match std::fs::read_to_string(&path) {
        Ok(yaml) => serde_yaml::from_str(&yaml).unwrap_or_default(),
        Err(_) => {
            // File doesn't exist — create with defaults
            let cfg = ANUBISConfig::default();
            save_config(&cfg);
            cfg
        }
    };

    // ── Per-install admin token (BLOCKER-2 hardening) ─────────────────
    // Generated once, persisted. Required as X-Anubis-Token on mutating
    // /__anubis/* routes + secret-bearing GETs. Threat model: browser
    // CSRF + unprivileged local processes (cannot read this file).
    if cfg.api_token.is_empty() {
        cfg.api_token = generate_api_token();
        tracing::info!(target: "config", "generated per-install admin token");
        save_config(&cfg);
    }

    // ── Auto-detect API key from harness configs if empty ───────────
    // The harness (opencode) already has the API key configured in its
    // MCP environment. Rather than forcing users to set it separately
    // in anubis config, we auto-detect it here.
    if cfg.scanner.api_key.is_empty() {
        if let Some(key) = detect_api_key_from_harnesses() {
            tracing::info!(
                target: "config",
                "auto-detected scanner API key from harness config"
            );
            cfg.scanner.api_key = key;
            // Persist so it survives restarts and other components can use it
            save_config(&cfg);
        }
    }

    cfg
}

/// Master switch for code-executing gates (BLOCKER-1 hardening).
/// ON only when BOTH config (`scanner.execution_gate: true`) AND env
/// (`ANUBIS_EXECUTION_GATE=1|true`) opt in. Default-off on every axis —
/// the env var alone can no longer enable execution (it was previously
/// an opt-OUT switch, inverted from safe defaults).
pub fn execution_gate_enabled() -> bool {
    let cfg_flag = load_config().scanner.execution_gate;
    let env_opt_in = std::env::var("ANUBIS_EXECUTION_GATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    cfg_flag && env_opt_in
}

/// Scan harness configs for API keys that the scanner can reuse.
/// Checks opencode's MCP environment variables and Authorization headers.
fn detect_api_key_from_harnesses() -> Option<String> {
    // Check opencode config
    let opencode_paths = [
        // Unix: ~/.config/opencode/opencode.json
        home_dir().join(".config").join("opencode").join("opencode.json"),
        // Windows: %USERPROFILE%\.config\opencode\opencode.json
    ];

    for path in &opencode_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                // Check MCP environment variables (Z_AI_API_KEY, OPENAI_API_KEY, etc.)
                if let Some(mcp) = json.get("mcp").and_then(|m| m.as_object()) {
                    for (_name, config) in mcp {
                        // Environment variables
                        if let Some(env) = config.get("environment").and_then(|e| e.as_object()) {
                            for (key, val) in env {
                                if key.ends_with("_API_KEY") || key.ends_with("_KEY") {
                                    if let Some(s) = val.as_str() {
                                        if !s.is_empty() && s.len() > 10 {
                                            return Some(s.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        // Authorization headers
                        if let Some(headers) = config.get("headers").and_then(|h| h.as_object()) {
                            if let Some(auth) = headers.get("Authorization").and_then(|a| a.as_str()) {
                                // Strip "Bearer " prefix if present
                                let key = auth.strip_prefix("Bearer ").unwrap_or(auth);
                                if !key.is_empty() && key.len() > 10 {
                                    return Some(key.to_string());
                                }
                            }
                        }
                    }
                }

                // Check provider options for API keys in headers
                if let Some(providers) = json.get("provider").and_then(|p| p.as_object()) {
                    for (_id, config) in providers {
                        if let Some(opts) = config.get("options").and_then(|o| o.as_object()) {
                            if let Some(headers) = opts.get("headers").and_then(|h| h.as_object()) {
                                for (key, val) in headers {
                                    let key_lower = key.to_lowercase();
                                    if key_lower == "authorization" || key_lower.contains("api-key") || key_lower.contains("apikey") {
                                        if let Some(s) = val.as_str() {
                                            let clean = s.strip_prefix("Bearer ").unwrap_or(s);
                                            if clean.len() > 10 {
                                                return Some(clean.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Save config to disk.
pub fn save_config(cfg: &ANUBISConfig) {
    if let Ok(yaml) = serde_yaml::to_string(cfg) {
        let _ = std::fs::create_dir_all(config_dir());
        let _ = std::fs::write(config_path(), yaml);
    }
}

/// Discover Sleev gateway URL from gateway-runtime.json.
/// Falls back to http://127.0.0.1:17321 if not found.
fn discover_sleev_url() -> String {
    let runtime_path = home_dir()
        .join(".local")
        .join("state")
        .join("sleev")
        .join("gateway-runtime.json");

    if let Ok(content) = std::fs::read_to_string(&runtime_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(base_url) = json.get("base_url").and_then(|v| v.as_str()) {
                return base_url.to_string();
            }
            // Try host + port fields
            let host = json
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1");
            let port = json.get("port").and_then(|v| v.as_u64()).unwrap_or(17321);
            return format!("http://{}:{}", host, port);
        }
    }

    "http://127.0.0.1:17321".to_string()
}
