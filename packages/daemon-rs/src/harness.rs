// Harness detection + provider routing installer.
// Detects installed AI coding agents (opencode, claude-code, codex, cline, continue),
// reads their provider configs, and routes traffic through the ANUBIS proxy
// by rewriting baseURL fields. Originals are backed up for restore-on-disable.

use crate::registry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Local proxy host:port patterns that, if seen in a stored URL, indicate the
/// URL points at Anubis itself (or another known local proxy like Sleev) rather
/// than a real upstream. Conservative: only known proxy ports are rejected so
/// legit local services (e.g. Ollama on :11434) keep working.
const KNOWN_PROXY_HOSTS: &[&str] = &[
    "127.0.0.1:7878",
    "127.0.0.1:17321",
    "localhost:7878",
    "localhost:17321",
    "[::1]:7878",
    "[::1]:17321",
];

/// Returns true if `url` points at the Anubis proxy itself (`proxy_url`) or any
/// other known local proxy. Used to detect the circular-dependency class of bug
/// where reading an agent config back yields a URL that loops through Anubis.
///
/// Empty `url` is never a loop. Empty `proxy_url` only triggers the known-host
/// pattern check (still catches Sleev→Anubis chains).
pub fn is_proxy_loop(url: &str, proxy_url: &str) -> bool {
    let url_t = url.trim();
    if url_t.is_empty() {
        return false;
    }
    if !proxy_url.trim().is_empty() && url_t == proxy_url.trim() {
        return true;
    }
    let lower = url_t.to_ascii_lowercase();
    KNOWN_PROXY_HOSTS.iter().any(|h| lower.contains(h))
}

/// Header injected into opencode provider options so the proxy knows the target harness.
const X_ANUBIS_TARGET: &str = "x-anubis-target";

/// Harness IDs known to the registry (order = display order in TUI).
const HARNESS_IDS: &[&str] = &["opencode", "claude-code", "codex", "cline", "continue"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRoute {
    pub id: String,
    pub name: String,
    pub original_url: String,
    pub routed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessStatus {
    pub id: String,
    pub name: String,
    pub config_path: String,
    pub installed: bool,
    pub providers: Vec<ProviderRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BackupFile {
    #[serde(default)]
    providers: BTreeMap<String, BackupEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEntry {
    #[serde(rename = "originalUrl")]
    original_url: String,
}

/// Detect every known harness, read its config, and report which providers
/// are currently pointed at the proxy.
pub fn list_harnesses(proxy_url: &str) -> Vec<HarnessStatus> {
    HARNESS_IDS
        .iter()
        .map(|id| probe_harness(id, proxy_url))
        .collect()
}

fn probe_harness(id: &str, proxy_url: &str) -> HarnessStatus {
    let (name, config_path) = harness_meta(id);
    let installed = !config_path.is_empty() && PathBuf::from(&config_path).exists();
    let mut providers = if installed {
        read_providers(id).unwrap_or_default()
    } else {
        Vec::new()
    };
    // Live config URLs are read post-hijack, so for any provider whose URL
    // points back at Anubis (or another local proxy), resolve the real upstream
    // from backup first, then the models.dev registry. This prevents the
    // dashboard "Direct" mode from showing Anubis→Anubis circular URLs.
    let reg = registry::load_or_empty();
    for p in providers.iter_mut() {
        let raw = p.original_url.clone();
        // routed = "currently pointed at Anubis in live config"
        p.routed = raw == proxy_url;
        if is_proxy_loop(&raw, proxy_url) {
            p.original_url = resolve_upstream(id, &p.id, &raw, proxy_url, &reg);
        }
    }
    HarnessStatus {
        id: id.to_string(),
        name,
        config_path,
        installed,
        providers,
    }
}

/// Resolve the real upstream URL for a provider when the live config URL is a
/// proxy loop. Resolution order:
///   1. Backup file (if it exists AND the backup URL is itself not a loop)
///   2. models.dev registry (cached, covers zai-coding-plan + ~170 others)
///   3. Give up — return the raw URL. Callers can detect unresolved loops with
///      `is_proxy_loop()` and surface "(needs URL)" in the UI.
fn resolve_upstream(
    harness_id: &str,
    provider_id: &str,
    raw_url: &str,
    proxy_url: &str,
    reg: &registry::Registry,
) -> String {
    // 1. Backup
    if let Some(backup_url) = load_backup_url(harness_id, provider_id) {
        if !backup_url.is_empty() && !is_proxy_loop(&backup_url, proxy_url) {
            return backup_url;
        }
    }
    // 2. Registry (provider IDs often match across harnesses — e.g. "zai-coding-plan"
    //    in opencode matches models.dev's `zai-coding-plan` entry)
    if let Some(canonical) = reg.get(provider_id) {
        return canonical.to_string();
    }
    // 3. Nothing left to try
    raw_url.to_string()
}

/// Look up a single provider's backup URL. Empty string if no backup exists.
/// Look up the resolved backup URL for a harness. Returns the first non-empty
/// backup URL (after proxy-loop validation), or None if no usable backup exists.
///
/// Used by proxy.rs in Direct mode for harnesses that can't send per-request
/// `x-anubis-target` headers (Claude Code, Codex, Continue). For those, the
/// proxy falls back to reading the harness's backup file to find the real
/// upstream URL.
pub fn direct_target_for(harness_id: &str) -> Option<String> {
    let backup = load_backup(harness_id);
    for entry in backup.providers.values() {
        let url = entry.original_url.trim();
        if !url.is_empty() && !is_proxy_loop(url, "") {
            return Some(url.to_string());
        }
    }
    None
}

/// Look up a specific provider's resolved URL in a harness backup.
/// Like `direct_target_for` but for harnesses with multiple providers
/// (e.g. opencode with several configured). Returns None if not found or invalid.
pub fn direct_target_for_provider(harness_id: &str, provider_id: &str) -> Option<String> {
    let backup = load_backup(harness_id);
    backup.providers.get(provider_id).map(|e| e.original_url.clone()).filter(|u| {
        !u.is_empty() && !is_proxy_loop(u, "")
    })
}

fn load_backup_url(harness_id: &str, provider_id: &str) -> Option<String> {
    let backup = load_backup(harness_id);
    backup
        .providers
        .get(provider_id)
        .map(|e| e.original_url.clone())
}

/// Display name + on-disk config path for a harness ID.
/// Returns empty path when the harness ID is unknown.
fn harness_meta(id: &str) -> (String, String) {
    let home = home_dir();
    let cfg = home.join(".config");
    match id {
        "opencode" => (
            "OpenCode".into(),
            cfg.join("opencode")
                .join("opencode.json")
                .to_string_lossy()
                .into_owned(),
        ),
        "claude-code" => (
            "Claude Code".into(),
            home.join(".claude")
                .join("settings.json")
                .to_string_lossy()
                .into_owned(),
        ),
        "codex" => (
            "Codex".into(),
            home.join(".codex")
                .join("config.toml")
                .to_string_lossy()
                .into_owned(),
        ),
        "cline" => {
            // Prefer .cline/endpoints.json, fall back to .kilo/kilo.jsonc.
            let primary = home.join(".cline").join("endpoints.json");
            let alt = home.join(".kilo").join("kilo.jsonc");
            let path = if primary.exists() { primary } else { alt };
            ("Cline".into(), path.to_string_lossy().into_owned())
        }
        "continue" => (
            "Continue".into(),
            home.join(".continue")
                .join("config.yaml")
                .to_string_lossy()
                .into_owned(),
        ),
        _ => ("Unknown".into(), String::new()),
    }
}

/// Read providers from the harness config. Returns Err on parse failure so callers
/// can decide whether to surface an empty list or a diagnostic.
fn read_providers(harness_id: &str) -> Result<Vec<ProviderRoute>, String> {
    let (_, config_path) = harness_meta(harness_id);
    if config_path.is_empty() {
        return Ok(Vec::new());
    }
    let content =
        std::fs::read_to_string(&config_path).map_err(|e| format!("read {config_path}: {e}"))?;
    match harness_id {
        "opencode" => read_opencode(&content),
        "claude-code" => read_claude(&content),
        "codex" => read_codex(&content),
        "cline" => read_cline(&content),
        "continue" => read_continue(&content),
        _ => Ok(Vec::new()),
    }
}

fn read_opencode(content: &str) -> Result<Vec<ProviderRoute>, String> {
    let json: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("parse opencode.json: {e}"))?;
    let obj = json
        .get("provider")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "opencode.json: missing provider object".to_string())?;
    Ok(obj
        .iter()
        .filter_map(|(id, p)| {
            let base = p.pointer("/options/baseURL")?.as_str()?;
            Some(ProviderRoute {
                id: id.clone(),
                name: id.clone(),
                original_url: base.to_string(),
                routed: false,
            })
        })
        .collect())
}

fn read_claude(content: &str) -> Result<Vec<ProviderRoute>, String> {
    let json: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("parse settings.json: {e}"))?;
    let url = json
        .pointer("/env/ANTHROPIC_BASE_URL")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if url.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![ProviderRoute {
        id: "default".into(),
        name: "Anthropic".into(),
        original_url: url.to_string(),
        routed: false,
    }])
}

fn read_codex(content: &str) -> Result<Vec<ProviderRoute>, String> {
    // Match `base_url = "..."` in the [provider.openai] section. We don't ship a TOML
    // parser; the first non-comment base_url under that section is the live one.
    let section = content
        .split("[provider.openai]")
        .nth(1)
        .map(|s| {
            // Stop at the next section header.
            s.split("\n[").next().unwrap_or(s)
        })
        .unwrap_or("");
    let re = regex::Regex::new(r#"(?m)^\s*base_url\s*=\s*"([^"]+)"\s*$"#).unwrap();
    let url = re
        .captures(section)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    Ok(url
        .into_iter()
        .map(|u| ProviderRoute {
            id: "openai".into(),
            name: "OpenAI".into(),
            original_url: u,
            routed: false,
        })
        .collect())
}

fn read_cline(content: &str) -> Result<Vec<ProviderRoute>, String> {
    let cleaned = strip_jsonc_comments(content);
    let json: serde_json::Value =
        serde_json::from_str(&cleaned).map_err(|e| format!("parse cline/kilo config: {e}"))?;
    let arr = json.get("providers").and_then(|v| v.as_array());
    match arr {
        Some(arr) => Ok(arr
            .iter()
            .filter_map(|p| {
                let id = p.get("id")?.as_str()?.to_string();
                let base = p.get("apiBaseUrl")?.as_str()?.to_string();
                Some(ProviderRoute {
                    id: id.clone(),
                    name: id,
                    original_url: base,
                    routed: false,
                })
            })
            .collect()),
        None => Ok(Vec::new()),
    }
}

fn read_continue(content: &str) -> Result<Vec<ProviderRoute>, String> {
    let yaml: serde_json::Value =
        serde_yaml::from_str(content).map_err(|e| format!("parse config.yaml: {e}"))?;
    let arr = yaml.get("models").and_then(|v| v.as_array());
    match arr {
        Some(arr) => Ok(arr
            .iter()
            .filter_map(|m| {
                let title = m.get("title")?.as_str()?.to_string();
                let base = m.get("apiBase")?.as_str()?.to_string();
                Some(ProviderRoute {
                    id: title.clone(),
                    name: title,
                    original_url: base,
                    routed: false,
                })
            })
            .collect()),
        None => Ok(Vec::new()),
    }
}

/// Point a harness provider at the proxy. Records the original URL so it can be
/// restored by `disable_provider`.
///
/// If the live config URL is itself a proxy loop (already hijacked by Anubis,
/// or pointed at Sleev / another local proxy), resolves the real upstream via
/// backup → models.dev registry before hijacking. This is critical: Direct mode
/// must be the only proxy hop between harness and model endpoint — we never
/// want opencode → Anubis → Sleev → ??? chains.
pub fn enable_provider(harness_id: &str, provider_id: &str, proxy_url: &str) -> Result<(), String> {
    let (_, config_path) = harness_meta(harness_id);
    if config_path.is_empty() {
        return Err(format!("unknown harness: {harness_id}"));
    }
    if !PathBuf::from(&config_path).exists() {
        return Err(format!("harness config not found: {config_path}"));
    }
    let current = find_provider_url(harness_id, provider_id)?;
    let real_url = if is_proxy_loop(&current, proxy_url) {
        let reg = registry::load_or_empty();
        let resolved = resolve_upstream(harness_id, provider_id, &current, proxy_url, &reg);
        if is_proxy_loop(&resolved, proxy_url) {
            return Err(format!(
                "cannot enable {provider_id} in {harness_id}: live URL '{current}' is a proxy \
                 loop and no backup or models.dev entry provides the real upstream. Set the \
                 real URL in the agent config (e.g. opencode.json) first."
            ));
        }
        resolved
    } else {
        current
    };
    // Capture the resolved real URL — validator refuses loops, real_url is
    // clean by construction so this also heals any previously-corrupt backup.
    save_backup(harness_id, provider_id, &real_url)?;
    // Hijack: baseURL → proxy, x-anubis-target → real URL (NOT the loop URL).
    set_provider_url(harness_id, provider_id, proxy_url, &real_url)
}

/// Restore a harness provider to its original URL.
pub fn disable_provider(harness_id: &str, provider_id: &str) -> Result<(), String> {
    let url = pop_backup(harness_id, provider_id)?;
    // Both baseURL and x-anubis-target get the real URL — harmless redundancy
    // when Anubis is no longer in the path (header ignored by upstream).
    set_provider_url(harness_id, provider_id, &url, &url)
}

fn find_provider_url(harness_id: &str, provider_id: &str) -> Result<String, String> {
    read_providers(harness_id)?
        .into_iter()
        .find(|p| p.id == provider_id)
        .map(|p| p.original_url)
        .ok_or_else(|| format!("provider {provider_id} not found in {harness_id}"))
}

fn set_provider_url(
    harness_id: &str,
    provider_id: &str,
    new_baseurl: &str,
    target_url: &str,
) -> Result<(), String> {
    let (_, config_path) = harness_meta(harness_id);
    let content =
        std::fs::read_to_string(&config_path).map_err(|e| format!("read {config_path}: {e}"))?;
    let updated = match harness_id {
        "opencode" => set_opencode(&content, provider_id, new_baseurl, target_url)?,
        "claude-code" => set_claude(&content, new_baseurl)?,
        "codex" => set_codex(&content, new_baseurl)?,
        "cline" => set_cline(&content, provider_id, new_baseurl)?,
        "continue" => set_continue(&content, provider_id, new_baseurl)?,
        _ => return Err(format!("unknown harness: {harness_id}")),
    };
    std::fs::write(&config_path, updated).map_err(|e| format!("write {config_path}: {e}"))
}

fn set_opencode(
    content: &str,
    provider_id: &str,
    new_url: &str,
    target_url: &str,
) -> Result<String, String> {
    let mut json: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("parse opencode.json: {e}"))?;
    let providers = json
        .get_mut("provider")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| "opencode.json: missing provider object".to_string())?;
    let p = providers
        .get_mut(provider_id)
        .ok_or_else(|| format!("provider {provider_id} not found in opencode.json"))?;
    if let Some(opts) = p.get_mut("options").and_then(|v| v.as_object_mut()) {
        opts.insert("baseURL".into(), serde_json::json!(new_url));
        let headers = opts
            .entry("headers")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(h) = headers.as_object_mut() {
            h.insert(X_ANUBIS_TARGET.into(), serde_json::json!(target_url));
        }
    }
    serde_json::to_string_pretty(&json).map_err(|e| format!("serialize opencode.json: {e}"))
}

fn set_claude(content: &str, new_url: &str) -> Result<String, String> {
    let mut json: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("parse settings.json: {e}"))?;
    let env = json
        .get_mut("env")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| "settings.json: missing env object".to_string())?;
    env.insert("ANTHROPIC_BASE_URL".into(), serde_json::json!(new_url));
    serde_json::to_string_pretty(&json).map_err(|e| format!("serialize settings.json: {e}"))
}

fn set_codex(content: &str, new_url: &str) -> Result<String, String> {
    // Replace the first `base_url = "..."` line that lives under [provider.openai].
    // If the line is absent but the section exists, append it; otherwise append the section.
    let re = regex::Regex::new(r#"(?m)^(\s*base_url\s*=\s*)"[^"]*"(.*)$"#).unwrap();
    let replacement = format!("${{1}}\"{new_url}\"${{2}}");
    let section = content
        .split("[provider.openai]")
        .nth(1)
        .map(|s| s.split("\n[").next().unwrap_or(s))
        .unwrap_or("");
    if re.is_match(section) {
        // Apply replacement only within the [provider.openai] section.
        let section_new = re.replace_all(section, replacement.as_str()).into_owned();
        return Ok(content.replacen(section, &section_new, 1));
    }
    if content.contains("[provider.openai]") {
        let insert_at = content.find("[provider.openai]").unwrap() + "[provider.openai]".len();
        let mut out = String::with_capacity(content.len() + new_url.len() + 32);
        out.push_str(&content[..insert_at]);
        out.push_str(&format!("\nbase_url = \"{new_url}\""));
        out.push_str(&content[insert_at..]);
        Ok(out)
    } else {
        Ok(format!(
            "{content}\n[provider.openai]\nbase_url = \"{new_url}\"\n"
        ))
    }
}

fn set_cline(content: &str, provider_id: &str, new_url: &str) -> Result<String, String> {
    // JSONC comments are stripped before parse; we write back plain JSON (comments lost).
    let cleaned = strip_jsonc_comments(content);
    let mut json: serde_json::Value =
        serde_json::from_str(&cleaned).map_err(|e| format!("parse cline/kilo config: {e}"))?;
    let providers = json
        .get_mut("providers")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "cline/kilo config: missing providers array".to_string())?;
    for p in providers.iter_mut() {
        if p.get("id").and_then(|v| v.as_str()) == Some(provider_id) {
            if let Some(obj) = p.as_object_mut() {
                obj.insert("apiBaseUrl".into(), serde_json::json!(new_url));
            }
            return serde_json::to_string_pretty(&json)
                .map_err(|e| format!("serialize cline/kilo config: {e}"));
        }
    }
    Err(format!(
        "provider {provider_id} not found in cline/kilo config"
    ))
}

fn set_continue(content: &str, provider_id: &str, new_url: &str) -> Result<String, String> {
    let mut yaml: serde_json::Value =
        serde_yaml::from_str(content).map_err(|e| format!("parse config.yaml: {e}"))?;
    let models = yaml
        .get_mut("models")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "config.yaml: missing models array".to_string())?;
    for m in models.iter_mut() {
        if m.get("title").and_then(|v| v.as_str()) == Some(provider_id) {
            if let Some(obj) = m.as_object_mut() {
                obj.insert("apiBase".into(), serde_json::json!(new_url));
            }
            return serde_yaml::to_string(&yaml).map_err(|e| format!("serialize config.yaml: {e}"));
        }
    }
    Err(format!("model {provider_id} not found in continue config"))
}

// --- Backup storage: ~/.anubis/backups/<harness_id>.json ---

fn backup_file_path(harness_id: &str) -> PathBuf {
    home_dir()
        .join(".anubis")
        .join("backups")
        .join(format!("{harness_id}.json"))
}

fn load_backup(harness_id: &str) -> BackupFile {
    let path = backup_file_path(harness_id);
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => BackupFile::default(),
    }
}

fn save_backup_file(harness_id: &str, backup: &BackupFile) -> Result<(), String> {
    let path = backup_file_path(harness_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let content =
        serde_json::to_string_pretty(backup).map_err(|e| format!("serialize backup: {e}"))?;
    std::fs::write(&path, content).map_err(|e| format!("write {}: {e}", path.display()))
}

fn save_backup(harness_id: &str, provider_id: &str, original_url: &str) -> Result<(), String> {
    // Refuse to capture proxy URLs as "original" — this is the root cause of
    // backup pollution: when Anubis hijacks an already-hijacked config (e.g.
    // user had Sleev mode on, then switched to Anubis), the "original" URL
    // captured is itself a proxy URL. Next hijack captures the new proxy URL,
    // compounding the loop. Reject upfront so backups only ever contain real
    // upstream URLs.
    if is_proxy_loop(original_url, "") {
        return Err(format!(
            "refusing to back up proxy URL '{original_url}' for {harness_id}/{provider_id} \
             — this would create a circular dependency (Anubis → proxy → ???). \
             Either let Anubis resolve via models.dev registry, or set the real \
             upstream URL in the agent config first."
        ));
    }
    let mut backup = load_backup(harness_id);
    backup.providers.insert(
        provider_id.into(),
        BackupEntry {
            original_url: original_url.to_string(),
        },
    );
    save_backup_file(harness_id, &backup)
}

/// Remove and return the stored original URL for a provider. Returns Err if no
/// backup exists (i.e. the provider was never routed).
fn pop_backup(harness_id: &str, provider_id: &str) -> Result<String, String> {
    let mut backup = load_backup(harness_id);
    let entry = backup
        .providers
        .remove(provider_id)
        .ok_or_else(|| format!("no backup for provider {provider_id} in {harness_id}"))?;
    save_backup_file(harness_id, &backup)?;
    Ok(entry.original_url)
}

// --- JSONC comment stripping (handles // and /* */ outside strings) ---

fn strip_jsonc_comments(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    let mut string_char = '\0';
    while i < chars.len() {
        let c = chars[i];
        let next = if i + 1 < chars.len() {
            chars[i + 1]
        } else {
            '\0'
        };
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == string_char {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            in_string = true;
            string_char = c;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && next == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Home directory (USERPROFILE preferred on Windows, HOME elsewhere).
fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .ok()
        .or_else(|| std::env::var("HOME").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
