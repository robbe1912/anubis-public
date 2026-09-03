// Provider upstream URL registry.
//
// Resolves provider IDs (e.g. "zai-coding-plan") to their canonical base URLs
// (e.g. "https://api.z.ai/api/coding/paas/v4"). Used by the harness layer to
// recover the real upstream URL when an agent config has been hijacked by Anubis
// (or another local proxy) — preventing the circular-dependency class of bug.
//
// Source: https://models.dev/api.json — public catalog of AI providers/models
// maintained at github.com/anomalyco/models.dev. Same source sst/opencode uses.
//
// Cache strategy:
//   - First boot: fetch synchronously (blocking short delay) OR fall back to empty
//   - Daemon boot: spawn async refresh task (non-blocking)
//   - Subsequent lookups: read from disk cache (24h TTL via mtime)
//   - Offline: stale cache is used indefinitely if fetch fails after TTL

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const REGISTRY_URL: &str = "https://models.dev/api.json";
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24h

/// SDK-default URLs for the ~10 "well-known" providers where models.dev leaves
/// `api` empty because the SDK npm package (e.g. `@ai-sdk/anthropic`) hardcodes
/// the URL. These match the upstream SDK defaults as of 2026-08.
/// Languages evolve — update from models.dev source if these drift.
const WELL_KNOWN_DEFAULTS: &[(&str, &str)] = &[
    ("anthropic", "https://api.anthropic.com/v1"),
    ("openai", "https://api.openai.com/v1"),
    ("google", "https://generativelanguage.googleapis.com/v1beta"),
    ("google-vertex", "https://us-central1-aiplatform.googleapis.com/v1"),
    ("google-vertex-anthropic", "https://us-central1-aiplatform.googleapis.com/v1"),
    ("xai", "https://api.x.ai/v1"),
    ("groq", "https://api.groq.com/openai/v1"),
    ("togetherai", "https://api.together.xyz/v1"),
    ("mistral", "https://api.mistral.ai/v1"),
    ("cohere", "https://api.cohere.com/v2"),
    ("perplexity", "https://api.perplexity.ai"),
    ("perplexity-agent", "https://api.perplexity.ai"),
    ("huggingface", "https://api-inference.huggingface.co"),
    ("nvidia", "https://integrate.api.nvidia.com/v1"),
    ("azure", "https://anubis.invalid/azure-requires-deployment-url"),
    ("amazon-bedrock", "https://anubis.invalid/bedrock-uses-aws-signing"),
];

#[derive(Debug, Clone, Default)]
pub struct Registry {
    /// provider_id (lowercase) → base URL
    providers: HashMap<String, String>,
}

impl Registry {
    /// Look up the canonical base URL for a provider ID.
    /// Returns None if unknown.
    pub fn get(&self, provider_id: &str) -> Option<&str> {
        let lower = provider_id.to_ascii_lowercase();
        if let Some(url) = self.providers.get(&lower) {
            return Some(url.as_str());
        }
        WELL_KNOWN_DEFAULTS
            .iter()
            .find(|(id, _)| *id == lower)
            .map(|(_, url)| *url)
    }

    /// Empty registry (used when fetch fails and no cache exists).
    pub fn empty() -> Self {
        Registry {
            providers: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

/// Path to the on-disk cache: `~/.anubis/registry-cache.json`.
pub fn cache_path() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".anubis").join("registry-cache.json")
}

/// Load registry from cache file. Returns None if cache missing, stale (>24h), or unparseable.
pub fn load_cached() -> Option<Registry> {
    let path = cache_path();
    let metadata = std::fs::metadata(&path).ok()?;
    let modified = metadata.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > CACHE_TTL {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    let parsed: HashMap<String, ProviderEntry> = serde_json::from_str(&content).ok()?;
    let providers = parsed
        .into_iter()
        .filter(|(_, p)| !p.api.is_empty())
        .map(|(id, p)| (id.to_ascii_lowercase(), p.api))
        .collect();
    Some(Registry { providers })
}

#[derive(Debug, Deserialize)]
struct ProviderEntry {
    #[serde(default)]
    api: String,
}

/// Fetch the latest registry from models.dev, write to cache, return Registry.
pub async fn refresh() -> Result<Registry> {
    let bytes = reqwest::get(REGISTRY_URL)
        .await
        .with_context(|| format!("fetch {REGISTRY_URL}"))?
        .bytes()
        .await
        .context("read body")?;

    // Parse before writing so we never poison the cache with garbage
    let parsed: HashMap<String, ProviderEntry> =
        serde_json::from_slice(&bytes).context("parse models.dev api.json")?;
    let providers: HashMap<String, String> = parsed
        .iter()
        .filter(|(_, p)| !p.api.is_empty())
        .map(|(id, p)| (id.to_ascii_lowercase(), p.api.clone()))
        .collect();

    if let Some(parent) = cache_path().parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("registry cache mkdir failed: {e}");
        }
    }
    if let Err(e) = std::fs::write(cache_path(), &bytes) {
        tracing::warn!("registry cache write failed: {e}");
    }

    tracing::info!("registry refreshed: {} providers", providers.len());
    Ok(Registry { providers })
}

/// Synchronous best-effort load. Returns cached registry if fresh, empty otherwise.
/// Used by harness.rs `list_harnesses` (sync code path) for provider URL resolution.
pub fn load_or_empty() -> Registry {
    load_cached().unwrap_or_else(Registry::empty)
}
