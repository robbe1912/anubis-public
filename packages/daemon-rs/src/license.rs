// License validation via Keygen.sh REST API (no SDK).
// License key + machine_id stored encrypted in OS keychain. Tier/timestamp in file.
//
// ── OPEN-SOURCE BUILD: ENFORCEMENT DISABLED ─────────────────────────────────
// The commercial product this gated was killed (see docs/anubis-postmortem.md).
// The full keygen/trial machinery is retained for reference, but every gate
// short-circuits: `has_license()` reports true, validation/check-in skip all
// network calls, and no Keygen account/product identifiers ship in source
// (they come from build-time env vars only when re-arming a private build).
pub const LICENSE_ENFORCEMENT_ENABLED: bool = false;

pub const KEYGEN_ACCOUNT: &str = match option_env!("ANUBIS_KEYGEN_ACCOUNT") {
    Some(v) => v,
    None => "00000000-0000-0000-0000-000000000000",
};
pub const KEYGEN_PRODUCT: &str = match option_env!("ANUBIS_KEYGEN_PRODUCT") {
    Some(v) => v,
    None => "00000000-0000-0000-0000-000000000000",
};
const KEYGEN_API: &str = "https://api.keygen.sh";

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const OFFLINE_GRACE_HOURS: i64 = 168;
const KEYCHAIN_SERVICE: &str = "anubis-ai";
const KEYCHAIN_ENTRY: &str = "license";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseState {
    pub tier: LicenseTier,
    pub last_validated: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub license_id: Option<String>,
    #[serde(default)]
    pub tier_label: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub expiry: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LicenseTier {
    Trial,
    Licensed,
    #[allow(dead_code)]
    Mercury,
}

impl Default for LicenseState {
    fn default() -> Self {
        LicenseState {
            tier: LicenseTier::Trial,
            last_validated: chrono::Utc::now(),
            license_id: None,
            tier_label: None,
            email: None,
            expiry: None,
        }
    }
}

impl LicenseState {
    pub fn is_within_grace(&self) -> bool {
        if self.tier != LicenseTier::Licensed {
            return false;
        }
        let elapsed = chrono::Utc::now().signed_duration_since(self.last_validated);
        elapsed.num_hours() < OFFLINE_GRACE_HOURS
    }
}

// ── Encrypted key storage (OS keychain) ─────────────────────────────────────

fn store_keychain(key: &str, machine_id: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ENTRY)?;
    let combined = format!("{}|{}", key, machine_id);
    entry.set_password(&combined)?;
    Ok(())
}

fn load_keychain() -> Option<(String, String)> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ENTRY).ok()?;
    let stored = entry.get_password().ok()?;
    let parts: Vec<&str> = stored.splitn(2, '|').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

fn delete_keychain() {
    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ENTRY) {
        let _ = entry.delete_credential();
    }
}

pub fn has_license_key() -> bool {
    load_keychain().is_some()
}

/// Remove local credentials without contacting Keygen API.
/// Used when --remove should succeed even if the API key is already invalid.
pub fn delete_local_credentials() {
    let _ = delete_keychain();
    if let Ok(path) = meta_path() {
        let _ = fs::remove_file(path);
    }
}

// ── Non-secret metadata file ────────────────────────────────────────────────

fn meta_path() -> Result<PathBuf> {
    let home = dirs_home()?;
    Ok(home.join(".anubis").join("license-meta.json"))
}

pub fn load_state() -> LicenseState {
    match meta_path() {
        Ok(path) if path.exists() => match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => LicenseState::default(),
        },
        _ => LicenseState::default(),
    }
}

fn save_meta(state: &LicenseState) -> Result<()> {
    let path = meta_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    fs::write(&path, json)?;
    Ok(())
}

// ── Keygen REST API (pure reqwest, no SDK) ──────────────────────────────────

fn keygen_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("anubis/0.1.0")
        .build()?)
}

fn get_fingerprint() -> Result<String> {
    machine_uid::get().map_err(|e| anyhow::anyhow!("machine fingerprint error: {}", e))
}

/// Metadata extracted from Keygen validate-key response.
#[derive(Debug, Clone, Default)]
pub struct LicenseMeta {
    pub tier_label: Option<String>,
    pub email: Option<String>,
    pub expiry: Option<String>,
}

/// Extract license metadata from Keygen response body.
fn extract_meta(body: &serde_json::Value) -> LicenseMeta {
    LicenseMeta {
        tier_label: body
            .pointer("/data/attributes/metadata/tier")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        email: body
            .pointer("/data/attributes/metadata/email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        expiry: body
            .pointer("/data/attributes/expiry")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }
}

/// Validate a license key against Keygen.
/// Returns Ok(Some((machine_id, license_id))) if license is valid AND machine is activated.
/// Returns Ok(None) if license is valid but machine NOT yet activated. (license_id available in Ok(None)? No — return tuple always)
/// Returns Err if license is invalid/expired/suspended.
async fn validate_key(
    client: &reqwest::Client,
    license_key: &str,
    fingerprint: &str,
) -> Result<(Option<String>, String, LicenseMeta)> {
    let url = format!(
        "{}/v1/accounts/{}/licenses/actions/validate-key",
        KEYGEN_API, KEYGEN_ACCOUNT
    );

    // Policy has strict:true — requires product + fingerprint scope
    let body = serde_json::json!({
        "meta": {
            "key": license_key,
            "scope": {
                "product": KEYGEN_PRODUCT,
                "fingerprint": fingerprint
            }
        }
    });

    let json_str = serde_json::to_string(&body)?;
    let resp = client
        .post(&url)
        .header("Content-Type", "application/vnd.api+json")
        .header("Accept", "application/vnd.api+json")
        .body(json_str)
        .send()
        .await?;

    let status = resp.status();
    let resp_text = resp.text().await?;
    let body: serde_json::Value = serde_json::from_str(&resp_text)?;

    if !status.is_success() {
        let detail = body
            .pointer("/errors/0/detail")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        let code = body
            .pointer("/errors/0/code")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        return Err(anyhow::anyhow!("{} ({}): {}", status, code, detail));
    }

    let valid = body
        .pointer("/meta/valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !valid {
        // Check WHY validation failed before deciding what to do
        let code = body
            .pointer("/meta/code")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let license_id = body
            .pointer("/data/id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Only attempt activation if machine hasn't been activated yet
        match code {
            "NO_MACHINES" | "FINGERPRINT_SCOPE_MISMATCH" | "" => {
                // Machine needs activation — caller handles this
                return Ok((None, license_id, extract_meta(&body)));
            }
            _ => {
                // SUSPENDED, EXPIRED, BANNED, CHECK_IN_OVERDUE, etc — Keygen rejected
                let detail = body
                    .pointer("/meta/detail")
                    .and_then(|v| v.as_str())
                    .unwrap_or("license rejected");
                return Err(anyhow::anyhow!("license rejected ({}): {}", code, detail));
            }
        }
    }

    // meta.valid is true → Keygen confirmed this fingerprint is activated.
    // Per Keygen docs: fingerprint scope + meta.valid:true = machine is authorized.
    // No need to check machines relationship (not included without ?include=machines).
    let license_id = body
        .pointer("/data/id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Return the machine_id from keychain if available (for deactivation later).
    let machine_id = load_keychain().map(|(_, mid)| mid).unwrap_or_default();

    Ok((Some(machine_id), license_id, extract_meta(&body)))
}

/// Activate a machine on a license via Keygen REST API.
/// Returns the machine UUID.
async fn activate_machine(
    client: &reqwest::Client,
    license_key: &str,
    license_id: &str,
    fingerprint: &str,
) -> Result<String> {
    let url = format!("{}/v1/accounts/{}/machines", KEYGEN_API, KEYGEN_ACCOUNT);

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let body = serde_json::json!({
        "data": {
            "type": "machines",
            "attributes": {
                "fingerprint": fingerprint,
                "platform": std::env::consts::OS,
                "name": hostname,
            },
            "relationships": {
                "license": {
                    "data": {
                        "type": "licenses",
                        "id": license_id
                    }
                }
            }
        }
    });

    let json_str = serde_json::to_string(&body)?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("License {}", license_key))
        .header("Accept", "application/vnd.api+json")
        .header("Content-Type", "application/vnd.api+json")
        .body(json_str)
        .send()
        .await?;

    let status = resp.status();
    let resp_text = resp.text().await?;
    let resp_body: serde_json::Value = serde_json::from_str(&resp_text)?;

    if !status.is_success() {
        let detail = resp_body
            .pointer("/errors/0/detail")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        let code = resp_body
            .pointer("/errors/0/code")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        return Err(anyhow::anyhow!("{} ({}): {}", status, code, detail));
    }

    let machine_id = resp_body
        .pointer("/data/id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("activation succeeded but Keygen did not return machine ID")
        })?
        .to_string();

    Ok(machine_id)
}

/// Deactivate a machine from a license via Keygen REST API.
async fn deactivate_machine(
    client: &reqwest::Client,
    license_key: &str,
    machine_id: &str,
) -> Result<()> {
    let url = format!(
        "{}/v1/accounts/{}/machines/{}",
        KEYGEN_API, KEYGEN_ACCOUNT, machine_id
    );

    let resp = client
        .delete(&url)
        .header("Authorization", format!("License {}", license_key))
        .header("Accept", "application/vnd.api+json")
        .send()
        .await?;

    if !resp.status().is_success() {
        let resp_text = resp.text().await?;
        let body: serde_json::Value = serde_json::from_str(&resp_text)?;
        let detail = body
            .pointer("/errors/0/detail")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(anyhow::anyhow!("deactivation failed: {}", detail));
    }

    Ok(())
}

// ── Public API ──────────────────────────────────────────────────────────────

pub fn has_license() -> bool {
    if !LICENSE_ENFORCEMENT_ENABLED {
        return true; // open-source build: all license gates pass
    }
    load_keychain().is_some()
}

/// Activate a license key. Validates first, activates machine if needed.
/// If old credentials exist in keychain, deactivates old machine first.
pub async fn activate_license(license_key: &str) -> Result<LicenseState> {
    if !LICENSE_ENFORCEMENT_ENABLED {
        return Err(anyhow::anyhow!(
            "license enforcement is disabled in this build — nothing to activate"
        ));
    }
    // Deactivate old machine on Keygen before activating new key.
    // Frees the fingerprint so the new license can claim it.
    if let Some((old_key, old_machine_id)) = load_keychain() {
        if old_key != license_key {
            eprintln!("[anubis] deactivating previous machine...");
            if let Ok(client) = keygen_client() {
                let _ = deactivate_machine(&client, &old_key, &old_machine_id).await;
            }
        }
    }

    let client = keygen_client()?;
    let fingerprint = get_fingerprint()?;

    // Step 1: Validate key with fingerprint scope.
    match validate_key(&client, license_key, &fingerprint).await {
        Ok((Some(machine_id), license_id, meta)) => {
            // Already activated on this machine.
            store_keychain(license_key, &machine_id)?;
            let state = LicenseState {
                tier: LicenseTier::Licensed,
                last_validated: chrono::Utc::now(),
                license_id: Some(license_id),
                tier_label: meta.tier_label,
                email: meta.email,
                expiry: meta.expiry,
            };
            save_meta(&state)?;
            Ok(state)
        }
        Ok((None, license_id, meta)) => {
            // License valid but machine not activated yet. Activate now.
            let machine_id =
                activate_machine(&client, license_key, &license_id, &fingerprint).await?;
            store_keychain(license_key, &machine_id)?;
            let state = LicenseState {
                tier: LicenseTier::Licensed,
                last_validated: chrono::Utc::now(),
                license_id: Some(license_id.clone()),
                tier_label: meta.tier_label,
                email: meta.email,
                expiry: meta.expiry,
            };
            save_meta(&state)?;
            Ok(state)
        }
        Err(e) => Err(anyhow::anyhow!("license validation failed: {}", e)),
    }
}

/// Validate existing license on daemon startup.
pub async fn validate_existing() -> LicenseTier {
    if !LICENSE_ENFORCEMENT_ENABLED {
        return LicenseTier::Licensed; // open-source build: skip keychain + network entirely
    }
    let state = load_state();

    if state.tier != LicenseTier::Licensed {
        return LicenseTier::Trial;
    }

    if !state.is_within_grace() {
        return LicenseTier::Trial;
    }

    let (key, _machine_id) = match load_keychain() {
        Some(v) => v,
        None => return LicenseTier::Trial,
    };

    let fingerprint = match get_fingerprint() {
        Ok(fp) => fp,
        Err(_) => return LicenseTier::Licensed,
    };

    let client = match keygen_client() {
        Ok(c) => c,
        Err(_) => return LicenseTier::Licensed, // can't build client, trust offline grace
    };

    match validate_key(&client, &key, &fingerprint).await {
        Ok((Some(_machine_id), _license_id, meta)) => {
            // Keygen confirmed: key valid AND fingerprint activated.
            let updated = LicenseState {
                last_validated: chrono::Utc::now(),
                tier_label: meta.tier_label.or(state.tier_label.clone()),
                email: meta.email.or(state.email.clone()),
                expiry: meta.expiry.or(state.expiry.clone()),
                ..state
            };
            let _ = save_meta(&updated);
            LicenseTier::Licensed
        }
        Ok((None, license_id, meta)) => {
            // Keygen says: key valid BUT this machine not activated.
            // Keygen is sole source of truth — try to activate now.
            match activate_machine(&client, &key, &license_id, &fingerprint).await {
                Ok(machine_id) => {
                    let _ = store_keychain(&key, &machine_id);
                    let updated = LicenseState {
                        last_validated: chrono::Utc::now(),
                        tier_label: meta.tier_label.or(state.tier_label.clone()),
                        email: meta.email.or(state.email.clone()),
                        expiry: meta.expiry.or(state.expiry.clone()),
                        ..state
                    };
                    let _ = save_meta(&updated);
                    LicenseTier::Licensed
                }
                Err(_) => LicenseTier::Trial,
            }
        }
        Err(e) => {
            // Network/infrastructure error — stay Licensed during offline grace period.
            // Keygen 5xx, Cloudflare, DNS, timeout, connection refused all treated as transient.
            let err_str = format!("{}", e);
            let is_transient = err_str.contains("error sending request")
                || err_str.contains("timeout")
                || err_str.contains("connection")
                || err_str.contains("dns")
                || err_str.contains("503")
                || err_str.contains("502")
                || err_str.contains("504")
                || err_str.contains("500");
            if is_transient {
                LicenseTier::Licensed
            } else {
                // Keygen explicitly rejected (suspended/expired/revoked/overdue).
                LicenseTier::Trial
            }
        }
    }
}

/// Deactivate license + remove from keychain.
pub async fn deactivate() -> Result<()> {
    let (key, machine_id) = match load_keychain() {
        Some(v) => v,
        None => return Ok(()),
    };

    let client = keygen_client()?;

    if let Err(e) = deactivate_machine(&client, &key, &machine_id).await {
        eprintln!(
            "[anubis] warning: failed to deactivate machine on Keygen: {}",
            e
        );
    }

    delete_keychain();
    if let Ok(path) = meta_path() {
        let _ = fs::remove_file(path);
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Check-in a license with Keygen. Required weekly for subscription policies.
/// Returns Ok(()) if license is still valid, Err if suspended/expired/revoked.
pub async fn check_in() -> Result<()> {
    if !LICENSE_ENFORCEMENT_ENABLED {
        return Ok(()); // open-source build: no-op
    }
    let (key, _machine_id) = match load_keychain() {
        Some(v) => v,
        None => return Err(anyhow::anyhow!("no license in keychain")),
    };

    // Get license ID from last validation
    let license_id = get_license_id().ok_or_else(|| anyhow::anyhow!("no license_id cached"))?;

    let client = keygen_client()?;
    let url = format!(
        "{}/v1/accounts/{}/licenses/{}/actions/check-in",
        KEYGEN_API, KEYGEN_ACCOUNT, license_id
    );

    let resp = client
        .post(&url)
        .header("Authorization", format!("License {}", key))
        .header("Accept", "application/vnd.api+json")
        .header("Content-Type", "application/vnd.api+json")
        .body("{}")
        .send()
        .await?;

    let status = resp.status();
    let resp_text = resp.text().await?;
    let body: serde_json::Value = serde_json::from_str(&resp_text).unwrap_or(serde_json::json!({}));

    if !status.is_success() {
        let detail = body
            .pointer("/errors/0/detail")
            .and_then(|v| v.as_str())
            .unwrap_or("check-in failed");
        let code = body
            .pointer("/errors/0/code")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        return Err(anyhow::anyhow!("check-in failed ({}): {}", code, detail));
    }

    // Update last_validated timestamp
    let mut state = load_state();
    state.last_validated = chrono::Utc::now();
    let _ = save_meta(&state);

    tracing::info!("license check-in successful");
    Ok(())
}

/// Get the cached license ID from meta file.
fn get_license_id() -> Option<String> {
    load_state().license_id
}

fn dirs_home() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        Ok(PathBuf::from(home))
    } else {
        Err(anyhow::anyhow!("cannot determine home directory"))
    }
}
