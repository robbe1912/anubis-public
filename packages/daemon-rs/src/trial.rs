// Trial activation via signed RS256 JWT (issued by codeanubis.com Cloudflare Worker)
// Offline validation — no network required after activation.

use anyhow::Result;
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// Embedded public key — never fetched at runtime.
const TRIAL_PUBKEY_PEM: &str = include_str!("../resources/keys/trial-pubkey.pem");

const KEYCHAIN_SERVICE: &str = "anubis-ai";
const KEYCHAIN_TRIAL_ENTRY: &str = "trial-jwt";

/// JWT claims as signed by the Worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialClaims {
    pub iss: String,
    pub sub: String,       // user email
    pub tier: String,      // always "trial"
    pub max_machines: u32, // always 1
    pub iat: u64,          // issued at (unix seconds)
    pub exp: u64,          // expiry (unix seconds) — server-authoritative
    pub jti: String,       // trial UUID
    #[serde(default)]
    pub paddle_customer_id: Option<String>,
}

/// Runtime trial state after checking stored JWT.
#[derive(Debug, Clone)]
pub enum TrialState {
    /// No trial JWT stored — show activation prompt.
    NotActivated,
    /// Trial JWT valid and not expired.
    Active {
        email: String,
        exp: u64,
        days_remaining: i64,
    },
    /// Trial JWT signature valid but exp has passed.
    Expired { exp: u64 },
    /// Trial JWT present but signature invalid / tampered.
    Invalid,
}

/// Plaintext metadata for display (NOT for validation).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrialMeta {
    exp: u64,
    email: String,
    activated_at: i64,
    jti: String,
}

// ---------------------------------------------------------------------------
// JWT validation
// ---------------------------------------------------------------------------

/// Verify RS256 signature, issuer, expiry. Returns claims on success.
pub fn validate_trial_jwt(token: &str) -> Result<TrialClaims> {
    let key = DecodingKey::from_rsa_pem(TRIAL_PUBKEY_PEM.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["codeanubis"]);
    // jsonwebtoken checks exp by default; we also want iss.

    let data = decode::<TrialClaims>(token, &key, &validation)
        .map_err(|e| anyhow::anyhow!("JWT validation failed: {}", e))?;

    if data.claims.tier != "trial" {
        return Err(anyhow::anyhow!(
            "not a trial token (tier={})",
            data.claims.tier
        ));
    }

    Ok(data.claims)
}

// ---------------------------------------------------------------------------
// Encrypted storage (OS keychain)
// ---------------------------------------------------------------------------

fn store_trial_jwt(token: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TRIAL_ENTRY)?;
    entry.set_password(token)?;
    Ok(())
}

fn load_trial_jwt() -> Option<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TRIAL_ENTRY).ok()?;
    entry.get_password().ok()
}

fn delete_trial_jwt() {
    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TRIAL_ENTRY) {
        let _ = entry.delete_credential();
    }
}

// ---------------------------------------------------------------------------
// Plaintext metadata file
// ---------------------------------------------------------------------------

fn meta_path() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home.join(".anubis").join("trial.meta.json"))
}

fn save_meta(claims: &TrialClaims) -> Result<()> {
    let path = meta_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let meta = TrialMeta {
        exp: claims.exp,
        email: claims.sub.clone(),
        activated_at: Utc::now().timestamp(),
        jti: claims.jti.clone(),
    };
    let json = serde_json::to_string_pretty(&meta)?;
    fs::write(&path, json)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Activate a trial from a pasted JWT token.
/// Validates signature → stores encrypted in keychain → writes meta file.
pub fn activate_trial(token: &str) -> Result<TrialClaims> {
    let claims = validate_trial_jwt(token)?;

    let now = Utc::now().timestamp() as u64;
    if claims.exp <= now {
        return Err(anyhow::anyhow!(
            "trial token already expired (exp={})",
            claims.exp
        ));
    }

    store_trial_jwt(token)?;
    save_meta(&claims)?;

    Ok(claims)
}

/// Deactivate trial — remove from keychain + delete meta.
pub fn deactivate_trial() {
    delete_trial_jwt();
    if let Ok(path) = meta_path() {
        let _ = fs::remove_file(&path);
    }
}

/// Check trial state at startup. Offline — no network calls.
/// Open-source build: enforcement disabled — reports Active forever so all
/// trial gates pass without a token (machinery retained for reference).
pub fn check_trial() -> TrialState {
    if !crate::license::LICENSE_ENFORCEMENT_ENABLED {
        return TrialState::Active {
            email: "open-source".to_string(),
            exp: u64::MAX,
            days_remaining: i64::MAX,
        };
    }
    let token = match load_trial_jwt() {
        Some(t) => t,
        None => return TrialState::NotActivated,
    };

    match validate_trial_jwt(&token) {
        Ok(claims) => {
            let now = Utc::now().timestamp() as u64;
            if claims.exp <= now {
                TrialState::Expired { exp: claims.exp }
            } else {
                let exp_dt = chrono::DateTime::<chrono::Utc>::from_timestamp(claims.exp as i64, 0)
                    .unwrap_or_else(Utc::now);
                let days_remaining = (exp_dt - Utc::now()).num_days();
                TrialState::Active {
                    email: claims.sub,
                    exp: claims.exp,
                    days_remaining,
                }
            }
        }
        Err(_) => TrialState::Invalid,
    }
}

/// Does the user have an active (non-expired) trial?
pub fn has_active_trial() -> bool {
    if !crate::license::LICENSE_ENFORCEMENT_ENABLED {
        return true; // open-source build: trial gates pass without a token
    }
    matches!(check_trial(), TrialState::Active { .. })
}

/// Days remaining string for TUI display. Returns None if no active trial.
pub fn days_remaining_str() -> Option<String> {
    if !crate::license::LICENSE_ENFORCEMENT_ENABLED {
        return None; // open-source build: no trial UI
    }
    match check_trial() {
        TrialState::Active { days_remaining, .. } => {
            if days_remaining <= 0 {
                Some("expired".to_string())
            } else if days_remaining == 1 {
                Some("1 day left".to_string())
            } else {
                Some(format!("{} days left", days_remaining))
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(dir) = std::env::var("USERPROFILE") {
            return Ok(PathBuf::from(dir));
        }
    }
    if let Ok(dir) = std::env::var("HOME") {
        return Ok(PathBuf::from(dir));
    }
    Err(anyhow::anyhow!("cannot determine home directory"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_empty_token() {
        assert!(validate_trial_jwt("").is_err());
    }

    #[test]
    fn test_reject_garbage() {
        assert!(validate_trial_jwt("not.a.jwt").is_err());
    }

    #[test]
    fn test_reject_wrong_issuer() {
        // A real JWT signed by a different issuer would fail iss check.
        // We can't easily generate one without the private key,
        // but the validation struct has set_issuer(&["codeanubis"])
        // so any token with iss != codeanubis is rejected.
        assert!(validate_trial_jwt("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3cm9uZyJ9.sig").is_err());
    }

    #[test]
    fn test_public_key_loads() {
        // Verify the embedded PEM is valid RSA public key material.
        let result = DecodingKey::from_rsa_pem(TRIAL_PUBKEY_PEM.as_bytes());
        assert!(
            result.is_ok(),
            "embedded trial public key should parse as RSA"
        );
    }
}
