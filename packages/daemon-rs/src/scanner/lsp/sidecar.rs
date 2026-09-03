//! Sidecar binary path resolution placeholder (COLD-001 stub, COLD-007..009 implementation).
//!
//! Per master plan:
//! - COLD-007 [deps: 002]: sidecar bundle rust-analyzer + clangd. 50 LOC.
//! - COLD-008 [deps: 007]: binary path resolution per platform. 40 LOC.
//! - COLD-009 [deps: 008]: SHA256 verification. 40 LOC.
//!
//! Sidecars bundle LSP binaries (rust-analyzer 16MB, clangd 22.1.6
//! Win 26.9MB / macOS 93.6MB / Linux 109.5MB) for the Offline tier
//! ($150). PATH-probe (Online tiers) uses what the user already has.
//!
//! This stub captures the interface; actual resolution lands in COLD-008.

use std::path::PathBuf;

/// Resolve the binary path for a given language LSP, preferring sidecar
/// bundle over PATH probe when the sidecar exists.
///
/// Returns `None` in this stub — COLD-008 will populate. Callers fall
/// back to `cmd` from `LspSpawnConfig` (PATH probe) which is the
/// existing behavior.
pub fn resolve_binary(_language: crate::scanner::language::Language) -> Option<PathBuf> {
    // COLD-008: probe `<install_dir>/sidecars/{binary}-{platform}.{ext}`
    // → SHA256 verify → return absolute path. None → caller uses cmd
    // from LspSpawnConfig (PATH probe).
    None
}

/// Per-platform binary name suffix (COLD-008 will populate).
///
/// - Windows: `.exe`
/// - macOS: `-darwin-{arch}` (universal2 for clangd)
/// - Linux: `-linux-{arch}`
pub fn platform_suffix() -> &'static str {
    #[cfg(target_os = "windows")]
    { ".exe" }
    #[cfg(target_os = "macos")]
    { "-darwin" }
    #[cfg(target_os = "linux")]
    { "-linux" }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    { "" }
}

/// Verify SHA256 of a sidecar binary matches the pinned hash. COLD-009.
///
/// Returns `false` in this stub — no sidecars bundled yet, so nothing
/// to verify. When COLD-007 lands bundled binaries, this becomes a
/// hard gate (binary mismatch → reject to prevent supply-chain attack).
pub fn verify_sha256(_binary: &std::path::Path, _expected: &str) -> bool {
    // COLD-009: compute sha256(binary), constant-time compare to expected.
    false
}
