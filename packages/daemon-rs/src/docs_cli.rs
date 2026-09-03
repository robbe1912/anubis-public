// docs_cli — input parsing helpers for the `docs add` CLI subcommand.
//
// Extracted into a lib module (instead of living in the dashboard binary) so
// the dispatch heuristics can be unit-tested without spawning the binary.
//
// The remote Worker (T13) serves npm packages only. `is_remote_eligible`
// routes npm-like inputs to the Worker path; everything else (URLs, paths,
// owner/repo) falls through to the existing `docs_fetcher::fetch_from_input`
// strategy chain.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Decide whether `input` should try the remote Worker first.
///
/// Remote Worker serves npm packages only (MVP scope). Heuristic rejects:
///   - URLs (`http://`, `https://`)
///   - Relative/absolute paths (`./`, `../`, `/`, `~`, `.`, `..`)
///   - Windows drive paths (`C:\...`, `C:/...`)
///   - `owner/repo` GitHub refs (contains `/` without leading `@`)
pub fn is_remote_eligible(input: &str) -> bool {
    if input.starts_with("http")
        || input.starts_with("./")
        || input.starts_with("../")
        || input.starts_with('/')
        || input.starts_with('~')
        || input == "."
        || input == ".."
    {
        return false;
    }

    // Windows drive absolute path: "C:\..." or "C:/..."
    let bytes = input.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return false;
    }

    // owner/repo: slash without leading @
    if input.contains('/') && !input.starts_with('@') {
        return false;
    }

    true
}

/// Split `lib@version` syntax into `(library, Option<version>)`.
///
/// Handles scoped packages carefully — the leading `@` is the scope marker,
/// not a version separator. The version separator is the *second* `@`.
///
/// Examples:
///   `react`            → (`react`, None)
///   `react@18.2.0`     → (`react`, Some(`18.2.0`))
///   `@scope/pkg`       → (`@scope/pkg`, None)
///   `@scope/pkg@2.0.0` → (`@scope/pkg`, Some(`2.0.0`))
///   `react@latest`     → (`react`, Some(`latest`))
pub fn parse_lib_at_version(input: &str) -> (String, Option<String>) {
    if input.starts_with('@') {
        // Skip the leading scope marker; find the next `@` (the version sep).
        if let Some(at_idx) = input[1..].find('@') {
            let real_idx = at_idx + 1;
            return (
                input[..real_idx].to_string(),
                Some(input[real_idx + 1..].to_string()),
            );
        }
        (input.to_string(), None)
    } else if let Some(at_idx) = input.find('@') {
        (
            input[..at_idx].to_string(),
            Some(input[at_idx + 1..].to_string()),
        )
    } else {
        (input.to_string(), None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_remote_eligible ───────────────────────────────────────────────

    #[test]
    fn is_remote_eligible_npm_unscoped() {
        assert!(is_remote_eligible("react"));
        assert!(is_remote_eligible("lodash-es"));
    }

    #[test]
    fn is_remote_eligible_npm_scoped() {
        assert!(is_remote_eligible("@scope/pkg"));
        assert!(is_remote_eligible("@rezi-ui/core"));
    }

    #[test]
    fn is_remote_eligible_npm_scoped_with_version() {
        assert!(is_remote_eligible("@scope/pkg@2.0.0"));
    }

    #[test]
    fn is_remote_eligible_npm_unscoped_with_version() {
        assert!(is_remote_eligible("react@18.2.0"));
        assert!(is_remote_eligible("react@latest"));
    }

    #[test]
    fn is_remote_eligible_github_owner_repo() {
        assert!(!is_remote_eligible("facebook/react"));
        assert!(!is_remote_eligible("godotengine/godot"));
    }

    #[test]
    fn is_remote_eligible_url() {
        assert!(!is_remote_eligible("https://example.com/docs"));
        assert!(!is_remote_eligible("http://example.com"));
    }

    #[test]
    fn is_remote_eligible_relative_path() {
        assert!(!is_remote_eligible("./docs"));
        assert!(!is_remote_eligible("../siblings/docs"));
        assert!(!is_remote_eligible("."));
        assert!(!is_remote_eligible(".."));
    }

    #[test]
    fn is_remote_eligible_absolute_unix_path() {
        assert!(!is_remote_eligible("/abs/path"));
        assert!(!is_remote_eligible("/home/user/docs"));
    }

    #[test]
    fn is_remote_eligible_tilde_path() {
        assert!(!is_remote_eligible("~/docs"));
    }

    #[test]
    fn is_remote_eligible_windows_drive_path() {
        assert!(!is_remote_eligible("C:\\Users\\foo\\docs"));
        assert!(!is_remote_eligible("D:/dev/docs"));
    }

    // ── parse_lib_at_version ─────────────────────────────────────────────

    #[test]
    fn parse_lib_unscoped_no_version() {
        assert_eq!(parse_lib_at_version("react"), ("react".to_string(), None));
    }

    #[test]
    fn parse_lib_unscoped_with_version() {
        assert_eq!(
            parse_lib_at_version("react@18.2.0"),
            ("react".to_string(), Some("18.2.0".to_string()))
        );
    }

    #[test]
    fn parse_lib_unscoped_with_latest_keyword() {
        assert_eq!(
            parse_lib_at_version("react@latest"),
            ("react".to_string(), Some("latest".to_string()))
        );
    }

    #[test]
    fn parse_lib_scoped_no_version() {
        assert_eq!(
            parse_lib_at_version("@scope/pkg"),
            ("@scope/pkg".to_string(), None)
        );
    }

    #[test]
    fn parse_lib_scoped_with_version() {
        assert_eq!(
            parse_lib_at_version("@scope/pkg@2.0.0"),
            ("@scope/pkg".to_string(), Some("2.0.0".to_string()))
        );
    }

    #[test]
    fn parse_lib_scoped_with_latest_keyword() {
        assert_eq!(
            parse_lib_at_version("@scope/pkg@latest"),
            ("@scope/pkg".to_string(), Some("latest".to_string()))
        );
    }

    #[test]
    fn parse_lib_trailing_at_yields_empty_version() {
        // Degenerate input — empty version string preserved as-is. The Worker
        // request will fail and the caller falls back to docs_fetcher.
        assert_eq!(
            parse_lib_at_version("react@"),
            ("react".to_string(), Some("".to_string()))
        );
    }

    #[test]
    fn parse_lib_leading_at_only_no_scope() {
        // Bare `@` is treated as a (degenerate) scoped name. Worker request
        // fails and caller falls back.
        assert_eq!(parse_lib_at_version("@"), ("@".to_string(), None));
    }
}
