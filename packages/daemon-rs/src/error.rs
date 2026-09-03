//! Typed error enum for anubis daemon.
//!
//! Replaces ad-hoc `Result<T, String>` returns with structured errors that:
//!   - Carry context (HTTP status, raw response preview, source error chain)
//!   - Are pattern-matchable for retry logic (see [`AnubisError::is_retryable`])
//!   - Render nicely via `Display` (thiserror-derived)
//!   - Auto-convert from common error types via `#[from]` (no `.map_err(|e| e.to_string())`)
//!
//! Scope (initial): validator HTTP path in `scanner::validate_logic`. Other
//! modules still use `String` errors — refactor incrementally as files are
//! touched. Don't bulk-rewrite working code.

use thiserror::Error;

/// Top-level anubis error.
///
/// Variants follow the "where it happened" not "what kind" principle —
/// callers usually care about whether it was the validator, the cache, the
/// fetcher, etc. The underlying error chain carries the "what kind".
#[derive(Debug, Error)]
pub enum AnubisError {
    /// Validator HTTP call returned non-2xx.
    /// `status` is the HTTP code, `body` is the (truncated) response body.
    #[error("validator HTTP {status}: {body}")]
    ValidatorHttp {
        status: u16,
        body: String,
    },

    /// Validator network failure (connect refused, DNS, timeout, TLS, etc.).
    /// Wraps the underlying reqwest error so callers can introspect via
    /// `is_connect()` / `is_timeout()` etc.
    #[error("validator network: {0}")]
    ValidatorNetwork(#[from] reqwest::Error),

    /// Validator response couldn't be parsed as JSON or didn't contain
    /// expected fields. `raw_preview` is the first ~500 chars for debugging.
    #[error("validator parse failure: {raw_preview}")]
    ValidatorParse {
        raw_preview: String,
    },

    /// Symbol cache SQLite error (open, query, insert).
    #[error("cache SQLite: {0}")]
    CacheSqlite(#[from] rusqlite::Error),

    /// Symbol cache file I/O (creating ~/.anubis/symbols/, reading cache file).
    #[error("cache I/O: {0}")]
    CacheIo(#[from] std::io::Error),

    /// Configuration problem (missing API key, malformed URL, etc.).
    #[error("config: {0}")]
    Config(String),

    /// License / Keygen API error.
    #[error("license: {0}")]
    License(String),

    /// Symbol fetcher HTTP failure (docs.rs, unpkg, godot downloads).
    #[error("fetch: {0}")]
    Fetch(String),
}

impl AnubisError {
    /// Whether retrying the operation could succeed.
    ///
    /// Used by retry loops (e.g. `validate_logic`'s 2-attempt backoff) to
    /// decide whether to sleep + retry or fail fast. Non-retryable errors
    /// won't succeed on a second attempt (e.g., 401 auth, malformed URL).
    pub fn is_retryable(&self) -> bool {
        match self {
            // Network errors: retry only if connect/timeout/request-tier.
            // Body-decode errors are not retryable (same body will fail again).
            Self::ValidatorNetwork(e) => e.is_connect() || e.is_timeout() || e.is_request(),
            // HTTP: retry on 429 (rate limit) + 5xx (server error).
            // 4xx (except 429) are not retryable (auth, malformed request).
            Self::ValidatorHttp { status, .. } => *status == 429 || *status >= 500,
            // Parse failures are never retryable — same response parses the same way.
            Self::ValidatorParse { .. } => false,
            // All other variants are not in retry paths — default false.
            _ => false,
        }
    }

    /// Short category string for structured logging ("connect", "timeout",
    /// "http_429", "parse", etc.). Useful for metrics + log filters.
    pub fn category(&self) -> &'static str {
        match self {
            Self::ValidatorNetwork(e) if e.is_connect() => "connect",
            Self::ValidatorNetwork(e) if e.is_timeout() => "timeout",
            Self::ValidatorNetwork(e) if e.is_request() => "request",
            Self::ValidatorNetwork(_) => "network_other",
            Self::ValidatorHttp { status, .. } if *status == 429 => "http_429",
            Self::ValidatorHttp { status, .. } if *status >= 500 => "http_5xx",
            Self::ValidatorHttp { .. } => "http_4xx",
            Self::ValidatorParse { .. } => "parse",
            Self::CacheSqlite(_) => "cache_sqlite",
            Self::CacheIo(_) => "cache_io",
            Self::Config(_) => "config",
            Self::License(_) => "license",
            Self::Fetch(_) => "fetch",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn parse_error_not_retryable() {
        let e = AnubisError::ValidatorParse {
            raw_preview: "garbage".to_string(),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn http_429_retryable() {
        let e = AnubisError::ValidatorHttp {
            status: 429,
            body: "rate limited".to_string(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn http_500_retryable() {
        let e = AnubisError::ValidatorHttp {
            status: 503,
            body: "upstream down".to_string(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn http_401_not_retryable() {
        let e = AnubisError::ValidatorHttp {
            status: 401,
            body: "bad key".to_string(),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn http_400_not_retryable() {
        let e = AnubisError::ValidatorHttp {
            status: 400,
            body: "malformed".to_string(),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn config_error_not_retryable() {
        let e = AnubisError::Config("missing key".to_string());
        assert!(!e.is_retryable());
    }

    // ── category ─────────────────────────────────────────────────────

    #[test]
    fn category_http_429() {
        let e = AnubisError::ValidatorHttp {
            status: 429,
            body: "".to_string(),
        };
        assert_eq!(e.category(), "http_429");
    }

    #[test]
    fn category_http_5xx() {
        let e = AnubisError::ValidatorHttp {
            status: 500,
            body: "".to_string(),
        };
        assert_eq!(e.category(), "http_5xx");
    }

    #[test]
    fn category_http_4xx() {
        let e = AnubisError::ValidatorHttp {
            status: 404,
            body: "".to_string(),
        };
        assert_eq!(e.category(), "http_4xx");
    }

    #[test]
    fn category_parse() {
        let e = AnubisError::ValidatorParse {
            raw_preview: "".to_string(),
        };
        assert_eq!(e.category(), "parse");
    }

    #[test]
    fn category_cache() {
        let e = AnubisError::Config("x".to_string());
        assert_eq!(e.category(), "config");
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn display_validator_http_includes_status() {
        let e = AnubisError::ValidatorHttp {
            status: 503,
            body: "down".to_string(),
        };
        let s = format!("{}", e);
        assert!(s.contains("503"), "Display must include status: {}", s);
        assert!(s.contains("down"), "Display must include body: {}", s);
    }

    #[test]
    fn display_validator_parse_includes_preview() {
        let e = AnubisError::ValidatorParse {
            raw_preview: "unexpected token at byte 42".to_string(),
        };
        let s = format!("{}", e);
        assert!(s.contains("unexpected token"));
    }
}
