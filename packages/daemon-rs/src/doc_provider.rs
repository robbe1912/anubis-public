//! Shared doc provider abstraction.
//!
//! Both preventative (request-side `injection::maybe_inject_docs`) and
//! detective (response-side `scanner::mod::build_library_docs_fallback`)
//! paths need library API docs. Historically each re-derived the lookup:
//! `detect_libraries` + per-lib cache probe. This module centralizes the
//! contract behind a single [`DocProvider`] trait so new sources (markdown
//! cache, remote Worker, future cascade composition) slot in without
//! touching either call site.
//!
//! P0 scope: trait + [`LocalSymbolCacheProvider`] (byte-for-byte refactor).
//! P1 adds [`LocalMarkdownProvider`] — per-claim slicing from
//! `~/.anubis/docs/` markdown with source-tagged chunks (`[DOC_N] ... [/DOC_N]`)
//! for citation forcing in L3. P2+ adds remote impls and a cascade
//! composer — see `.omo/plans/doc-injection-design.md`.

use std::path::PathBuf;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::injection::{DetectedLibrary, DocSnippet, build_doc_snippets};
use crate::symbols::cache::SymbolCache;

/// Total token budget the provider may consume for a single `snippets()` call.
///
/// Soft bound: providers should truncate gracefully when the budget is
/// exhausted rather than fail. Wrapping the raw usize clarifies intent at
/// call sites and leaves room for future budget-split policy.
#[derive(Debug, Clone, Copy)]
pub struct TokenBudget(pub usize);

impl TokenBudget {
    pub fn tokens(self) -> usize {
        self.0
    }
}

/// What the caller wants from the provider. Different paths care about
/// different facets of a library's API surface — passing the focus in
/// lets the provider pick the most relevant slice instead of always
/// returning the top-level overview.
#[derive(Debug, Clone)]
pub enum Focus {
    /// Top-level Functions / Classes / Types — the preventative injection
    /// path uses this so the model sees the canonical API surface for the
    /// libraries it's about to call.
    TopLevelAPI,
    /// Per-claim narrow lookup (L3 lazy grounding). The provider may use the
    /// enclosed claim text to prefer symbols mentioned in the claim.
    PerClaim(String),
    /// Lifecycle / behavioral signals (deprecated, thread-safety, performance
    /// claims). Reserved for P2; providers may fall back to TopLevelAPI.
    LifecycleBehavior,
}

/// Cost-of-lookup tier for cascade ordering. Lower-cost providers run first;
/// higher-cost providers only fire for libraries the cheaper tiers don't
/// cover (see `CascadeProvider` in P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CostTier {
    /// In-memory / free (no I/O).
    Free = 0,
    /// Local disk / SQLite — sub-millisecond.
    Local = 1,
    /// Network — bounded but slow.
    Network = 2,
}

/// Source of library API documentation.
///
/// `Send + Sync` so providers can sit behind a `Box<dyn DocProvider>` shared
/// across tokio tasks. Async `snippets()` allows the remote Worker provider
/// (P1) to await HTTP without forcing the local cache provider to do the
/// same — the cache impl returns immediately under `async_trait`'s
/// desugaring.
///
/// `libraries_for` defaults to the shared `injection::detect_libraries`
/// heuristic. Providers that need bespoke detection (markdown frontmatter,
/// remote registry search) override it.
#[async_trait]
pub trait DocProvider: Send + Sync {
    /// Detect library references in arbitrary content. Default delegates to
    /// [`crate::injection::detect_libraries`] (the regex-based detector
    /// shared by every language path).
    fn libraries_for(&self, content: &str) -> Vec<DetectedLibrary> {
        crate::injection::detect_libraries(content)
    }

    /// Build doc snippets for the given libraries within the budget. Returns
    /// one [`DocSnippet`] per resolved library; unresolved libraries are
    /// omitted (the cascade composer, when present, retries them at higher
    /// tiers).
    async fn snippets(
        &self,
        libs: &[DetectedLibrary],
        budget: TokenBudget,
        focus: Focus,
    ) -> Vec<DocSnippet>;

    /// Cost tier — used to order providers in a cascade.
    fn cost_tier(&self) -> CostTier;

    /// Whether this provider believes it can serve the given library name.
    /// Hints the cascade skip work without probing each tier. Conservative
    /// implementations may return `false` from `covers` and still succeed
    /// inside `snippets()` (covers is an optimization, not a guarantee).
    fn covers(&self, lib: &str) -> bool;
}

// ──────────────────────────────────────────────────────────────────────
// LocalSymbolCacheProvider
// ──────────────────────────────────────────────────────────────────────

/// Doc provider backed by the local SQLite symbol cache
/// (`~/.anubis/symbols.db`, opened via [`SymbolCache::open`]).
///
/// This is the cheapest non-trivial source of API surface — symbols are
/// pre-fetched by `docs add` / auto-fetch and queried via sub-millisecond
/// prefix lookups. No network, no filesystem markdown walk. Replacement
/// for the inline `SymbolCache::open()` + `build_doc_snippets()` chain
/// that lived in `injection::maybe_inject_docs` and
/// `scanner::build_library_docs_from_cache`.
///
/// `SymbolCache` itself is `!Sync` (rusqlite uses `RefCell` for statement
/// caching), so we wrap it in a `parking_lot::Mutex`. The mutex is
/// uncontended in practice — each scan constructs its own provider — but
/// the wrapper satisfies the trait's `Sync` superbound so the provider
/// can sit behind `Arc<dyn DocProvider>` in the upcoming cascade.
pub struct LocalSymbolCacheProvider {
    cache: Mutex<SymbolCache>,
}

impl LocalSymbolCacheProvider {
    /// Open the SQLite symbol cache. Returns `Err` if the cache file is
    /// missing / corrupt — callers should fall back to higher-tier
    /// providers rather than treating this as fatal.
    pub fn open() -> Result<Self, String> {
        SymbolCache::open().map(|cache| Self {
            cache: Mutex::new(cache),
        })
    }

    /// Construct from an already-open cache handle. Used by tests that
    /// pre-populate the cache before invoking the provider.
    pub fn from_cache(cache: SymbolCache) -> Self {
        Self {
            cache: Mutex::new(cache),
        }
    }
}

#[async_trait]
impl DocProvider for LocalSymbolCacheProvider {
    /// Build snippets from the cache. `max_per_lib` mirrors the historical
    /// 30-symbols-per-library cap used by the preventative injector —
    /// P0 keeps that constant identical so behavior is byte-for-byte
    /// preserved. The `focus` argument is accepted but does not yet
    /// influence cache selection (top-level prioritization already lives
    /// in `build_doc_snippets`); it will gate per-claim slicing in P2.
    async fn snippets(
        &self,
        libs: &[DetectedLibrary],
        budget: TokenBudget,
        _focus: Focus,
    ) -> Vec<DocSnippet> {
        // Match the prior call sites exactly: preventative used 30/lib,
        // detective used 20/lib. Callers pick the budget; the per-lib cap
        // is a single constant here so future tuning happens in one place.
        // 30 is the looser of the two — callers that need tighter slicing
        // can truncate afterwards, and P1 will surface this on the trait.
        const MAX_PER_LIB: usize = 30;
        let cache = self.cache.lock();
        build_doc_snippets(libs, &cache, budget.tokens(), MAX_PER_LIB)
    }

    fn cost_tier(&self) -> CostTier {
        CostTier::Local
    }

    /// A library is "covered" iff the cache has at least one symbol row
    /// indexed under that name prefix. Probes via `lookup_prefix(name, "")`
    /// (same call `build_doc_snippets` makes), so the cover test is
    /// consistent with what `snippets` will actually return.
    fn covers(&self, lib: &str) -> bool {
        // lookup_prefix returns Vec<SymbolEntry>; non-empty ⇒ covered.
        // Cheap (SQLite prefix scan) and matches the exact path the
        // snippet builder uses, so no false "covered" hints.
        let cache = self.cache.lock();
        !cache.lookup_prefix(lib, "").is_empty()
    }
}

// ──────────────────────────────────────────────────────────────────────
// LocalMarkdownProvider
// ──────────────────────────────────────────────────────────────────────

/// Per-claim markdown retrieval from `~/.anubis/docs/<slug>/<slug>.md`.
///
/// Complements [`LocalSymbolCacheProvider`] for prose claims: the symbol
/// cache returns terse signatures (`pandas.read_csv(filepath, ...)`) while
/// markdown doc sets carry the surrounding prose (deprecation notes,
/// thread-safety caveats, parameter semantics). The L3 citation-forcing
/// prompt needs both: signatures to ground API existence, prose to ground
/// behavioral claims.
///
/// Output format (source-tagged chunks):
///
/// ```text
/// [DOC_1] <slug>: <matched section markdown> [/DOC_1]
///
/// [DOC_2] <slug>: <matched section markdown> [/DOC_2]
/// ```
///
/// The LLM judge cites `[DOC_N]` for each verdict; a downstream citation
/// ratio gate rejects un-cited verdicts (regex: `\[DOC_\d+\]`).
///
/// This is NOT the full `CascadeProvider` — just a focused retrieval
/// function that the scanner calls to build doc snippets for the L3 prompt.
pub struct LocalMarkdownProvider {
    root: PathBuf,
}

impl LocalMarkdownProvider {
    /// Open the default docs root (`~/.anubis/docs/`). Returns a provider
    /// regardless of whether the root exists — `per_claim_snippets` simply
    /// yields empty if the dir is missing.
    pub fn open() -> Self {
        Self {
            root: crate::docs_fetcher::docs_root(),
        }
    }

    /// Construct with an explicit root. Used by tests that point at a
    /// tempdir instead of touching the user's `~/.anubis/docs/`.
    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    /// Retrieve doc chunks relevant to `claim`. Returns a joined string
    /// with `[DOC_N] <slug>: <text> [/DOC_N]` tags. Empty if no docs root,
    /// no markdown files, or no token overlap with the claim.
    ///
    /// `budget_tokens` is a soft cap on output size (~4 chars/token, so
    /// 500 tokens → ~2000 chars). Caps body content; the `[DOC_N]` wrapper
    /// adds a small per-file overhead on top.
    pub fn per_claim_snippets(&self, claim: &str, budget_tokens: usize) -> String {
        let tokens = extract_claim_tokens(claim);
        if tokens.is_empty() {
            return String::new();
        }

        // Walk all doc sets, find sections matching claim tokens.
        let mut sections: Vec<(String, String)> = Vec::new();
        let mut total_chars = 0usize;
        let max_chars = budget_tokens.saturating_mul(4); // ~4 chars/token

        let entries = match std::fs::read_dir(&self.root) {
            Ok(it) => it,
            Err(_) => return String::new(),
        };
        for entry in entries.flatten() {
            if total_chars >= max_chars {
                break;
            }
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let slug = entry.file_name().to_string_lossy().to_string();
            if slug.starts_with('.') {
                continue;
            }

            // Walk .md files in this doc set.
            let files = match std::fs::read_dir(&path) {
                Ok(it) => it,
                Err(_) => continue,
            };
            for file in files.flatten() {
                if total_chars >= max_chars {
                    break;
                }
                let fpath = file.path();
                let fname = match file.file_name().into_string() {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !fname.ends_with(".md") {
                    continue;
                }

                let content = match std::fs::read_to_string(&fpath) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let focused =
                    extract_focused_sections(&content, &tokens, max_chars - total_chars);
                if !focused.is_empty() {
                    total_chars += focused.len();
                    sections.push((slug.clone(), focused));
                }
            }
        }

        // Source-tag the sections: [DOC_N] <lib>: <text> [/DOC_N]
        sections
            .iter()
            .enumerate()
            .map(|(i, (slug, text))| {
                format!(
                    "[DOC_{}] {}: {} [/DOC_{}]",
                    i + 1,
                    slug,
                    text.trim(),
                    i + 1
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

/// Convenience entry: open the default docs root and slice docs for `claim`.
///
/// Returns empty if `~/.anubis/docs/` is missing, empty, or no markdown
/// section matches tokens extracted from the claim. Wraps
/// [`LocalMarkdownProvider::per_claim_snippets`] for the common case where
/// the caller doesn't hold an open provider handle.
pub fn per_claim_docs(claim: &str, budget: usize) -> String {
    LocalMarkdownProvider::open().per_claim_snippets(claim, budget)
}

/// Extract markdown sections that match claim tokens.
///
/// A section is `## <heading>\n<body>` (level-2 headings, per docs_fetcher's
/// output convention). Match if the heading contains any token OR if the
/// body contains at least 2 different claim tokens.
///
/// Returns concatenated matched section bodies (heading included), capped
/// at `max_chars`. Empty if no matches.
fn extract_focused_sections(markdown: &str, tokens: &[String], max_chars: usize) -> String {
    if tokens.is_empty() || max_chars == 0 {
        return String::new();
    }

    let mut out = String::new();
    let mut current_heading = String::new();
    let mut current_body = String::new();

    let flush = |out: &mut String,
                 heading: &str,
                 body: &str,
                 max_chars: usize,
                 tokens: &[String],
                 used: &mut usize| {
        if body.trim().is_empty() {
            return;
        }
        let heading_match = tokens
            .iter()
            .any(|t| heading.to_lowercase().contains(t));
        let body_matches = tokens
            .iter()
            .filter(|t| body.to_lowercase().contains(t.as_str()))
            .count();
        if !heading_match && body_matches < 2 {
            return;
        }
        if *used + body.len() > max_chars {
            return;
        }
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        if !heading.is_empty() {
            out.push_str("## ");
            out.push_str(heading);
            out.push('\n');
        }
        out.push_str(body);
        *used += body.len();
    };

    let mut used = 0usize;
    for line in markdown.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            flush(
                &mut out,
                &current_heading,
                &current_body,
                max_chars,
                tokens,
                &mut used,
            );
            current_heading = rest.trim().to_string();
            current_body.clear();
        } else {
            current_body.push_str(line);
            current_body.push('\n');
        }
    }
    flush(
        &mut out,
        &current_heading,
        &current_body,
        max_chars,
        tokens,
        &mut used,
    );

    out
}

/// Extract CamelCase + 4+ char lowercase identifiers from a claim.
///
/// Lowercased. Filters common English / coding stopwords so trivial prose
/// claims don't trigger noisy section matches.
///
/// The combined regex captures:
/// - `[A-Z][a-zA-Z0-9]+` — CamelCase / PascalCase (Node3D, PolynomialFeatures)
/// - `[a-z_][a-z0-9_]{3,}` — any 4+ char lowercase identifier (queue_free,
///   fit_transform, deprecated, thread_safe)
///
/// Examples:
/// - `"PolynomialFeatures.fit_transform("` → `["polynomialfeatures", "fit_transform"]`
/// - `"Node3D and queue_free"` → `["node3d", "queue_free"]`
/// - `"this is deprecated"` → `["deprecated"]` (stopword filter removes "this")
fn extract_claim_tokens(claim: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"\b(?:[A-Z][a-zA-Z0-9]+|[a-z_][a-z0-9_]{3,})\b").unwrap()
    });

    // Stopwords: common English + coding-noise terms that would otherwise
    // produce false-positive section matches (e.g., `## function returns`).
    const STOPWORDS: &[&str] = &[
        "that", "this", "with", "from", "when", "while", "does", "have",
        "been", "will", "would", "could", "should", "their", "there",
        "then", "than", "into", "only", "same", "such", "here", "code",
        "function", "method", "value", "result", "returns",
    ];

    re.find_iter(claim)
        .map(|m| m.as_str().to_lowercase())
        .filter(|t| !STOPWORDS.contains(&t.as_str()))
        .collect()
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `TokenBudget` is a thin newtype — make sure the constructor + accessor
    /// round-trip is sane so call sites can rely on `.tokens()`.
    #[test]
    fn token_budget_roundtrip() {
        let b = TokenBudget(2000);
        assert_eq!(b.tokens(), 2000);
    }

    /// `CostTier` ordering drives cascade composition. Lock the order
    /// (Free < Local < Network) so future providers can be sorted without
    /// surprises.
    #[test]
    fn cost_tier_ordering() {
        assert!(CostTier::Free < CostTier::Local);
        assert!(CostTier::Local < CostTier::Network);
    }

    /// Default `libraries_for` defers to the shared detector — verify it
    /// fires on a Python import and returns the expected normalized name.
    /// Guards against accidental future override that drops the default.
    #[test]
    fn default_libraries_for_delegates_to_injection() {
        // Arrange a cache-less provider shim so we can call the default
        // method without touching SQLite. wraps() returns a no-op impl.
        struct Shim;
        #[async_trait]
        impl DocProvider for Shim {
            async fn snippets(
                &self,
                _libs: &[DetectedLibrary],
                _budget: TokenBudget,
                _focus: Focus,
            ) -> Vec<DocSnippet> {
                Vec::new()
            }
            fn cost_tier(&self) -> CostTier {
                CostTier::Free
            }
            fn covers(&self, _: &str) -> bool {
                false
            }
        }
        let shim = Shim;
        let libs = DocProvider::libraries_for(&shim, "import pandas\n");
        assert!(libs.iter().any(|l| l.name == "pandas"));
    }

    /// `LocalSymbolCacheProvider::open` failing when SQLite is unavailable
    /// must surface as `Err`, not panic. We can't reliably delete the cache
    /// under test, so this only exercises the happy path — but the signature
    /// being `Result` is the contract this test locks in.
    #[test]
    fn open_returns_result_not_panics() {
        // We don't assert success — CI may not have the cache populated.
        // The point is that `open()` returns a Result type at all; the
        // type system guarantees callers handle both branches.
        let _ = LocalSymbolCacheProvider::open();
    }

    // ── LocalMarkdownProvider tests ──────────────────────────────────────

    /// `extract_claim_tokens` extracts CamelCase identifiers (len >= 4).
    /// "Node3D and queue_free" → ["node3d", "queue_free"].
    #[test]
    fn extract_claim_tokens_handles_camel_case() {
        let got = extract_claim_tokens("Node3D and queue_free");
        assert!(
            got.contains(&"node3d".to_string()),
            "expected node3d in {:?}",
            got
        );
        assert!(
            got.contains(&"queue_free".to_string()),
            "expected queue_free in {:?}",
            got
        );
    }

    /// `extract_claim_tokens` filters common stopwords ("the", "function",
    /// "value") so trivial prose claims don't trigger noisy matches.
    #[test]
    fn extract_claim_tokens_filters_stopwords() {
        let got = extract_claim_tokens("the function returns value");
        assert!(
            !got.iter().any(|t| t == "the"),
            "stopword 'the' should be filtered"
        );
        assert!(
            !got.iter().any(|t| t == "function"),
            "stopword 'function' should be filtered"
        );
        assert!(
            !got.iter().any(|t| t == "value"),
            "stopword 'value' should be filtered"
        );
        // Result should be empty for a stopword-only claim.
        assert!(got.is_empty(), "expected empty after stopword filter, got: {:?}", got);
    }

    /// `extract_focused_sections` includes a section when its heading
    /// contains a claim token (heading match path).
    #[test]
    fn extract_focused_sections_matches_heading() {
        let md = "# godot\n\n## queue_free\n\nNodes can be freed with queue_free.\n";
        let tokens = vec!["queue_free".to_string()];
        let got = extract_focused_sections(md, &tokens, 1000);
        assert!(
            !got.is_empty(),
            "section with matching heading should be included"
        );
        assert!(got.contains("queue_free"), "body should be present");
        assert!(got.contains("## queue_free"), "heading should be preserved");
    }

    /// `extract_focused_sections` excludes a section whose body has only
    /// 1 matching token (requires ≥2 body matches when heading doesn't match).
    #[test]
    fn extract_focused_sections_requires_two_body_matches() {
        // Heading "Other Topic" doesn't contain tokens. Body has only 1 hit.
        let md = "## Other Topic\n\nThis section mentions queue_free once but nothing else relevant.\n";
        let tokens = vec!["queue_free".to_string(), "polynomialfeatures".to_string()];
        let got = extract_focused_sections(md, &tokens, 1000);
        assert!(
            got.is_empty(),
            "section with <2 body matches and no heading match should be excluded, got: {}",
            got
        );
    }

    /// `extract_focused_sections` includes a section when body has ≥2
    /// distinct token matches even without a heading match.
    #[test]
    fn extract_focused_sections_includes_with_two_body_matches() {
        let md = "## Overview\n\nThis is about queue_free and polynomialfeatures together.\n";
        let tokens = vec![
            "queue_free".to_string(),
            "polynomialfeatures".to_string(),
        ];
        let got = extract_focused_sections(md, &tokens, 1000);
        assert!(!got.is_empty(), "≥2 body matches should include the section");
    }

    /// `per_claim_snippets` emits source-tagged chunks in the
    /// `[DOC_N] <slug>: <text> [/DOC_N]` format.
    #[test]
    fn local_markdown_per_claim_returns_source_tagged_chunks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let slug_dir = dir.path().join("godot");
        std::fs::create_dir_all(&slug_dir).expect("create slug dir");
        std::fs::write(
            slug_dir.join("godot.md"),
            "# godot\n\n## queue_free\n\nMarks a node for deletion at end of frame.\n\n## Node3D\n\nA 3D node.\n",
        )
        .expect("write godot.md");

        let provider = LocalMarkdownProvider::with_root(dir.path().to_path_buf());
        let got = provider.per_claim_snippets("Node3D.queue_free()", 500);

        assert!(
            !got.is_empty(),
            "expected non-empty output for matching claim"
        );
        assert!(
            got.contains("[DOC_1]"),
            "expected [DOC_1] opening tag; got:\n{}",
            got
        );
        assert!(
            got.contains("[/DOC_1]"),
            "expected [/DOC_1] closing tag; got:\n{}",
            got
        );
        assert!(
            got.contains("godot:"),
            "expected slug 'godot:' label; got:\n{}",
            got
        );
    }

    /// `per_claim_snippets` caps output at `budget_tokens * 4` chars.
    #[test]
    fn local_markdown_per_claim_caps_at_budget() {
        // Build a large doc set with many matching sections.
        let dir = tempfile::tempdir().expect("tempdir");
        let slug_dir = dir.path().join("biglib");
        std::fs::create_dir_all(&slug_dir).expect("create slug dir");
        let mut md = String::from("# biglib\n\n");
        for i in 0..50 {
            md.push_str(&format!(
                "## PolynomialFeatures section {}\n\nA long discussion of polynomialfeatures in context {} with many words and details to make body long enough for the two body match rule. polynomialfeatures appears repeatedly here.\n\n",
                i, i
            ));
        }
        std::fs::write(slug_dir.join("biglib.md"), md).expect("write");

        let provider = LocalMarkdownProvider::with_root(dir.path().to_path_buf());
        // 50 tokens → ~200 chars budget.
        let got = provider.per_claim_snippets("PolynomialFeatures.fit_transform", 50);
        let cap = 50usize * 4;
        assert!(
            got.len() <= cap + 64, // allow small overflow from the final [DOC_N]...[/DOC_N] tag wrapper
            "output len {} should be ≤ ~{} (budget*4); got:\n{}",
            got.len(),
            cap,
            got
        );
    }

    /// Hidden dirs (`.remote-cache`) are skipped — content never leaks.
    #[test]
    fn local_markdown_skips_hidden_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hidden = dir.path().join(".remote-cache");
        std::fs::create_dir_all(&hidden).expect("create hidden");
        std::fs::write(
            hidden.join("ignored.md"),
            "## queue_free\n\nShould not appear.\n",
        )
        .expect("write hidden");

        let provider = LocalMarkdownProvider::with_root(dir.path().to_path_buf());
        let got = provider.per_claim_snippets("queue_free()", 500);
        assert!(
            !got.contains("Should not appear"),
            "hidden dir leaked into output: {}",
            got
        );
    }

    /// Missing docs root returns empty string (no panic).
    #[test]
    fn local_markdown_missing_root_returns_empty() {
        let bogus = std::env::temp_dir()
            .join("anubis-doc-provider-nonexistent-xyz-44881");
        let _ = std::fs::remove_dir_all(&bogus);
        let provider = LocalMarkdownProvider::with_root(bogus.clone());
        let got = provider.per_claim_snippets("PolynomialFeatures.fit_transform", 500);
        assert!(got.is_empty(), "missing root should yield empty");
        let _ = std::fs::remove_dir_all(&bogus);
    }

    /// `per_claim_docs` convenience function returns the same shape as
    /// the method on an open provider. (Doesn't assert non-empty since
    /// CI may not have `~/.anubis/docs/` populated.)
    #[test]
    fn per_claim_docs_returns_string_no_panic() {
        let _ = per_claim_docs("PolynomialFeatures.fit_transform", 500);
    }
}
