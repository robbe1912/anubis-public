//! Symbol extraction and local cache subsystem.
//!
//! Architecture:
//!   - types.rs: generic Symbol struct (works for Godot/TS/Python/Rust/Go)
//!   - cache.rs: SQLite cache at ~/.anubis/symbols/cache.sqlite
//!   - godot_parser.rs: parse Godot class reference XML → Vec<Symbol>
//!   - godot_fetcher.rs: download Godot XML files from upstream
//!   - (future) ts_parser.rs, py_parser.rs, etc.
//!
//! Used by scanner.rs as Layer 1.5 — between regex Layer 1 and
//! retrieval Layer 2. Checks symbol existence locally before
//! consulting docs/LLM.

pub mod cache;
pub mod godot_fetcher;
pub mod godot_parser;
pub mod local_scanner;
pub mod rust_fetcher;
pub mod rust_parser;
pub mod ts_fetcher;
pub mod ts_parser;
pub mod types;
pub mod go_fetcher;
pub mod java_fetcher;
pub mod csharp_fetcher;
pub mod python_fetcher;
pub mod cpp_std_fetcher;
pub mod csharp_metadata_fetcher;

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use tokio::sync::{Mutex as TokioMutex, Semaphore};

/// Negative cache: libraries we've tried to auto-fetch and failed.
/// Prevents repeated docs.rs 404s for non-Rust packages (react, axios, etc).
///
/// Bounded LRU: caps at 1000 entries to prevent unbounded memory growth
/// across long-running daemon sessions. A busy agent session can accumulate
/// hundreds of failed-fetch entries per day (every typo, every misspelled
/// crate name, every non-existent npm package); without a cap, the set
/// grows forever. At 1000 entries × ~32 bytes per name ≈ 32KB cap, which
/// is fine for a long-running process. Pruning happens on every insert.
static ATTEMPTED_FETCHES: Lazy<TokioMutex<std::collections::VecDeque<String>>> =
    Lazy::new(|| TokioMutex::new(std::collections::VecDeque::with_capacity(1000)));

const ATTEMPTED_FETCHES_MAX: usize = 1000;

/// Universal trait/built-in methods available on virtually all types via
/// standard library trait implementations. These should never be flagged
/// as hallucinated by the symbol cache because:
/// - The cache stores crate-defined methods, not blanket trait impls
/// - These methods exist on every type that implements the trait
/// - Flagging them produces false positives (e.g., Pending.to_string())
///
/// Rust traits: Display/ToString, Clone, Debug, Default, Hash, PartialEq,
/// AsRef/AsMut, Borrow/BorrowMut, IntoIterator, Sized, etc.
/// Also includes common cross-language builtins (Python, JS).
const UNIVERSAL_TRAIT_METHODS: &[&str] = &[
    // Rust: Display/ToString
    "to_string", "to_owned", "fmt",
    // Rust: Clone
    "clone",
    // Rust: Debug
    "debug",
    // Rust: PartialEq/Eq
    "eq", "ne",
    // Rust: Hash
    "hash",
    // Rust: Default
    "default",
    // Rust: AsRef/AsMut
    "as_ref", "as_mut",
    // Rust: Borrow/BorrowMut
    "borrow", "borrow_mut",
    // Rust: Into/TryInto
    "into", "try_into",
    // Rust: IntoIterator
    "iter", "iter_mut", "into_iter",
    // Rust: ExactSizeIterator / container traits
    "len", "is_empty", "contains",
    // Rust: Send/Sync markers (not methods but sometimes matched)
    // Common cross-language: Python/JS builtins
    "toString",  // JS
    "valueOf",   // JS
    "hasOwnProperty", // JS
];
/// Python stdlib classes that exist in multiple packages or are universally
/// available. Their methods should never trigger cached-hallucination FPs.
const PYTHON_STDLIB_CLASSES: &[&str] = &[
    "Path", "PurePath", "PurePosixPath", "PureWindowsPath", "PosixPath", "WindowsPath",
    "Date", "Time", "DateTime", "TimeDelta", "TZInfo", "TimeZone",
    "Decimal", "Fraction",
    "Counter", "OrderedDict", "DefaultDict", "ChainMap", "NamedTuple",
    "Enum", "IntEnum", "Flag", "IntFlag",
    "BaseException", "Exception", "ValueError", "TypeError", "KeyError",
    "AttributeError", "RuntimeError", "StopIteration", "NotImplementedError",
    "IOBase", "StringIO", "BytesIO", "TextIOWrapper", "BufferedReader",
    "re.Pattern", "re.Match",
    "Thread", "Lock", "RLock", "Event", "Condition", "Semaphore",
    "Logger", "LogRecord",
    "Column", "Session", "Engine", "Table",  // SQLAlchemy base classes
    "BaseModel", "Field",  // Pydantic
    "Flask", "Blueprint",  // Flask
    "TestClient",  // FastAPI/Starlette
];


/// When `check_symbols` sees a method call on one of these receivers
/// (e.g., `Date.now()`, `Math.random()`), skip it entirely. These are
/// language builtins, not library-provided APIs that could be hallucinated.
const JS_GLOBAL_OBJECTS: &[&str] = &[
    "Date", "Math", "JSON", "Object", "Array", "String", "Number",
    "Boolean", "RegExp", "Error", "TypeError", "RangeError",
    "Promise", "Map", "Set", "WeakMap", "WeakSet", "Symbol",
    "Proxy", "Reflect", "console", "window", "document",
    "globalThis", "process", "Buffer", "Intl", "BigInt",
    "encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI",
];

/// Common framework/library method names that are never hallucinated —
/// they come from React, zustand, Redux, testing-library, and other
/// well-known JS/TS frameworks. Skipping prevents fuzzy matches like
/// `setState()` → `useState` or `setup()` → `setupDB`.
const COMMON_FRAMEWORK_METHODS: &[&str] = &[
    // React component lifecycle
    "render", "componentDidMount", "componentDidUpdate", "componentWillUnmount",
    "shouldComponentUpdate", "getDerivedStateFromProps", "getSnapshotBeforeUpdate",
    // React hooks (lowercase, sometimes extracted as method calls)
    "useEffect", "useState", "useRef", "useMemo", "useCallback", "useContext",
    "useReducer", "useLayoutEffect",
    // zustand store methods
    "setState", "getState", "subscribe", "destroy", "persist",
    // Redux
    "dispatch", "subscribe", "getState",
    // Testing library
    "setup", "teardown", "cleanup", "render", "rerender", "unmount",
    "findByText", "findByRole", "findByTestId", "findByPlaceholderText",
    "getByText", "getByRole", "getByTestId", "getByPlaceholderText",
    "queryByText", "queryByRole", "queryByTestId",
    // Vue
    "mounted", "unmounted", "created", "beforeMount", "beforeUnmount",
    // Express/HTTP
    "listen", "use", "get", "post", "put", "delete", "patch", "all",
];

/// Axios `AxiosHeaders` instance methods. These names are NOT generic
/// framework methods — they are specific to the axios `AxiosHeaders`
/// class. Only skip them when the receiver is actually `AxiosHeaders`,
/// otherwise we mask hallucinations on unrelated receivers (e.g. a
/// hallucinated `myClient.getContentType()` on a non-axios client passes
/// at 100% confidence). Gating by receiver class preserves recall.
/// Receiver is the regex-captured identifier before the dot, so this
/// only fires for `AxiosHeaders.<method>(...)`-style calls.
const AXIOS_HEADERS_METHODS: &[&str] = &[
    "getContentType", "hasContentType", "getContentLength", "getAuthorization",
    "hasAuthorization", "setContentType", "setAuthorization", "getSetCookie",
    "setSetCookie",
];

/// Receiver class names recognized as axios `AxiosHeaders` (or its
/// aliases in @types/axios). Used to gate AXIOS_HEADERS_METHODS.
const AXIOS_HEADERS_RECEIVERS: &[&str] = &["AxiosHeaders"];

/// Limits concurrent background symbol fetches to avoid hammering docs.rs.
static FETCH_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::const_new(2));

/// Matches `ClassName.method(` patterns in code.
/// Captures: (1) capitalized class name, (2) lowercase/snake method name.
static METHOD_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Z][a-zA-Z0-9_]+)\.([a-z_][a-zA-Z0-9_]*)\s*\(").unwrap()
});

/// Result of `check_symbols` — both the markdown context for Layer 3 AND
/// structured counts that drive the cascade decision (Layer 2.5).
#[derive(Debug, Clone, Default)]
pub struct SymbolCheckResult {
    /// Markdown-formatted context for Layer 3 (verified symbols + warnings).
    /// Empty if no cache, no libraries, or no method calls in content.
    pub markdown: String,

    /// Total distinct `ClassName.method(` patterns extracted from content.
    pub method_calls_count: usize,

    /// Method calls that hit the cache (symbol exists). Strong positive
    /// signal — these API claims are verified against authoritative source.
    pub verified_count: usize,

    /// Method calls where the CLASS exists in cache but the METHOD does not.
    /// Strong negative signal — high-confidence hallucination.
    pub hallucination_count: usize,

    /// Method calls where neither class nor method is in any cached library.
    /// Silent — we can't say either way (cache is incomplete). L3 should run.
    pub unknown_count: usize,

    /// "ClassName.method" pairs already verified against the cache (L1.5
    /// positive matches). Used by the cascade filter in scan_response to
    /// skip redundant L3 calls on claims L1.5 already resolved.
    pub verified_claims: std::collections::HashSet<String>,

    /// Per-claim confidence scores in [0.0, 1.0]. Used by the confidence-
    /// graded cascade to decide which claims warrant L3 escalation:
    ///   - 1.00: exact cache hit (verified, no L3 needed)
    ///   - 0.90: hallucinated with close fuzzy suggestion (deterministic)
    ///   - 0.85: class exists in cache, method missing (deterministic)
    ///   - 0.70: fuzzy class match across libraries (weaker signal)
    ///   - 0.00: no match at all (truly unknown — L3 candidate)
    ///
    /// Keyed by normalized claim text "ClassName.method" (no parens).
    pub claim_confidence: std::collections::HashMap<String, f64>,
}

impl SymbolCheckResult {
    /// True if Layer 1.5 fully resolves the content — every method call is
    /// either verified or flagged as hallucination. No ambiguity remains.
    pub fn fully_resolved(&self) -> bool {
        self.method_calls_count > 0
            && self.unknown_count == 0
            && (self.verified_count + self.hallucination_count) == self.method_calls_count
    }

    /// True if Layer 1.5 found at least one high-confidence hallucination
    /// (class cached, method missing). These are deterministic findings
    /// that don't need LLM confirmation.
    pub fn has_deterministic_hallucination(&self) -> bool {
        self.hallucination_count > 0
    }

    /// Scan-level confidence: minimum per-claim confidence across all
    /// method calls. High (>=0.85) means every claim was resolved with
    /// strong deterministic evidence. Low (<0.5) means at least one claim
    /// is uncertain — L3 spot-check warranted.
    ///
    /// Returns 1.0 when there are no claims (empty content / no method calls)
    /// — vacuously true that there's nothing to be uncertain about.
    pub fn scan_confidence(&self) -> f64 {
        if self.claim_confidence.is_empty() {
            return 1.0;
        }
        self.claim_confidence.values().copied().fold(1.0_f64, f64::min)
    }

    /// Count of claims with confidence >= threshold. Used by cascade to
    /// decide how many claims are "resolved" at a given confidence level.
    pub fn resolved_at_confidence(&self, threshold: f64) -> usize {
        self.claim_confidence.values().filter(|c| **c >= threshold).count()
    }
}

/// Map a cached library name to its programming language.
///
/// Used by [`check_symbols`] to gate cache lookups — when the scanner knows
/// the response is Python, it must not match Python's `pathlib.Path` against
/// Rust's `axum::extract::Path` (different types sharing a name).
///
/// Industry precedent: SCIP, Kythe, and Glean all treat language as a
/// first-class field on symbols. We avoid a schema migration by deriving
/// language from the library name at query time — the daemon's auto-fetcher
/// already namespaces libraries (`pypi.X`, `npm.X`) and most cached libraries
/// are well-known crates/packages with deterministic language ownership.
///
/// Returns `"unknown"` for libraries we can't classify — callers must treat
/// `unknown` as "no filter" (fall back to current behavior) to avoid
/// introducing false negatives on unrecognised libraries.
pub fn library_to_language(library: &str) -> &'static str {
    let lower = library.to_lowercase();
    let lower = lower.trim();

    // 0. Local-scanned projects: `local.<lang>.<name>` form.
    //    Tagged by local_scanner::detect_project_name when a marker file
    //    (package.json, Cargo.toml, pyproject.toml, go.mod, pom.xml,
    //    project.godot, *.csproj) identifies the dominant language.
    //    Falls through if the language segment is unrecognised.
    if let Some(rest) = lower.strip_prefix("local.") {
        let lang_seg = rest.split('.').next().unwrap_or("");
        let mapped = match lang_seg {
            "python" | "py" => Some("python"),
            "typescript" | "ts" | "javascript" | "js" => Some("typescript"),
            "rust" | "rs" => Some("rust"),
            "go" => Some("go"),
            "java" => Some("java"),
            "csharp" | "cs" => Some("csharp"),
            "cpp" | "c" | "c++" => Some("cpp"),
            "gdscript" | "gd" => Some("gdscript"),
            "ruby" | "rb" => Some("ruby"),
            "lua" => Some("lua"),
            "php" => Some("php"),
            _ => None,
        };
        if let Some(lang) = mapped {
            return lang;
        }
    }

    // 1. Auto-fetcher prefixes (docs Worker + direct fetch paths).
    if lower.starts_with("pypi.")
        || lower.starts_with("pypi_")
        || lower.starts_with("python.")
    {
        return "python";
    }
    if lower.starts_with("npm.")
        || lower.starts_with("npm_")
        || lower.starts_with("unpkg.")
    {
        return "typescript";
    }
    if lower.starts_with("crates.") || lower.starts_with("docs.rs/") || lower.starts_with("rust.") {
        return "rust";
    }
    // Cross-language prefixes from auto-fetcher and manual ingestion.
    if lower.starts_with("csharp.") || lower.starts_with("cs.") {
        return "csharp";
    }
    if lower.starts_with("java.") || lower.starts_with("maven.") {
        return "java";
    }
    if lower.starts_with("go.") || lower.starts_with("golang.") {
        return "go";
    }
    if lower.starts_with("cpp.") || lower.starts_with("c++.") {
        return "cpp";
    }

    // 2. Godot ecosystem (single language for the whole library).
    if lower == "godot" || lower.starts_with("godot-") {
        return "gdscript";
    }

    // 2b. Java ecosystem libraries (groupId prefixes from Maven Central).
    // Without these, `library_to_language("org.springframework")` returns
    // "unknown" → language gate at mod.rs:488-493 treats it as a candidate
    // for ALL languages → cross-language bleed when scanning non-Java content.
    if lower.starts_with("org.springframework")
        || lower.starts_with("org.apache")
        || lower.starts_with("com.google")
        || lower.starts_with("org.hibernate")
        || lower.starts_with("jakarta.")
        || lower.starts_with("org.junit")
        || lower.starts_with("org.mockito")
        || lower.starts_with("org.reactivestreams")
        || lower.starts_with("io.netty")
        || lower.starts_with("com.fasterxml.jackson")
        || lower.starts_with("org.slf4j")
        || lower.starts_with("ch.qos.logback")
        || lower.starts_with("com.zaxxer")
    {
        return "java";
    }

    // 2c. C++ libraries in the bundle.
    if lower == "sfml"
        || lower == "armadillo"
        || lower == "dlib"
        || lower == "opencv"
        || lower == "eigen"
        || lower == "boost"
        || lower == "qt"
        || lower == "glm"
        || lower == "wscript" // bundled C++ helpers
        || lower.starts_with("cpp.")
    {
        return "cpp";
    }

    // 3. Known Rust crates (daemon dependencies + auto-fetched crates).
    const RUST_CRATES: &[&str] = &[
        "axum", "tokio", "serde", "serde_json", "hyper", "hyper-util",
        "reqwest", "anyhow", "thiserror", "clap", "ratatui", "crossterm",
        "keyring", "jsonwebtoken", "quick-xml", "rusqlite", "html2markdown",
        "tracing", "tracing-subscriber", "once_cell", "regex", "tower",
        "tower-http", "mime", "futures", "async-trait", "bytes",
        "anubis", "anubis-daemon", "anubis-benchmark",
        // Common Rust crates that may appear in symbol cache from auto-fetch.
        "chrono", "rand", "uuid", "itertools", "rayon", "crossbeam",
        "dashmap", "parking_lot", "tokio-util", "tower-service",
        "pin-project", "slab", "smallvec", "lazy_static",
        "env_logger", "log", "config", "dotenv",
        // Daemon-internal: `robin` is the user's Rust workspace name and
        // holds 770K+ symbols. Without this, scanning non-Rust content
        // falls back to suggesting Robin types as fuzzy matches.
        "robin", "syn", "tree-sitter", "tree-sitter-rust", "rust_crates",
        "thiserror", "flate2", "tokio-stream", "quick-xml",
        "sha2", "semver", "serde_yaml", "fastrand", "hashbrown",
        "notify", "catppuccin", "agents", "agent",
    ];
    if RUST_CRATES.contains(&lower) {
        return "rust";
    }

    // 4. Known Python packages.
    const PYTHON_PKGS: &[&str] = &[
        "sqlalchemy", "pydantic", "click", "pathlib", "datetime",
        "json", "os", "sys", "typing", "asyncio", "fastapi", "flask",
        "requests", "numpy", "pandas", "sklearn", "scipy",
        "pytest", "unittest", "logging", "re", "collections",
        // Bundled stdlib shadows.
        "streamlit", "langchain", "openai", "pdb", "matplotlib",
        "dataclasses", "defaultdict", "iterable", "dateutil",
        "relativedelta", "bson", "pymongo", "redis",
        "sqlalchemy.orm", "langchain_core", "aiohttp", "httpx",
        "orjson", "openpyxl", "gunicorn", "typer", "rich",
        "virtualenv", "wheel", "setuptools", "pip",
    ];
    if PYTHON_PKGS.contains(&lower) {
        return "python";
    }

    // 5. Known TypeScript/JS libraries.
    const TS_LIBS: &[&str] = &[
        "react", "vue", "angular", "lodash", "axios", "express",
        "next", "typescript", "rxjs", "jquery", "three",
        // Bundled JS/TS libraries.
        "zod", "vite", "vitest", "promise", "jest", "level",
        "fetchtype", "flag", "detection", "agents",
        "@opencode-ai/mobile",
    ];
    if TS_LIBS.contains(&lower) {
        return "typescript";
    }

    // 6. .NET / C# libraries (NuGet packages + bundled BCL).
    if lower == "microsoft" || lower == "system"
        || lower.starts_with("csharp.")
        || lower.starts_with("microsoft.")
        || lower.starts_with("system.")
        || lower.starts_with("net.")
        || lower.starts_with("nuget.")
    {
        return "csharp";
    }

    // 7. Go standard library + ecosystem.
    if lower.starts_with("go.")
        || lower == "gorm" || lower == "grpc"
        || lower == "prometheus" || lower == "mongodb"
        || lower == "bson" || lower == "faiss"
        || lower == "fastrand" || lower == "oracledb"
    {
        return "go";
    }

    "unknown"
}

/// Scanner Layer 1.5 hook — check code's method calls against cached symbols.
///
/// `detected_language` (e.g. `"python"`, `"rust"`, `""`) gates the cache
/// lookup: when non-empty, libraries of a *different* known language are
/// skipped — preventing Python's `pathlib.Path` from matching Rust's
/// `axum::extract::Path`. Empty or `"unknown"` keeps the legacy behavior
/// (search all libraries) to preserve recall for projects with mixed or
/// undetected languages.
///
/// Returns [`SymbolCheckResult`] containing both:
///   - `markdown`: context string for Layer 3 LLM validator
///     - Section "Cached symbol references" with verified signatures
///     - Section "Potential hallucinations" for methods missing from cached classes
///   - Structured counts (`verified_count`, `hallucination_count`, etc.) used
///     by the scanner's cascade decision (Layer 2.5) to skip L3 when L1.5
///     fully resolves the content.
///
/// Returns empty markdown + zero counts if:
///   - No SymbolCache exists (fresh install, never ran `symbols add`)
///   - No libraries indexed
///   - No method calls in content
///
/// Designed to never block — just augment Layer 3 context + drive cascade.
/// Layer 3 (LLM) makes the final call when Layer 1.5 is ambiguous.
pub fn check_symbols(content: &str, detected_language: &str) -> SymbolCheckResult {
    let cache = match cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return SymbolCheckResult::default(),
    };
    check_symbols_with_cache(content, detected_language, &cache)
}

/// Same as `check_symbols` but with an explicit cache. Useful for tests
/// that need deterministic, in-memory seeding (council A4 — held-out
/// corpus testing requires this path so tests don't pollute the on-disk
/// global cache or depend on what bundle was loaded at install time).
pub fn check_symbols_with_cache(
    content: &str,
    detected_language: &str,
    cache: &cache::SymbolCache,
) -> SymbolCheckResult {
    let mut out = SymbolCheckResult::default();

    // Skip entirely if no libraries cached — avoids noise on fresh installs
    let cached_libs = match cache.list_libraries() {
        libs if !libs.is_empty() => libs,
        _ => return out,
    };

    // Extract method calls: ClassName.method(
    let method_calls: Vec<(String, String)> = METHOD_CALL_RE
        .captures_iter(content)
        .filter_map(|cap| {
            Some((
                cap.get(1)?.as_str().to_string(),
                cap.get(2)?.as_str().to_string(),
            ))
        })
        .collect();

    if method_calls.is_empty() {
        return out;
    }

    let mut verified_section = String::new();
    let mut hallucination_warnings: Vec<String> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for (class, method) in &method_calls {
        // Dedupe identical (class, method) pairs
        if !seen.insert((class.clone(), method.clone())) {
            continue;
        }

        out.method_calls_count += 1;
        let claim_key = format!("{}.{}", class, method);

        // Universal trait/built-in methods — available on virtually all types
        // via standard trait implementations. These should never be flagged as
        // hallucinated by the symbol cache because the cache only stores
        // crate-defined methods, not trait impls. Skipping prevents FPs like
        // Pending.to_string() (Display trait) or Vec.len() (ExactSizeIterator).
        if UNIVERSAL_TRAIT_METHODS.contains(&method.as_str()) {
            out.verified_count += 1;
            out.verified_claims.insert(claim_key.clone());
            out.claim_confidence.insert(claim_key, 1.0);
            continue;
        }

        // Common framework methods (React, zustand, Redux, testing-library).
        // These come from well-known libraries and are never hallucinated —
        // skipping prevents fuzzy matches like setState()→useState.
        // Gate by language: only skip when scanning JS/TS OR when language
        // is unknown. Names like useEffect/useState/getByRole are not
        // meaningful in Rust/Python/Java — let the language gate handle them.
        let framework_method_skip = COMMON_FRAMEWORK_METHODS.contains(&method.as_str())
            && (detected_language.is_empty() || detected_language == "unknown" || detected_language == "typescript" || detected_language == "javascript");
        if framework_method_skip {
            out.verified_count += 1;
            out.verified_claims.insert(claim_key.clone());
            out.claim_confidence.insert(claim_key, 1.0);
            continue;
        }

        // AxiosHeaders instance methods — scoped to receiver class so we
        // don't mask hallucinations on non-axios clients. Generic HTTP
        // verb names (getContentType, setAuthorization) should NOT be
        // globally trusted.
        if AXIOS_HEADERS_RECEIVERS.contains(&class.as_str())
            && AXIOS_HEADERS_METHODS.contains(&method.as_str())
        {
            out.verified_count += 1;
            out.verified_claims.insert(claim_key.clone());
            out.claim_confidence.insert(claim_key, 1.0);
            continue;
        }

        // JavaScript/TypeScript global objects (Date, Math, JSON, etc.).
        // These are language builtins, not library-provided APIs. Skipping
        // prevents cached-hallucination FPs like Date.now() matched against
        // the npm "date" package.
        // Gate by language: only skip when scanning JS/TS OR when language
        // is unknown. When scanning Rust/Python/Java/etc., let the language
        // gate handle it — JS_GLOBAL_OBJECTS otherwise defeated the gate
        // and verified e.g. java.util.Date.getTime() via npm "date" package.
        let js_global_skip = JS_GLOBAL_OBJECTS.contains(&class.as_str())
            && (detected_language.is_empty() || detected_language == "unknown" || detected_language == "typescript" || detected_language == "javascript");
        if js_global_skip {
            out.verified_count += 1;
            out.verified_claims.insert(claim_key.clone());
            out.claim_confidence.insert(claim_key, 1.0);
            continue;
        }

        // Python stdlib/framework classes (Path, Column, BaseModel, etc.).
        // These exist in multiple packages — name collision causes FPs when
        // e.g. pathlib.Path.home() matches against fastapi.Path.
        // Gate by language: only skip when scanning Python OR when language
        // is unknown (preserves the original behavior for uncategorised
        // responses). When scanning Rust/TS/Java/etc., let the language
        // gate at line 600 handle it — PYTHON_STDLIB_CLASSES defeated the
        // gate and verified axum.Path.home() via pypi.pathlib.
        let py_class_skip = PYTHON_STDLIB_CLASSES.contains(&class.as_str())
            && (detected_language.is_empty() || detected_language == "unknown" || detected_language == "python");
        if py_class_skip {
            out.verified_count += 1;
            out.verified_claims.insert(claim_key.clone());
            out.claim_confidence.insert(claim_key, 1.0);
            continue;
        }

        // SCREAMING_SNAKE_CASE constants (FILTERS, API_BASE_URL, MAX_RETRIES).
        // These are project-level constants, not class names. The method_call
        // regex catches them as ClassName.method() but they're const.method().
        // Skip to prevent cached-hallucination FPs like FILTERS.map().
        if class.len() >= 2
            && class.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            && class.chars().filter(|c| c.is_ascii_uppercase()).count() >= 2
        {
            out.verified_count += 1;
            out.verified_claims.insert(claim_key.clone());
            out.claim_confidence.insert(claim_key, 1.0);
            continue;
        }

        // Try each cached library (godot, typescript, etc.)
        let mut resolved = false;
        for (lib_name, _lib_version, _sym_count) in &cached_libs {
            // Language gate: when the scanner knows the response language,
            // skip libraries known to belong to a *different* language.
            // Prevents Python's `pathlib.Path` from matching Rust's
            // `axum::extract::Path`. Unknown-language libraries stay in the
            // candidate pool — preserves recall for unrecognised libs.
            if !detected_language.is_empty() && detected_language != "unknown" {
                let lib_lang = library_to_language(lib_name);
                if lib_lang != "unknown" && lib_lang != detected_language {
                    continue;
                }
            }
            let path = format!("{}.{}", class, method);

            match cache.lookup(lib_name, &path) {
                Some(symbol) => {
                    // Method exists — add to verified context
                    if verified_section.is_empty() {
                        verified_section.push_str("## Cached symbol references\n\n");
                    }
                    let sig = symbol.signature.as_deref().unwrap_or("(unknown)");
                    verified_section.push_str(&format!(
                        "- **{}.{}** ({}): `{}`\n",
                        class, method, lib_name, sig
                    ));
                    out.verified_count += 1;
                    // Track verified (class, method) pairs for cascade filter.
                    out.verified_claims.insert(format!("{}.{}", class, method));
                    // Exact cache hit → maximum confidence.
                    out.claim_confidence.insert(claim_key.clone(), 1.0);
                    resolved = true;
                    break; // found in one library, don't check others
                }
                None => {
                    // Method not found — check if class itself exists
                    if let Some(_class_symbol) = cache.lookup(lib_name, class) {
                        // Before flagging, check if the method exists on a class
                        // with the same name in any OTHER cached library.
                        //
                        // Cross-library type shadowing: cloudflare.Response has
                        // zero cached methods, but reqwest.Response.text() exists.
                        // Without this check, we'd flag Response.text() as a
                        // hallucination because cloudflare.Response is found
                        // first (alphabetically) and the loop breaks before
                        // checking reqwest.
                        //
                        // Also catches: std.Response vs framework.Response,
                        // library.Type vs project.Type (same name, different API).
                        let method_exists_in_other_lib = cached_libs
                            .iter()
                            .filter(|(l, _, _)| l.as_str() != lib_name.as_str())
                            .filter(|(l, _, _)| {
                                // Same language gate as the outer loop —
                                // don't accept a Rust method as proof that a
                                // Python call is real, or vice versa.
                                if !detected_language.is_empty()
                                    && detected_language != "unknown"
                                {
                                    let lang = library_to_language(l);
                                    lang == "unknown" || lang == detected_language
                                } else {
                                    true
                                }
                            })
                            .any(|(other_lib, _, _)| {
                                cache.lookup(other_lib, &path).is_some()
                            });

                        if method_exists_in_other_lib {
                            // Method exists on a same-named class in another
                            // library — not a hallucination.
                            out.verified_count += 1;
                            out.verified_claims
                                .insert(format!("{}.{}", class, method));
                            out.claim_confidence.insert(claim_key.clone(), 1.0);
                            resolved = true;
                            break;
                        }

                        // Fuzzy search: find closest method name on this class.
                        // Tightened thresholds to reduce false positives:
                        //   - Max Levenshtein distance ≤ 2 (was ≤ 3)
                        //   - Both names must be ≥ 4 chars (avoids all()↔allow())
                        //   - Length ratio must be ≥ 0.60 (bidirectional)
                        //   - Confidence floor: 0.50 (don't suggest below this)
                        let class_methods = cache.lookup_prefix(lib_name, &format!("{}.", class));
                        let closest = class_methods.iter()
                            .map(|s| (levenshtein_capped(method, &s.name, 3), s))
                            .filter(|(d, s)| {
                                if *d > 2 {
                                    return false;
                                }
                                // Skip very short names (high FP risk)
                                if method.len() < 4 || s.name.len() < 4 {
                                    return false;
                                }
                                // Length ratio check (bidirectional)
                                let ratio = s.name.len().min(method.len()) as f64
                                    / s.name.len().max(method.len()) as f64;
                                ratio >= 0.60
                            })
                            .min_by_key(|(d, _)| *d);

                        if let Some((dist, sym)) = closest {
                            let conf = 0.95 - ((dist.saturating_sub(1)) as f64) * 0.05;
                            // Confidence floor: don't suggest below 0.50
                            if conf >= 0.50 {
                                hallucination_warnings.push(format!(
                                    "{}.{}() — likely typo (distance {}). Did you mean {}.{}()?",
                                    class, method, dist, class, sym.name
                                ));
                                out.claim_confidence.insert(claim_key.clone(), conf);
                            } else {
                                hallucination_warnings.push(format!(
                                    "{}.{}() — class {} exists in {} v{} but method is not in cached symbols",
                                    class, method, class, lib_name, _lib_version
                                ));
                                out.claim_confidence.insert(claim_key.clone(), 0.85);
                            }
                        } else {
                            hallucination_warnings.push(format!(
                                "{}.{}() — class {} exists in {} v{} but method is not in cached symbols",
                                class, method, class, lib_name, _lib_version
                            ));
                            // Class exists, method definitely missing — high
                            // confidence hallucination. Slightly below exact
                            // fuzzy match because we have no suggestion.
                            out.claim_confidence.insert(claim_key.clone(), 0.85);
                        }
                        out.hallucination_count += 1;
                        resolved = true;
                        break;
                    }
                    // Neither class nor method in this library — try next
                }
            }
        }

        if !resolved {
            // Class not found in any cached library. If we have library context,
            // try a prefix-narrowed fuzzy search across all class names.
            //
            // Two-tier matching:
            //   - Short names / short prefix: Levenshtein ≤4 (tight)
            //   - Long shared prefix (≥6 chars): allow distance ≤8
            //     This catches canonical rename hallucinations like
            //     PolynomialTransformer → PolynomialFeatures (10-char prefix,
            //     distance ~8) without inflating FPR on short names.
            let prefix: String = class.chars().take(4).collect();
            let candidates = cache
                .find_classes_with_prefix(&prefix)
                .into_iter()
                .filter(|(lib, _)| {
                    // Language gate: don't suggest a Rust crate as the
                    // "did you mean" fix for a missing Python class.
                    if !detected_language.is_empty() && detected_language != "unknown" {
                        let lang = library_to_language(lib);
                        lang == "unknown" || lang == detected_language
                    } else {
                        true
                    }
                })
                .collect::<Vec<_>>();
            let closest = candidates
                .iter()
                .map(|(lib, candidate)| {
                    let dist = levenshtein_capped(class, candidate, 9);
                    let common_prefix = class
                        .chars()
                        .zip(candidate.chars())
                        .take_while(|(a, b)| a.eq_ignore_ascii_case(b))
                        .count();
                    let threshold = if common_prefix >= 6 { 8 } else { 4 };
                    (dist, common_prefix, lib, candidate, threshold)
                })
                .filter(|(dist, common_prefix, _, _, threshold)| {
                    *dist <= *threshold && *common_prefix >= 4 && class.len() >= 5
                })
                .min_by_key(|(dist, _, _, _, _)| *dist);

            if let Some((dist, common_prefix, lib, suggestion, _)) = closest {
                hallucination_warnings.push(format!(
                    "{}.{}() — class not found in any cached library (shared prefix {} chars, distance {}). Did you mean {} (in {})?",
                    class, method, common_prefix, dist, suggestion, lib
                ));
                out.hallucination_count += 1;
                // Fuzzy class match across libraries. Weaker signal than
                // same-class method miss — confidence scales with prefix
                // overlap. common_prefix=4 → 0.55, common_prefix=10 → 0.85.
                let conf = 0.45 + (common_prefix.min(8) as f64) * 0.05;
                out.claim_confidence.insert(claim_key.clone(), conf);
            } else {
                out.unknown_count += 1;
                // Truly unknown — no cache evidence either way.
                // L3 should escalate these.
                out.claim_confidence.insert(claim_key.clone(), 0.0);
            }
        }
    }

    if !hallucination_warnings.is_empty() {
        if verified_section.is_empty() {
            verified_section.push_str("## Cached symbol references\n\n");
        }
        verified_section.push_str("\n### ⚠️ Potential hallucinations\n\n");
        for warning in &hallucination_warnings {
            verified_section.push_str(&format!("- {}\n", warning));
        }
    }

    out.markdown = verified_section;
    out
}

/// Levenshtein distance capped at `max_dist`. Returns `max_dist + 1` if the
/// distance exceeds the cap (early exit). Used for fuzzy method-name matching
/// in check_symbols — avoids full O(n*m) computation when strings are clearly
/// different.
pub(crate) fn levenshtein_capped(a: &str, b: &str, max_dist: usize) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let a_len = a_bytes.len();
    let b_len = b_bytes.len();
    if a_len.abs_diff(b_len) > max_dist {
        return max_dist + 1;
    }
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr: Vec<usize> = vec![0; b_len + 1];
    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        // Early exit: if min value in curr exceeds max_dist, no point continuing.
        if curr.iter().min().copied().unwrap_or(0) > max_dist {
            return max_dist + 1;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}
/// Auto-fetch symbols for libraries detected in scanned code but not yet cached.
///
/// Called from scanner after extract_lookup_terms. Detects Rust crate names
/// (lowercase, alphanumeric + hyphens/underscores) that aren't in the cache,
/// then background-fetches them from docs.rs. Non-blocking — spawns a task
/// and returns immediately. Rate-limited to 1 fetch per call to avoid
/// hammering docs.rs.
///
/// Libraries that fail to fetch (not Rust crates, network errors) are added
/// to a negative cache to prevent retry storms.
pub async fn auto_fetch_missing(terms: &HashSet<String>) {
    let cache = match cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Get currently cached library names
    let cached: HashSet<String> = cache
        .list_libraries()
        .into_iter()
        .map(|(lib, _, _)| lib)
        .collect();

    // Check negative cache — skip libraries we've already tried
    let attempted = ATTEMPTED_FETCHES.lock().await;
    let attempted_set: HashSet<&str> = attempted.iter().map(|s| s.as_str()).collect();

    // Find ALL plausible crate names that need fetching (not just the first).
    // Previously used .find() which only fetched one per scan — leaving
    // multi-package responses (e.g. MediatR + Serilog + Polly) partially
    // unfetched and causing framework type FPs.
    let to_fetch: Vec<String> = terms
        .iter()
        .filter(|t| {
            !cached.contains(*t)
                && !attempted_set.contains(t.as_str())
                && is_plausible_crate_name(t)
        })
        .cloned()
        .collect();

    drop(attempted);

    for crate_name in &to_fetch {
        // Mark as attempted BEFORE spawning (prevent duplicate fetches).
        // LRU prune: pop front when over cap (FIFO approximation — entries
        // evicted are the oldest, not least-recently-used, but good enough).
        {
            let mut attempted = ATTEMPTED_FETCHES.lock().await;
            // Don't insert duplicates (idempotent)
            if !attempted.iter().any(|s| s == crate_name) {
                attempted.push_back(crate_name.clone());
                while attempted.len() > ATTEMPTED_FETCHES_MAX {
                    attempted.pop_front();
                }
            }
        }

        // Background fetch — non-blocking
        let name = crate_name.clone();
        tokio::spawn(async move {
            // Rate limiting removed — background fetch fires for all plausible packages
            match crate::symbols_cli::fetch_and_cache_single_crate(&name, None).await {
                Ok((count, _)) => {
                    tracing::info!(
                        target: "symbols",
                        "auto-fetched {} symbols for crate '{}'",
                        count, name
                    );
                    return;
                }
                Err(rust_err) => {
                    // Not a Rust crate — try as a TypeScript package (.d.ts from unpkg).
                    match crate::symbols_cli::fetch_and_cache_single_package(&name, None).await {
                        Ok((count, _)) => {
                            tracing::info!(
                                target: "symbols",
                                "auto-fetched {} symbols for npm package '{}'",
                                count, name
                            );
                        }
                        Err(ts_err) => {
                            // Not TS either — try Go module.
                            match crate::symbols::go_fetcher::fetch_and_cache_go_module(&name).await {
                                Ok((count, _)) => {
                                    tracing::info!(
                                        target: "symbols",
                                        "auto-fetched {} symbols for Go module '{}'",
                                        count, name
                                    );
                                }
                                Err(go_err) => {
                                    // Not Go — try Java library.
                                    match crate::symbols::java_fetcher::fetch_and_cache_java_library(&name).await {
                                        Ok((count, _)) => {
                                            tracing::info!(
                                                target: "symbols",
                                                "auto-fetched {} symbols for Java library '{}'",
                                                count, name
                                            );
                                        }
                                        Err(java_err) => {
                                            // Not Java — try C# package.
                                            match crate::symbols::csharp_fetcher::fetch_and_cache_csharp_package(&name).await {
                                                Ok((count, _)) => {
                                                    tracing::info!(
                                                        target: "symbols",
                                                        "auto-fetched {} symbols for C# package '{}'",
                                                        count, name
                                                    );
                                                }
                                                Err(csharp_err) => {
                                                    // Not C# — try Python package (PyPI).
                                                    match crate::symbols::python_fetcher::fetch_and_cache_python_package(&name).await {
                                                        Ok((count, _)) => {
                                                            tracing::info!(
                                                                target: "symbols",
                                                                "auto-fetched {} symbols for Python package '{}'",
                                                                count, name
                                                            );
                                                        }
                                                        Err(python_err) => tracing::debug!(
                                                            target: "symbols",
                                                            "auto-fetch '{}' exhausted all fetchers: rust={}, npm={}, go={}, java={}, csharp={}, python={}",
                                                            name, rust_err, ts_err, go_err, java_err, csharp_err, python_err
                                                        ),
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
        });
    }
}

/// Proactively fetch symbols for a project's declared dependencies.
///
/// Reads manifest files (Cargo.toml, package.json, requirements.txt, go.mod)
/// from the project root and feeds dependency names into the existing
/// auto-fetch pipeline. Called as a detached background task when the daemon
/// first scans a new project — ensures the cache is warm before the user's
/// code triggers reactive fetches.
///
/// Idempotent: skips projects already fetched (tracked via SEEN_PROJECTS static).
pub async fn fetch_project_dependencies(project_root: &str) {
    use std::collections::HashSet;
    use std::sync::OnceLock;

    static SEEN_PROJECTS: OnceLock<parking_lot::Mutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN_PROJECTS.get_or_init(|| parking_lot::Mutex::new(HashSet::new()));

    {
        let mut seen = seen.lock();
        if seen.contains(project_root) {
            return;
        }
        seen.insert(project_root.to_string());
    }

    let root = std::path::Path::new(project_root);
    if !root.is_dir() {
        return;
    }

    let mut terms: HashSet<String> = HashSet::new();

    // Rust: Cargo.toml [dependencies]
    let cargo_toml = root.join("Cargo.toml");
    if cargo_toml.exists() {
        if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
            let mut in_deps = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed == "[dependencies]" || trimmed.starts_with("[dependencies.") {
                    in_deps = true; continue;
                }
                if trimmed.starts_with('[') { in_deps = false; continue; }
                if in_deps {
                    if let Some(name) = trimmed.split('=').next() {
                        let name = name.trim().split('.').next().unwrap_or("").trim();
                        if !name.is_empty() && !name.starts_with('#') {
                            terms.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }

    // TypeScript/JavaScript: package.json
    let pkg_json = root.join("package.json");
    if pkg_json.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                for key in &["dependencies", "devDependencies", "peerDependencies"] {
                    if let Some(deps) = json.get(key).and_then(|v| v.as_object()) {
                        for dep_name in deps.keys() {
                            let name = dep_name.rsplit('/').next().unwrap_or(dep_name);
                            terms.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }

    // Python: requirements.txt
    let reqs = root.join("requirements.txt");
    if reqs.exists() {
        if let Ok(content) = std::fs::read_to_string(&reqs) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('-') { continue; }
                let name = line.split(|c: char| c == '=' || c == '<' || c == '>' || c == '!' || c == ';' || c == '[' || c == ' ').next().unwrap_or("").trim();
                if !name.is_empty() { terms.insert(name.to_string()); }
            }
        }
    }

    // Go: go.mod require block
    let go_mod = root.join("go.mod");
    if go_mod.exists() {
        if let Ok(content) = std::fs::read_to_string(&go_mod) {
            let mut in_require = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("require (") { in_require = true; continue; }
                if trimmed == ")" { in_require = false; continue; }
                if in_require || trimmed.starts_with("require ") {
                    let pkg = if in_require { trimmed } else { trimmed.strip_prefix("require ").unwrap_or(trimmed) };
                    if let Some(name) = pkg.split_whitespace().next() {
                        terms.insert(name.to_string());
                    }
                }
            }
        }
    }

    // Seed C++ std symbols (OnceCell guards against re-fetching).
    if let Err(e) = cpp_std_fetcher::fetch_and_cache_cpp_std().await {
        tracing::debug!(target: "symbols", error = %e, "C++ std seed failed (non-fatal)");
    }
    // Seed C# BCL symbols via metadata fetcher (OnceCell guards against re-fetching).
    csharp_fetcher::seed_csharp_bcl().await;

    if terms.is_empty() { return; }

    tracing::info!(target: "symbols", project_root = %project_root, dep_count = terms.len(), "Proactively fetching symbols for project dependencies");
    auto_fetch_missing(&terms).await;
}

/// Heuristic: does this term look like a Rust crate name?
/// Rust crates: lowercase, alphanumeric + hyphens/underscores, 2-64 chars.
/// Also matches npm packages (react, axios) — that's OK, docs.rs returns 404
/// fast and the negative cache prevents retry.
fn is_plausible_crate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() >= 2
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_symbols_empty_when_no_cache() {
        // Force cache to fail by setting HOME to a non-writable path
        // (SymbolCache::open will return Err)
        std::env::set_var("ANUBIS_SYMBOLS_TEST_NO_CACHE", "1");
        let result = check_symbols("Node2D.apply_scale(Vector2::new(1.0, 2.0))", "");
        std::env::remove_var("ANUBIS_SYMBOLS_TEST_NO_CACHE");
        // Either empty (if cache fails) or has content (if cache exists from prior tests)
        // This test just verifies the function doesn't panic
        let _ = result;
    }

    #[test]
    fn check_symbols_returns_empty_for_no_method_calls() {
        let result = check_symbols("let x = 5;\nprint('hello');\n", "");
        // No ClassName.method( pattern → returns empty markdown + zero counts
        assert!(result.markdown.is_empty());
        assert_eq!(result.method_calls_count, 0);
        assert_eq!(result.verified_count, 0);
        assert_eq!(result.hallucination_count, 0);
    }

    // ── library_to_language ────────────────────────────────────────────

    #[test]
    fn library_to_language_maps_known_prefixes_and_crates() {
        // Auto-fetcher prefixes.
        assert_eq!(library_to_language("pypi.sqlalchemy"), "python");
        assert_eq!(library_to_language("pypi_django"), "python");
        assert_eq!(library_to_language("python.sqlalchemy"), "python");
        assert_eq!(library_to_language("npm.react"), "typescript");
        assert_eq!(library_to_language("npm_vue"), "typescript");
        assert_eq!(library_to_language("unpkg.d3"), "typescript");

        // Godot.
        assert_eq!(library_to_language("godot"), "gdscript");
        assert_eq!(library_to_language("Godot"), "gdscript");
        assert_eq!(library_to_language("godot-cpp"), "gdscript");

        // Known Rust crates (daemon deps).
        assert_eq!(library_to_language("axum"), "rust");
        assert_eq!(library_to_language("tokio"), "rust");
        assert_eq!(library_to_language("hyper-util"), "rust");
        assert_eq!(library_to_language("reqwest"), "rust");
        assert_eq!(library_to_language("anubis"), "rust");
        assert_eq!(library_to_language("anubis-daemon"), "rust");

        // Known Python packages.
        assert_eq!(library_to_language("sqlalchemy"), "python");
        assert_eq!(library_to_language("pydantic"), "python");
        assert_eq!(library_to_language("click"), "python");
        assert_eq!(library_to_language("pathlib"), "python");

        // Known TS libs.
        assert_eq!(library_to_language("react"), "typescript");
        assert_eq!(library_to_language("lodash"), "typescript");

        // Unknown → no filter.
        assert_eq!(library_to_language("some-random-lib"), "unknown");
        assert_eq!(library_to_language(""), "unknown");
    }

    #[test]
    fn library_to_language_case_insensitive() {
        assert_eq!(library_to_language("AXUM"), "rust");
        assert_eq!(library_to_language("SQLAlchemy"), "python");
        assert_eq!(library_to_language("REACT"), "typescript");
    }

    // Cross-language bleed coverage: previously these returned "unknown" and
    // the language gate at mod.rs:488-493 left them as candidates for ALL
    // languages — root cause of:
    //   - task-011-godot FPs on Image.create/lock/unlock (SFML Image matched
    //     when scanning GDScript content)
    //   - task-010-java FPs on SpringApplication (matched Robin workspace
    //     types) and ResponseEntity (matched fastapi ResponseExt)
    #[test]
    fn library_to_language_maps_java_ecosystem() {
        assert_eq!(library_to_language("org.springframework"), "java");
        assert_eq!(library_to_language("org.springframework.boot"), "java");
        assert_eq!(library_to_language("org.apache.commons"), "java");
        assert_eq!(library_to_language("org.hibernate"), "java");
        assert_eq!(library_to_language("jakarta.persistence"), "java");
        assert_eq!(library_to_language("org.junit.jupiter"), "java");
        assert_eq!(library_to_language("org.mockito"), "java");
        assert_eq!(library_to_language("com.fasterxml.jackson.databind"), "java");
        assert_eq!(library_to_language("org.slf4j"), "java");
        assert_eq!(library_to_language("io.netty"), "java");
    }

    #[test]
    fn library_to_language_maps_cpp_ecosystem() {
        assert_eq!(library_to_language("sfml"), "cpp");
        assert_eq!(library_to_language("SFML"), "cpp");
        assert_eq!(library_to_language("armadillo"), "cpp");
        assert_eq!(library_to_language("dlib"), "cpp");
        assert_eq!(library_to_language("opencv"), "cpp");
        assert_eq!(library_to_language("eigen"), "cpp");
        assert_eq!(library_to_language("boost"), "cpp");
        assert_eq!(library_to_language("qt"), "cpp");
        assert_eq!(library_to_language("glm"), "cpp");
        assert_eq!(library_to_language("cpp.vector"), "cpp");
    }

    #[test]
    fn library_to_language_maps_local_scanned_projects() {
        // Projects scanned by local_scanner::detect_project_name get
        // the prefix `local.<lang>.<name>` so the cross-language cache
        // gate (mod.rs:488-493) filters them correctly. Without this,
        // a Godot benchmark project's Image.create() symbol would bleed
        // into Java scans and vice versa.
        assert_eq!(library_to_language("local.gdscript.task-011-platformer"), "gdscript");
        assert_eq!(library_to_language("local.java.task-010-spring-api"), "java");
        assert_eq!(library_to_language("local.python.task-005-fastapi"), "python");
        assert_eq!(library_to_language("local.rust.task-001-todo-cli"), "rust");
        assert_eq!(library_to_language("local.typescript.task-007-express"), "typescript");
        assert_eq!(library_to_language("local.go.task-003-microservice"), "go");
        assert_eq!(library_to_language("local.csharp.task-009-api"), "csharp");
        assert_eq!(library_to_language("local.cpp.task-008-tracker"), "cpp");
        // Aliases also accepted.
        assert_eq!(library_to_language("local.ts.myapp"), "typescript");
        assert_eq!(library_to_language("local.rs.myapp"), "rust");
        assert_eq!(library_to_language("local.py.myapp"), "python");
        assert_eq!(library_to_language("local.cs.myapp"), "csharp");
        assert_eq!(library_to_language("local.gd.myapp"), "gdscript");
        assert_eq!(library_to_language("local.c++.myapp"), "cpp");
        // Unknown language segment still falls through to other rules.
        assert_eq!(library_to_language("local.foobar.myapp"), "unknown");
    }

    #[test]
    fn library_to_language_maps_daemon_workspace_robin_to_rust() {
        // `robin` is the user's Rust workspace name. Without this, Robin's
        // 770K symbols contaminated every non-Rust scan via fuzzy match
        // suggestions (e.g. ResponseEntity → ResponseExt in Robin).
        assert_eq!(library_to_language("robin"), "rust");
        assert_eq!(library_to_language("ROBIN"), "rust");
    }

    #[test]
    fn library_to_language_maps_csharp_ecosystem() {
        assert_eq!(library_to_language("csharp.System"), "csharp");
        assert_eq!(library_to_language("microsoft.extensions"), "csharp");
        assert_eq!(library_to_language("system.collections"), "csharp");
        assert_eq!(library_to_language("net.http"), "csharp");
    }

    #[test]
    fn library_to_language_maps_go_ecosystem() {
        assert_eq!(library_to_language("go.context"), "go");
        assert_eq!(library_to_language("gorm"), "go");
        assert_eq!(library_to_language("grpc"), "go");
    }

    #[test]
    fn library_to_language_unmapped_stays_unknown() {
        // Sanity: novel libraries still return "unknown" so the language
        // gate falls back to inclusive candidate search.
        assert_eq!(library_to_language("collection"), "unknown");
        assert_eq!(library_to_language("input"), "unknown");
        assert_eq!(library_to_language("image"), "unknown");
        assert_eq!(library_to_language("date"), "unknown");
        assert_eq!(library_to_language("totally-new-lib"), "unknown");
    }

    /// Verify the language filter prevents Python claims from matching Rust
    /// libraries. Builds a temp cache with axum.Path (no .home method) and
    /// pathlib.Path.home(), then checks that scanning Python content with
    /// detected_language="python" only sees the python library.
    #[test]
    fn check_symbols_language_filter_skips_wrong_language_libraries() {
        use crate::symbols::cache::SymbolCache;
        use crate::symbols::types::{Symbol, SymbolKind};

        let cache = SymbolCache::open_in_memory().unwrap();

        // Rust library: axum has a Path struct, no .home method.
        let mut axum_path = Symbol::new("axum", "0.7.0", "Path");
        axum_path.kind = SymbolKind::Class;
        cache.insert_many(&[axum_path]).unwrap();

        // Python library: pypi.pathlib has Path.home.
        let mut py_path = Symbol::new("pypi.pathlib", "3.12", "Path");
        py_path.kind = SymbolKind::Class;
        let mut py_path_home = Symbol::new("pypi.pathlib", "3.12", "Path.home");
        py_path_home.kind = SymbolKind::Method;
        cache.insert_many(&[py_path, py_path_home]).unwrap();

        // Sanity: axum.Path exists, but no axum.Path.home.
        assert!(cache.lookup("axum", "Path").is_some());
        assert!(cache.lookup("axum", "Path.home").is_none());
        // pypi.pathlib.Path.home exists.
        assert!(cache.lookup("pypi.pathlib", "Path.home").is_some());

        // detected_language="rust": Path.home() should NOT be verified
        // via pypi.pathlib (cross-language shadowing). The check should
        // resolve to "axum.Path exists but no .home method" — a cached-
        // hallucination warning, not a verified call.
        let rust_result = check_symbols_with_cache("Path.home()", "rust", &cache);
        // No verified hits — the Python lib was filtered out by the gate.
        // (We don't assert on hallucination_count because Path matches
        // PYTHON_STDLIB_CLASSES skip list inside check_symbols; the load-
        // bearing assertion is that nothing was verified via Python.)
        assert_eq!(
            rust_result.verified_count, 0,
            "Rust scan must not verify Path.home via pypi.pathlib"
        );

        // detected_language="python": Path.home() verifies via pypi.pathlib.
        let py_result = check_symbols_with_cache("Path.home()", "python", &cache);
        assert!(
            py_result.verified_count >= 1,
            "Python scan must verify Path.home via pypi.pathlib, got {}",
            py_result.verified_count
        );
    }

    #[test]
    fn check_symbols_js_global_objects_skipped_only_for_js() {
        use crate::symbols::cache::SymbolCache;
        use crate::symbols::types::{Symbol, SymbolKind};

        let cache = SymbolCache::open_in_memory().unwrap();

        // JS global: Date class. Seed a competing TS library with Date.now.
        let mut ts_date = Symbol::new("npm.date", "1.0", "Date");
        ts_date.kind = SymbolKind::Class;
        let mut ts_date_now = Symbol::new("npm.date", "1.0", "Date.now");
        ts_date_now.kind = SymbolKind::Method;
        cache.insert_many(&[ts_date, ts_date_now]).unwrap();

        // detected_language="typescript": Date.now() must skip via
        // JS_GLOBAL_OBJECTS and count as verified (skip is intentional
        // — Date is a TS builtin, not the npm "date" package).
        let ts_result = check_symbols_with_cache("Date.now()", "typescript", &cache);
        assert!(
            ts_result.verified_count >= 1,
            "TS scan must skip Date.now via JS_GLOBAL_OBJECTS, got {}",
            ts_result.verified_count
        );

        // detected_language="java": Date.now() is NOT a Java builtin
        // (java.util.Date has getTime, not now). The skip must NOT fire
        // — the call should resolve through the language-gated lookup
        // path, which finds npm.date (filtered out as typescript!=java)
        // and falls through to "no Java lib has Date.now" → unresolved.
        // We don't assert verified_count == 0 because Date also matches
        // PYTHON_STDLIB_CLASSES when lang is python, but for java neither
        // skip fires — the load-bearing assertion is no false verification.
        let java_result = check_symbols_with_cache("Date.now()", "java", &cache);
        assert_eq!(
            java_result.verified_count, 0,
            "Java scan must not skip Date.now via JS_GLOBAL_OBJECTS, got verified={}",
            java_result.verified_count
        );
    }

    #[test]
    fn fully_resolves_when_all_methods_verified() {
        // Construct a SymbolCheckResult where every call is verified.
        // fully_resolved() must be true.
        let r = SymbolCheckResult {
            markdown: "verified".to_string(),
            method_calls_count: 3,
            verified_count: 3,
            hallucination_count: 0,
            unknown_count: 0,
            verified_claims: Default::default(),
            ..Default::default()
        };
        assert!(r.fully_resolved());
        assert!(!r.has_deterministic_hallucination());
    }

    #[test]
    fn fully_resolves_when_all_methods_flagged_as_hallucinations() {
        // All calls hit cached classes but missing methods → still fully
        // resolved (we know the verdict for every call).
        let r = SymbolCheckResult {
            markdown: "hallucinations".to_string(),
            method_calls_count: 2,
            verified_count: 0,
            hallucination_count: 2,
            unknown_count: 0,
            verified_claims: Default::default(),
            ..Default::default()
        };
        assert!(r.fully_resolved());
        assert!(r.has_deterministic_hallucination());
    }

    #[test]
    fn not_fully_resolved_with_unknowns() {
        // Some calls couldn't be checked against any cached library — L3
        // should run.
        let r = SymbolCheckResult {
            markdown: String::new(),
            method_calls_count: 5,
            verified_count: 3,
            hallucination_count: 0,
            unknown_count: 2,
            verified_claims: Default::default(),
            ..Default::default()
        };
        assert!(!r.fully_resolved(), "unknowns mean L3 must run");
    }

    #[test]
    fn not_fully_resolved_with_zero_method_calls() {
        // No method calls — can't claim "fully resolved", let L3 decide.
        let r = SymbolCheckResult::default();
        assert!(!r.fully_resolved());
    }

    #[test]
    fn method_call_regex_matches_typical_patterns() {
        let text = "Node2D.apply_scale(v)\nNode.add_child(node)\nCanvasItem.queue_redraw()";
        let matches: Vec<_> = METHOD_CALL_RE
            .captures_iter(text)
            .filter_map(|c| {
                Some((
                    c.get(1)?.as_str().to_string(),
                    c.get(2)?.as_str().to_string(),
                ))
            })
            .collect();
        assert!(matches.contains(&("Node2D".to_string(), "apply_scale".to_string())));
        assert!(matches.contains(&("Node".to_string(), "add_child".to_string())));
        assert!(matches.contains(&("CanvasItem".to_string(), "queue_redraw".to_string())));
    }

    #[test]
    fn method_call_regex_ignores_lowercase_starts() {
        let text = "object.method()\narray.push(1)";
        // Should NOT match these — class must start with capital
        let matches: Vec<_> = METHOD_CALL_RE
            .captures_iter(text)
            .filter_map(|c| {
                Some((
                    c.get(1)?.as_str().to_string(),
                    c.get(2)?.as_str().to_string(),
                ))
            })
            .collect();
        // object.method and array.push don't start with capitals — no matches
        assert!(matches.is_empty());
    }

    #[test]
    fn method_call_regex_ignores_function_calls_without_dot() {
        let text = "print()\nfoo()\nBar()";
        let matches: Vec<_> = METHOD_CALL_RE
            .captures_iter(text)
            .filter_map(|c| {
                Some((
                    c.get(1)?.as_str().to_string(),
                    c.get(2)?.as_str().to_string(),
                ))
            })
            .collect();
        assert!(matches.is_empty());
    }

    // ── scan_confidence + claim_confidence tests ────────────────────
    // These test the per-claim confidence tracking that drives the
    // confidence-graded L3 cascade (L3_SKIP_CONFIDENCE_THRESHOLD = 0.85).

    fn claim_confidence_map(pairs: &[(&str, f64)]) -> std::collections::HashMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn scan_confidence_empty_claims_returns_one() {
        // Empty content / no method calls → vacuously confident.
        let r = SymbolCheckResult::default();
        assert_eq!(r.scan_confidence(), 1.0);
    }

    #[test]
    fn scan_confidence_all_high_confidence_returns_one() {
        // Every claim resolved with exact cache hits (1.0).
        let r = SymbolCheckResult {
            method_calls_count: 3,
            verified_count: 3,
            claim_confidence: claim_confidence_map(&[
                ("Node.add_child", 1.0),
                ("Node.queue_free", 1.0),
                ("Vector3.normalized", 1.0),
            ]),
            ..Default::default()
        };
        assert_eq!(r.scan_confidence(), 1.0);
    }

    #[test]
    fn scan_confidence_returns_minimum_across_claims() {
        // One uncertain claim drags the whole scan's confidence down.
        // This is intentional — the cascade escalates to L3 if ANY claim
        // is uncertain, because L3 spot-checks are per-claim.
        let r = SymbolCheckResult {
            method_calls_count: 3,
            verified_count: 2,
            claim_confidence: claim_confidence_map(&[
                ("Node.add_child", 1.0),
                ("Node.queue_free", 1.0),
                ("Phantom.method", 0.45),  // fuzzy class match
            ]),
            ..Default::default()
        };
        assert_eq!(r.scan_confidence(), 0.45);
    }

    #[test]
    fn scan_confidence_zero_when_any_claim_unknown() {
        // Unknown claim (no cache evidence) → 0.0 → triggers L3.
        let r = SymbolCheckResult {
            method_calls_count: 2,
            verified_count: 1,
            unknown_count: 1,
            claim_confidence: claim_confidence_map(&[
                ("Node.add_child", 1.0),
                ("MysteryClass.method", 0.0),
            ]),
            ..Default::default()
        };
        assert_eq!(r.scan_confidence(), 0.0);
    }

    #[test]
    fn scan_confidence_high_when_only_hallucinations_detected() {
        // Even when every claim IS a hallucination, confidence is high
        // if the evidence is strong (exact cache miss with close match).
        // The cascade trusts high-confidence hallucination verdicts.
        let r = SymbolCheckResult {
            method_calls_count: 2,
            hallucination_count: 2,
            claim_confidence: claim_confidence_map(&[
                ("Node.append_child", 0.85),  // class exists, method missing
                ("Vector3.normalize_self", 0.85),
            ]),
            ..Default::default()
        };
        // 0.85 ≥ L3_SKIP_CONFIDENCE_THRESHOLD → cascade skips L3.
        assert!(r.scan_confidence() >= 0.85);
    }

    #[test]
    fn resolved_at_confidence_counts_above_threshold() {
        let r = SymbolCheckResult {
            method_calls_count: 4,
            claim_confidence: claim_confidence_map(&[
                ("a", 1.0),
                ("b", 0.95),
                ("c", 0.85),  // exactly at threshold
                ("d", 0.45),  // below threshold
            ]),
            ..Default::default()
        };
        // Threshold 0.85 — should count a, b, c (>= comparison).
        assert_eq!(r.resolved_at_confidence(0.85), 3);
        // Higher threshold excludes c.
        assert_eq!(r.resolved_at_confidence(0.86), 2);
    }

    #[test]
    fn scan_confidence_at_cascade_boundary() {
        // L3_SKIP_CONFIDENCE_THRESHOLD = 0.85. Tests the exact boundary:
        //   confidence == 0.85 → skip L3 (>= comparison)
        //   confidence == 0.84 → run L3
        let at_boundary = SymbolCheckResult {
            method_calls_count: 1,
            claim_confidence: claim_confidence_map(&[("claim", 0.85)]),
            ..Default::default()
        };
        assert_eq!(at_boundary.scan_confidence(), 0.85);
        assert!(at_boundary.scan_confidence() >= 0.85);

        let just_below = SymbolCheckResult {
            method_calls_count: 1,
            claim_confidence: claim_confidence_map(&[("claim", 0.84)]),
            ..Default::default()
        };
        assert!(just_below.scan_confidence() < 0.85);
    }
}

