//! Go runtime introspection via `go doc` subprocess + pkg.go.dev HTTP fallback.
//!
//! For each imported package, fetches exported type methods.
//! Requires Go binary installed. Falls back to go_fetcher.rs web scraping.

use std::collections::HashMap;
use std::collections::HashSet;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use crate::scanner::local_introspect::ModuleInfo;

static GO_TYPE_CACHE: Lazy<Mutex<HashMap<(String, String), ModuleInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// ── User-extendable Go framework skip-lists (council A7) ───────────────────
//
// GO_FRAMEWORK_PKGS / GO_FRAMEWORK_FUNCS / GO_FRAMEWORK_FUNCS_BARE are
// static sets baked into the binary. Users with internal Go frameworks
// (custom routers, ORM wrappers) cannot extend without recompiling. The
// `extra_go_framework_pkgs` + `extra_go_framework_funcs` ScannerConfig
// fields feed these OnceCells at daemon startup; the is_go_*_skip helpers
// check both. Empty by default — common frameworks (gin, gorm, echo,
// fiber, chi, gorilla, mux) are already covered.

static EXTRA_GO_FRAMEWORK_PKGS: once_cell::sync::OnceCell<std::collections::HashSet<String>> =
    once_cell::sync::OnceCell::new();
static EXTRA_GO_FRAMEWORK_FUNCS: once_cell::sync::OnceCell<std::collections::HashSet<String>> =
    once_cell::sync::OnceCell::new();

/// Populate user-extendable Go framework skip-lists from config. Called
/// once at daemon startup. Subsequent calls are no-ops (first-write-wins).
/// NOTE: extra_go_framework_funcs feeds BOTH the package-qualified path
/// (GO_FRAMEWORK_FUNCS) and the bare-function path (GO_FRAMEWORK_FUNCS_BARE)
/// because they overlap heavily in practice — users typically want the
/// same name skipped regardless of call shape.
pub fn set_extra_go_framework(pkgs: Vec<String>, funcs: Vec<String>) {
    let _ = EXTRA_GO_FRAMEWORK_PKGS.set(pkgs.into_iter().collect());
    let _ = EXTRA_GO_FRAMEWORK_FUNCS.set(funcs.into_iter().collect());
}

/// Check whether a Go package name should be treated as a known framework
/// (router/ORM/etc.) for the package-qualified function skip. Caller must
/// ALSO check `is_go_framework_func_skip(func)` — skipping is gated on BOTH
/// the receiver package AND the function name being recognized.
pub fn is_go_framework_pkg_skip(pkg: &str) -> bool {
    // Built-in static set lives inside verify_go_package_functions (lazy
    // local static). Mirror its contents here as a separate static for the
    // helper to reference without restructuring.
    static BUILTIN_PKGS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
        ["gin", "gorm", "echo", "fiber", "chi", "gorilla", "mux"]
            .iter().copied().collect()
    });
    BUILTIN_PKGS.contains(pkg)
        || EXTRA_GO_FRAMEWORK_PKGS
            .get()
            .is_some_and(|set| set.contains(pkg))
}

/// Check whether a Go function name should be skipped when called on a
/// known framework package. Combined with is_go_framework_pkg_skip at the
/// call site. Also used standalone for the bare-function path (where any
/// upper-case Go framework name like `Recovery`/`Logger` is skipped).
pub fn is_go_framework_func_skip(func: &str) -> bool {
    static BUILTIN_FUNCS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
        [
            // gin middleware + HTTP methods
            "Recovery", "Logger", "Context",
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
            "Group", "Use", "Static", "StaticFS", "StaticFile",
            // GORM methods
            "TableName", "Migrate", "AutoMigrate", "Create", "Save", "First",
            "Find", "Where", "Delete", "Updates", "Assign", "Attrs",
            "FirstOrCreate", "Update", "Pluck", "Count", "Distinct",
            "Select", "Order", "Group", "Having", "Joins", "Preload",
            "Association", "Begin", "Commit", "Rollback",
            "Raw", "Exec", "Rows", "Scan", "Row", "RowsAffected",
            "UpdateColumn", "UpdateColumns", "Not", "Or", "Limit",
            "Offset", "Unscoped", "Debug",
        ]
        .iter().copied().collect()
    });
    BUILTIN_FUNCS.contains(func)
        || EXTRA_GO_FRAMEWORK_FUNCS
            .get()
            .is_some_and(|set| set.contains(func))
}

/// Map Go receiver names to (package, type) from variable declarations.
/// Handles:
///   - `var x http.Response`
///   - `x := http.GetResponse()`
///   - `x := pkg.TypeName{...}` (struct literal)
///   - `x := pkg.NewTypeName(...)` (New-prefixed constructor)
///   - `x := pkg.FuncName(...)` (general factory — derive type from func name)
///   - `x := pkg.Var.MethodName(...)` (method call on package var — derive
///     type from method name, e.g. `protoimpl.X.MessageStateOf(...)` →
///     MessageState)
pub fn build_go_receiver_map(content: &str) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();

    // var x pkg.TypeName
    let var_re = regex::Regex::new(
        r"\bvar\s+(\w+)\s+(\w+)\.([A-Z]\w*)"
    ).unwrap();
    for caps in var_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let pkg = caps.get(2).unwrap().as_str().to_string();
        let type_name = caps.get(3).unwrap().as_str().to_string();
        map.insert(receiver, (pkg, type_name));
    }

    // x := pkg.TypeName{...} (struct literal)
    let struct_re = regex::Regex::new(
        r"\b(\w+)\s*:?=\s*(\w+)\.([A-Z]\w*)\s*\{"
    ).unwrap();
    for caps in struct_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let pkg = caps.get(2).unwrap().as_str().to_string();
        let type_name = caps.get(3).unwrap().as_str().to_string();
        map.insert(receiver, (pkg, type_name));
    }

    // x := pkg.NewTypeName(...) (constructor pattern)
    let ctor_re = regex::Regex::new(
        r"\b(\w+)\s*:?=\s*(\w+)\.New([A-Z]\w*)\s*\("
    ).unwrap();
    for caps in ctor_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let pkg = caps.get(2).unwrap().as_str().to_string();
        let type_name = caps.get(3).unwrap().as_str().to_string();
        map.insert(receiver, (pkg, type_name));
    }

    // x := pkg.MethodName(...) (general factory pattern).
    // Derive type from method name by stripping common suffixes:
    //   MessageStateOf → MessageState
    //   ValueOf        → Value
    //   TypeOf         → Type
    //   NewClient      → Client (handled by ctor_re above; this catches
    //                   non-New factories like Build, Make, Create)
    // Only set if not already mapped (more specific patterns win).
    let factory_re = regex::Regex::new(
        r"\b(\w+)\s*:?=\s*(\w+)\.([A-Z]\w*)\s*\("
    ).unwrap();
    for caps in factory_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        if map.contains_key(&receiver) { continue; }
        let pkg = caps.get(2).unwrap().as_str().to_string();
        let func_name = caps.get(3).unwrap().as_str().to_string();
        if let Some(type_name) = derive_type_from_func(&func_name) {
            map.insert(receiver, (pkg, type_name));
        }
    }

    // x := pkg.Var.MethodName(...) (method call on package-level var).
    // Common in protobuf runtime code: `ms := protoimpl.X.MessageStateOf(...)`
    // Derive type from the trailing method name.
    let method_factory_re = regex::Regex::new(
        r"\b(\w+)\s*:?=\s*(\w+)\.(\w+)\.([A-Z]\w*Of)\s*\("
    ).unwrap();
    for caps in method_factory_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        if map.contains_key(&receiver) { continue; }
        let pkg = caps.get(2).unwrap().as_str().to_string();
        let method_name = caps.get(4).unwrap().as_str().to_string();
        if let Some(type_name) = derive_type_from_func(&method_name) {
            map.insert(receiver, (pkg, type_name));
        }
    }

    map
}

/// Derive a Go type name from a factory function name by stripping common
/// suffixes that indicate "returns a T":
///   `MessageStateOf` → `MessageState`
///   `ValueOf`        → `Value`
///   `NewClient`      → `Client` (also handled by ctor_re)
///   `BuildClient`    → `Client`
///
/// Conservative — only strips a small set of well-known factory suffixes to
/// avoid deriving nonsense types from arbitrary function names. Returns
/// None if no known suffix matches, in which case we don't add the receiver
/// to the map (can't safely verify).
fn derive_type_from_func(func_name: &str) -> Option<String> {
    // Suffixes that strongly indicate "returns T".
    const FACTORY_SUFFIXES: &[&str] = &[
        "Of",       // MessageStateOf → MessageState (protobuf idiom)
        "From",     // ClientFrom → Client
        "For",      // BuilderFor → Builder
    ];
    // Prefixes that strongly indicate "constructs T".
    const FACTORY_PREFIXES: &[&str] = &[
        "New",      // NewClient → Client
        "Build",    // BuildClient → Client
        "Make",     // MakeQueue → Queue
        "Create",   // CreateSession → Session
        "Get",      // GetClient → Client (best-effort)
    ];
    for suffix in FACTORY_SUFFIXES {
        if func_name.len() > suffix.len() && func_name.ends_with(suffix) {
            let base = &func_name[..func_name.len() - suffix.len()];
            if base.len() >= 2 {
                return Some(base.to_string());
            }
        }
    }
    for prefix in FACTORY_PREFIXES {
        if func_name.len() > prefix.len() && func_name.starts_with(prefix) {
            let base = &func_name[prefix.len()..];
            if base.len() >= 2 {
                return Some(base.to_string());
            }
        }
    }
    None
}

/// Introspect a Go type's methods via `go doc` subprocess.
pub async fn introspect_go_type(package: &str, type_name: &str) -> ModuleInfo {
    let key = (package.to_string(), type_name.to_string());

    {
        let cache = GO_TYPE_CACHE.lock().await;
        if let Some(info) = cache.get(&key) {
            return info.clone();
        }
    }

    let full_path = format!("{}.{}", package, type_name);
    let start = std::time::Instant::now();

    // Try `go doc` subprocess.
    let result = crate::scanner::command_hidden_tokio("go")
        .args(["doc", "-all", &full_path])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await;

    let latency_ms = start.elapsed().as_millis() as u64;

    let info = match result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let methods = parse_go_doc_methods(&stdout, type_name);
            ModuleInfo {
                module: full_path,
                names: methods,
                error: None,
                latency_ms,
            }
        }
        _ => {
            // Go not installed or type not found.
            ModuleInfo {
                module: full_path,
                names: vec![],
                error: Some("go doc unavailable".to_string()),
                latency_ms,
            }
        }
    };

    let mut cache = GO_TYPE_CACHE.lock().await;
    cache.insert(key, info.clone());
    info
}

/// Parse method names from `go doc -all` output.
fn parse_go_doc_methods(doc: &str, type_name: &str) -> Vec<String> {
    let mut methods = Vec::new();
    // go doc output format:
    //   func (t *TypeName) MethodName(args) returnType
    let method_re = regex::Regex::new(
        &format!(r"func\s+\(\s*\w+\s+\*?{}\s*\)\s+(\w+)", type_name)
    ).unwrap();

    for caps in method_re.captures_iter(doc) {
        if let Some(m) = caps.get(1) {
            let name = m.as_str();
            if !name.is_empty() && !name.starts_with('_') {
                methods.push(name.to_string());
            }
        }
    }
    methods
}

/// Look up a Go type from local SymbolCache (offline, instant).
fn lookup_go_type_from_cache(type_name: &str) -> Option<ModuleInfo> {
    let cache = crate::symbols::cache::SymbolCache::open().ok()?;
    let matches = cache.lookup_global(type_name);
    if matches.is_empty() {
        return None;
    }
    let sym = &matches[0];
    let methods = cache.lookup_prefix(&sym.library, &format!("{}.", type_name));
    let names: Vec<String> = methods.iter().map(|m| m.name.clone()).collect();
    if names.is_empty() {
        return None;
    }
    Some(ModuleInfo {
        module: format!("{}.{}", sym.library, type_name),
        names,
        error: None,
        latency_ms: 0,
    })
}

/// Verify Go method calls against go doc introspection.
pub async fn verify_go_methods(
    content: &str,
    receiver_map: &HashMap<String, (String, String)>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if receiver_map.is_empty() {
        return warnings;
    }

    let method_re = regex::Regex::new(
        r"(?:^|[^a-zA-Z0-9_])(\w+)\.([A-Z]\w*)\s*\("
    ).unwrap();

    let mut checked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut type_infos: HashMap<String, ModuleInfo> = HashMap::new();

    for caps in method_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method = caps.get(2).unwrap().as_str().to_string();

        let (pkg, type_name) = match receiver_map.get(&receiver) {
            Some(v) => v.clone(),
            None => continue,
        };

        if !checked.insert((receiver.clone(), method.clone())) {
            continue;
        }

        let cache_key = format!("{}.{}", pkg, type_name);
        let info = if let Some(i) = type_infos.get(&cache_key) {
            i.clone()
        } else {
            let i = if let Some(cached) = lookup_go_type_from_cache(&type_name) {
                cached
            } else {
                introspect_go_type(&pkg, &type_name).await
            };
            type_infos.insert(cache_key, i.clone());
            i
        };

        if info.error.is_some() {
            continue;
        }

        // Go methods are capitalized (exported). Lower the check.
        if !info.exists(&method) && !info.exists(&method.to_lowercase()) {
            match info.closest_match(&method) {
                Some(suggestion) => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not a method on `{}.{}`. Did you mean `{}`?",
                    receiver, method, method, pkg, type_name, suggestion
                )),
                None => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not a method on `{}.{}`",
                    receiver, method, method, pkg, type_name
                )),
            }
        }
    }

    warnings
}

pub async fn clear_cache() {
    GO_TYPE_CACHE.lock().await.clear();
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 { return n; }
    if n == 0 { return m; }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Verify bare function calls against SymbolCache.
/// General-purpose: catches hallucinated exported functions not in any
/// cached library. Only flags Capitalized names (Go exported convention).
pub fn verify_go_bare_functions(content: &str) -> Vec<String> {
    use std::collections::HashSet;
    use once_cell::sync::Lazy;

    static GO_BUILTINS: Lazy<HashSet<&str>> = Lazy::new(|| {
        ["Make", "New", "Len", "Cap", "Append", "Copy", "Delete",
         "Panic", "Recover", "Print", "Println", "Close", "Complex",
         "Real", "Imag", "Error", "Min", "Max", "Clear",
         "Assert", "Test", "Benchmark", "Example"]
        .iter().copied().collect()
    });

    let mut warnings = Vec::new();
    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return warnings,
    };

    // Collect user-defined function names from `func Name(` and `func (recv) Name(`.
    // These are local to the scanned code — must NOT be flagged as hallucinated.
    // Same pattern as Python's ApiKind::FunctionDef extraction.
    let func_def_re = regex::Regex::new(r"\bfunc\s+(?:\([^)]*\)\s+)?([A-Z]\w*)\s*\(").unwrap();
    let user_funcs: HashSet<String> = func_def_re.captures_iter(content)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();

    // Also collect Test* function names (Go test convention: func TestXxx(t *testing.T))
    let test_func_re = regex::Regex::new(r"\bfunc\s+(Test\w*)\s*\(").unwrap();
    let test_funcs: HashSet<String> = test_func_re.captures_iter(content)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();

    let bare_re = regex::Regex::new(r"(?:^|[^.\w])([A-Z]\w*)\s*\(").unwrap();
    // Package-qualified function calls: pkg.Func(args).
    // Common in Go — e.g. `protoimpl.Pointer(x)`, `fmt.Sprintf(...)`.
    // We verify Func against the cache; if not found in any library
    // matching the package, flag as hallucinated. This catches cases
    // like `protoimpl.WrapPointer(x)` (real: Pointer) that the bare_re
    // misses because Func is preceded by `.`.
    let pkg_re = regex::Regex::new(r"\b(\w+)\.([A-Z]\w*)\s*\(").unwrap();
    let mut checked: HashSet<String> = HashSet::new();

    for caps in bare_re.captures_iter(content) {
        let name = caps.get(1).unwrap().as_str();
        if !checked.insert(name.to_string()) { continue; }
        if GO_BUILTINS.contains(name) || name.len() < 3 { continue; }
        // Skip user-defined functions (func Name( declared in content).
        if user_funcs.contains(name) || test_funcs.contains(name) { continue; }
        // Skip Go test convention: TestXxx, BenchmarkXxx, FuzzXxx, ExampleXxx.
        // These are discovered by `go test`, never called directly in code.
        // Blanket skip avoids FPs when definition is in a prior response not
        // visible to the current scan (streaming tool-call JSON limitation).
        if (name.starts_with("Test") && name.len() > 4)
            || (name.starts_with("Benchmark") && name.len() > 9)
            || (name.starts_with("Fuzz") && name.len() > 4)
            || (name.starts_with("Example") && name.len() > 7)
        { continue; }
        // Skip SCREAMING_SNAKE_CASE constants.
        if name.len() >= 2
            && name.chars().all(|c| c.is_uppercase() || c == '_')
            && name.chars().filter(|c| c.is_uppercase()).count() >= 2
        { continue; }
        // Skip framework methods called bare (TableName, Migrate, etc.)
        // Use the unified is_go_framework_func_skip helper so user-provided
        // `extra_go_framework_funcs` config is honored (council A7).
        if is_go_framework_func_skip(name) { continue; }

        // Filter to Go-only libraries to prevent cross-language bleed.
        // Without this, a Rust library containing "WrapPointer" would mask
        // a Go hallucination of WrapPointer (real: Pointer).
        let has_go_match = cache.lookup_global(name).iter()
            .any(|s| crate::symbols::library_to_language(&s.library) == "go");
        if !has_go_match {
            // Search ALL symbols (functions + classes + types) for close
            // matches. The previous class-only search missed cases where
            // the closest real match is a free function (e.g. Go's
            // `WrapPointer` hallucination — closest match is a function,
            // not a class).
            //
            // Council cross-lang bleed fix (cf. cpp_introspect): filter
            // candidate matches to libraries classified as Go. Without
            // this, a Rust workspace's Wrap (in tokio) would mask a Go
            // hallucination of WrapPointer as "verified".
            let mut suggestion: Option<String> = None;
            for prefix_len in [4, 3] {
                if prefix_len > name.len() { continue; }
                let prefix: String = name.chars().take(prefix_len).collect();
                let candidates = cache.find_symbols_with_prefix(&prefix);
                let filtered = candidates.iter()
                    .filter(|(lib, _, _)| {
                        crate::symbols::library_to_language(lib) == "go"
                    })
                    .map(|(_, c, _)| c.clone())
                    .filter(|c| {
                        if c.len() < 3 { return false; }
                        let d = levenshtein(name, c);
                        let max_d = if name.len() <= 6 { 4 } else { name.len() / 3 + 2 };
                        d > 0 && d <= max_d
                    })
                    .min_by_key(|c| levenshtein(name, c));
                if let Some(s) = filtered {
                    suggestion = Some(s);
                    break;
                }
            }
            match suggestion {
                Some(s) => warnings.push(format!(
                    "hallucinated-function: `{}` — not in any cached library. Did you mean `{}`?", name, s)),
                None => warnings.push(format!(
                    "hallucinated-function: `{}` — not in any cached library", name)),
            }
        }
    }

    // Package-qualified function verification.
    // For `pkg.Func(args)`, look up Func as a symbol whose library starts
    // with the package name. If pkg is a known Go package alias (protoimpl,
    // fmt, etc.) and Func isn't in any matching library, flag with a
    // close-match suggestion.
    // Skip receiver-style patterns: only treat as package-qualified if pkg
    // is a known package alias (lowercase identifier matching a cached
    // library name). This avoids FPs on user variables like `client.Method()`.
    let known_pkgs: HashSet<&str> = HashSet::from([
        "fmt", "os", "io", "strings", "strconv", "time", "sync", "errors",
        "context", "reflect", "sort", "math", "bytes", "path", "filepath",
        "encoding", "json", "xml", "regexp", "net", "http", "rpc",
        "crypto", "hash", "testing", "log", "bufio", "unicode",
        "protoimpl", "protoreflect", "proto", "grpc", "protobuf",
        "prometheus", "jwt", "uuid", "viper", "cobra", "pflag",
        "redis", "mongo", "bson", "mysql", "sqlite3", "pq", "pgx",
        "gin", "echo", "fiber", "chi", "gorilla",
        "k8s", "clientgoscheme", "clientset", "kubernetes",
        "dapr", "proto", "twilio", "stripe",
    ]);

    for caps in pkg_re.captures_iter(content) {
        let pkg = caps.get(1).unwrap().as_str();
        let func = caps.get(2).unwrap().as_str();
        if !known_pkgs.contains(pkg) { continue; }
        let key = format!("{}.{}", pkg, func);
        if !checked.insert(key) { continue; }
        if GO_BUILTINS.contains(func) || func.len() < 3 { continue; }

        // Skip common Go stdlib functions — these are always real, but the
        // symbol cache doesn't include Go stdlib (it's not a "package" you
        // fetch). Without this, json.Marshal/bytes.NewReader/etc. get
        // flagged as hallucinated on every Go benchmark.
        static GO_STDLIB_FUNCS: Lazy<HashSet<&str>> = Lazy::new(|| {
            [
                // encoding/json
                "Marshal", "Unmarshal", "NewEncoder", "NewDecoder", "Compact", "Indent", "Valid", "HTMLEscape",
                "RawMessage", "Number", "Delim", "Token", "Decoder", "Encoder",
                // bytes
                "NewReader", "NewBuffer", "Compare", "Equal", "Index", "Contains", "HasPrefix", "HasSuffix", "Count", "Repeat", "Replace", "Split", "Join", "TrimPrefix", "TrimSuffix", "ToLower", "ToUpper", "Title", "Buffer", "Reader", "MinRead",
                // filepath
                "Join", "Base", "Dir", "Ext", "Clean", "Abs", "Rel", "Walk", "Glob", "Match", "Split", "FromSlash", "ToSlash", "WalkDir", "ErrBadPattern", "Separator",
                // strconv
                "ParseUint", "ParseInt", "ParseFloat", "ParseBool", "Atoi", "Itoa", "FormatUint", "FormatInt", "FormatFloat", "Quote", "Unquote", "AppendInt", "AppendUint", "NumError", "ErrRange", "ErrSyntax",
                // fmt
                "Printf", "Sprintf", "Println", "Errorf", "Fprintf", "Scanf", "Sscanf", "Fscan", "Sscan", "Stringer", "GoStringer", "Formatter", "ScanState", "Scanln", "Sprintln",
                // strings (same as bytes + these)
                "NewReader", "NewReplacer", "Builder", "Reader", "Replacer",
                // net/http
                "NewRequest", "Get", "Post", "Head", "Handle", "HandleFunc", "ListenAndServe", "ListenAndServeTLS", "Error", "NotFound", "Redirect", "SetCookie", "SetHeader", "Request", "Response", "Client", "Server", "Handler", "HandlerFunc", "Header", "Cookie", "ServeMux",
        "HandleFunc", "Handle", "ListenAndServe", "ListenAndServeTLS",
        "Serve", "ServeTLS", "Set", "Add", "Del", "Get", "Has", "Transport", "RoundTripper", "Flusher", "Hijacker", "Pusher",
                // sync
                "NewMutex", "NewWaitGroup", "NewOnce", "NewCond", "NewMap", "Mutex", "RWMutex", "WaitGroup", "Once", "Cond", "Map", "Pool", "Locker",
                // context
                "Background", "TODO", "WithCancel", "WithDeadline", "WithTimeout", "WithValue", "Context", "CancelFunc",
                // errors
                "New", "Is", "As", "Unwrap", "Join",
            ]
            .iter().copied().collect()
        });
        // Framework-specific functions (gin, GORM). Separated from stdlib
        // per council #3 finding #7 — these are third-party, not stdlib.
        // Blanket-skipping generic verbs (Find, Where, Count) for ANY receiver
        // is the SOURCES_OF_TRUTH.md anti-pattern. Scoped to known framework
        // packages only.
        //
        // Built-in static sets + user-provided config are unified via
        // is_go_framework_pkg_skip / is_go_framework_func_skip helpers
        // (council A7).
        // Stdlib funcs: skip for any known stdlib package.
        if known_pkgs.contains(pkg) && GO_STDLIB_FUNCS.contains(func) { continue; }
        // Framework funcs: skip ONLY when receiver package is a known framework.
        if is_go_framework_pkg_skip(pkg) && is_go_framework_func_skip(func) { continue; }

        // Look up func as a symbol whose library matches this package.
        // Accept library names like `go.{pkg}` or `{pkg}` or `go.{pkg}.*`.
        let cache_match = cache.lookup_global(func);
        let in_pkg = cache_match.iter().any(|s| {
            s.library == pkg
                || s.library == format!("go.{}", pkg)
                || s.library.starts_with(&format!("{}.", pkg))
                || s.library.starts_with(&format!("go.{}.", pkg))
        });
        if in_pkg { continue; }

        // Hallucinated (or at least not in our cache for this pkg).
        // Search ALL symbols for close matches to power a suggestion.
        // Gate: only warn if a close-match suggestion exists. This prevents
        // FPs on real-but-uncached package functions (e.g. protoimpl.EnforceVersion
        // is real but not in our bundle — without this gate we'd flag it).
        //
        // Cross-lang bleed fix (cf. bare-function branch above): filter
        // candidates to libraries classified as Go.
        let mut suggestion: Option<String> = None;
        for prefix_len in [4, 3] {
            if prefix_len > func.len() { continue; }
            let prefix: String = func.chars().take(prefix_len).collect();
            let candidates = cache.find_symbols_with_prefix(&prefix);
            let filtered = candidates.iter()
                .filter(|(lib, _, _)| {
                    crate::symbols::library_to_language(lib) == "go"
                })
                .map(|(_, c, _)| c.clone())
                .filter(|c| {
                    if c.len() < 3 { return false; }
                    let d = levenshtein(func, c);
                    let max_d = if func.len() <= 6 { 4 } else { func.len() / 3 + 2 };
                    d > 0 && d <= max_d
                })
                .min_by_key(|c| levenshtein(func, c));
            if let Some(s) = filtered {
                suggestion = Some(s);
                break;
            }
        }
        if let Some(s) = suggestion {
            warnings.push(format!(
                "hallucinated-function: `{}.{}` — not exported from cached `{}` package. Did you mean `{}`?", pkg, func, pkg, s));
        }
    }
    warnings
}

// ── pkg.go.dev live API integration for Go import symbol verification ────
//
// Constraint #8: source of truth = live APIs, never hardcoded data. Symbol
// data for Go packages MUST come from pkg.go.dev (the canonical Go package
// documentation service). Never hand-code symbol entries.
//
// Cascade:
//   1. Parse Go imports (single + block forms, with aliases)
//   2. For each import that resolved Verified on proxy.golang.org,
//      fetch `https://pkg.go.dev/{import_path}` HTML
//   3. Parse exported package symbols from HTML (functions, types, methods)
//   4. Cross-check `alias.Symbol` usages in code against parsed exports
//   5. Cache parsed exports in GO_TYPE_CACHE keyed (import_path, "*")
//
// Pattern: introspect_java_type() — reqwest 10s timeout + JAVA_TYPE_CACHE.
// We reuse GO_TYPE_CACHE for package-level lookups via the "*" type_name
// sentinel, which never collides with type-specific keys (package, TypeName).

/// Parse Go imports from source — both single `import "X"` and block
/// `import (...)` forms, including aliased imports
/// (`alias "github.com/x/y"`).
///
/// Returns `(alias, import_path)` pairs. The default alias is the last
/// path segment (e.g. `golang.org/x/term` → `term`). Dot-imports
/// (`. "fmt"`) and blank-imports (`_ "fmt"`) are excluded — they don't
/// introduce a usable alias for `alias.Symbol` lookup.
pub(crate) fn parse_go_imports(content: &str) -> Vec<(String, String)> {
    let mut imports = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Block form: import ( ... ) — extract every "path" inside.
    let block_re = regex::Regex::new(r"(?s)import\s*\(([^)]*)\)").unwrap();
    let line_re = regex::Regex::new(
        r#"(?m)^\s*(?:(\w+)\s+)?"([^"]+)"\s*(?://.*)?$"#
    ).unwrap();

    for caps in block_re.captures_iter(content) {
        let block = caps.get(1).unwrap().as_str();
        for line_cap in line_re.captures_iter(block) {
            let alias_tok = line_cap.get(1).map(|m| m.as_str());
            let path = line_cap.get(2).unwrap().as_str().to_string();
            // Dot/underscore imports don't introduce a usable alias.
            if matches!(alias_tok, Some(".") | Some("_")) { continue; }
            if !seen.insert(path.clone()) { continue; }
            let alias = alias_tok
                .map(|s| s.to_string())
                .unwrap_or_else(|| default_go_alias(&path));
            imports.push((alias, path));
        }
    }

    // Single form: import [alias] "path" — strip blocks first so the
    // single-form regex can't re-match paths already extracted above.
    let stripped = block_re.replace_all(content, " ");
    let single_re = regex::Regex::new(
        r#"import\s+(?:(\w+)\s+)?"([^"]+)""#
    ).unwrap();
    for caps in single_re.captures_iter(&stripped) {
        let alias_tok = caps.get(1).map(|m| m.as_str());
        let path = caps.get(2).unwrap().as_str().to_string();
        if matches!(alias_tok, Some(".") | Some("_")) { continue; }
        if !seen.insert(path.clone()) { continue; }
        let alias = alias_tok
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_go_alias(&path));
        imports.push((alias, path));
    }

    imports
}

/// Default Go alias = last path segment.
/// `golang.org/x/term` → `term`
/// `github.com/prometheus/client_golang/prometheus` → `prometheus`
fn default_go_alias(path: &str) -> String {
    path.split('/').last().unwrap_or(path).to_string()
}

/// Introspect a Go package's exported symbols via pkg.go.dev HTTP.
///
/// Cache key: `(import_path, "*")` — the `"*"` sentinel denotes package-level
/// symbols (functions, types, methods) as opposed to type-specific methods
/// cached under `(package, type_name)` by `introspect_go_type`.
///
/// On fetch failure or empty parse: returns ModuleInfo with `error` set and
/// empty `names`. Caller MUST check `error.is_some()` before flagging
/// hallucinations — conservative bias to avoid FPs when data is missing.
pub async fn introspect_go_package(import_path: &str) -> ModuleInfo {
    let key = (import_path.to_string(), "*".to_string());

    {
        let cache = GO_TYPE_CACHE.lock().await;
        if let Some(info) = cache.get(&key) {
            return info.clone();
        }
    }

    let start = std::time::Instant::now();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("anubis-go-introspect/0.1")
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return ModuleInfo {
                module: import_path.to_string(),
                names: vec![],
                error: Some("client build failed".to_string()),
                latency_ms: 0,
            };
        }
    };

    let url = format!("https://pkg.go.dev/{}", import_path);
    let resp = client.get(&url).send().await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let info = match resp {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            let names = parse_pkg_go_dev_symbols(&body);
            if names.is_empty() {
                // Page fetched but no symbols parsed — either an error page,
                // a redirect stub, or HTML structure changed. Treat as error
                // to avoid false-positive hallucination flags.
                ModuleInfo {
                    module: import_path.to_string(),
                    names: vec![],
                    error: Some("pkg.go.dev returned no parseable symbols".to_string()),
                    latency_ms,
                }
            } else {
                ModuleInfo {
                    module: import_path.to_string(),
                    names,
                    error: None,
                    latency_ms,
                }
            }
        }
        _ => ModuleInfo {
            module: import_path.to_string(),
            names: vec![],
            error: Some("pkg.go.dev fetch failed".to_string()),
            latency_ms,
        },
    };

    let mut cache = GO_TYPE_CACHE.lock().await;
    cache.insert(key, info.clone());
    info
}

/// Parse exported symbols from pkg.go.dev HTML.
///
/// pkg.go.dev renders symbol anchors as:
///   <a href="#FuncName" ...>FuncName(args)</a>           (functions)
///   <a href="#TypeName" title="type TypeName">...</a>    (types)
///   <a href="#ReceiverType.Method" ...>...</a>           (methods)
///
/// The href value is the canonical Go identifier. We extract the trailing
/// segment (after `.`) so `Terminal.ReadLine` → `ReadLine`. Section
/// anchors like `#pkg-overview`, `#section-documentation` start with
/// lowercase — filtered by requiring uppercase first letter (Go exported
/// convention).
fn parse_pkg_go_dev_symbols(html: &str) -> Vec<String> {
    let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();

    let re = regex::Regex::new(
        r##"href="#(?:[a-zA-Z0-9_]+\.)?([A-Z][A-Za-z0-9_]*)""##
    ).unwrap();
    for caps in re.captures_iter(html) {
        let name = caps.get(1).unwrap().as_str();
        if name.len() >= 2 {
            names.insert(name.to_string());
        }
    }

    let mut v: Vec<String> = names.into_iter().collect();
    v.sort();
    v
}

/// Verify Go import symbols against pkg.go.dev live exports.
///
/// For each Go import that resolved Verified on the Go proxy, fetches the
/// pkg.go.dev package page and parses exported symbols. Cross-checks
/// `alias.Symbol` usages in the code against the parsed exports.
///
/// Returns warnings for symbols not found in the package's exports.
/// Empty result on: no imports, no Verified imports, fetch failure, or
/// every import's fetch failing (conservative — avoid FPs when data missing).
pub async fn verify_go_import_symbols(content: &str) -> Vec<String> {
    use crate::scanner::package_index::{verify_import_with_language, ImportStatus};

    let mut warnings = Vec::new();
    let imports = parse_go_imports(content);
    if imports.is_empty() {
        return warnings;
    }

    // Build alias → import_path map (first-write-wins).
    let mut alias_to_path: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (alias, path) in &imports {
        alias_to_path
            .entry(alias.clone())
            .or_insert_with(|| path.clone());
    }

    // Determine which import paths resolved Verified on the proxy. Only
    // verified paths warrant a pkg.go.dev fetch — saves HTTP quota and
    // skips stdlib (which has no domain in the first segment).
    let mut verified_paths: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, path) in &imports {
        if verified_paths.contains(path) {
            continue;
        }
        let first_seg = path.split('/').next().unwrap_or("");
        if !first_seg.contains('.') {
            continue;
        }
        let status = verify_import_with_language("go", path).await;
        if status == ImportStatus::Verified {
            verified_paths.insert(path.clone());
        }
    }
    if verified_paths.is_empty() {
        return warnings;
    }

    // Fetch pkg.go.dev exports for each verified path concurrently.
    let mut tasks: Vec<tokio::task::JoinHandle<(String, ModuleInfo)>> = Vec::new();
    for path in verified_paths {
        let p = path.clone();
        tasks.push(tokio::spawn(async move {
            let info = introspect_go_package(&p).await;
            (p, info)
        }));
    }

    let mut pkg_exports: std::collections::HashMap<String, ModuleInfo> =
        std::collections::HashMap::new();
    for handle in tasks {
        match handle.await {
            Ok((path, info)) if info.error.is_none() => {
                pkg_exports.insert(path, info);
            }
            _ => {}
        }
    }
    if pkg_exports.is_empty() {
        return warnings;
    }

    // Cross-check `alias.Symbol` patterns against cached exports.
    // Matches both call sites (`alias.Func(`) and value references
    // (`alias.Type`, `alias.Const`) — pkg.go.dev lists all of these
    // as href anchors, so a single check covers every usage shape.
    let symbol_re = regex::Regex::new(
        r"(?:^|[^a-zA-Z0-9_])([a-zA-Z_]\w*)\.([A-Z][A-Za-z0-9_]*)"
    ).unwrap();
    let mut checked: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    for caps in symbol_re.captures_iter(content) {
        let alias = caps.get(1).unwrap().as_str().to_string();
        let symbol = caps.get(2).unwrap().as_str().to_string();

        if !checked.insert((alias.clone(), symbol.clone())) {
            continue;
        }
        if symbol.len() < 3 {
            continue;
        }

        let path = match alias_to_path.get(&alias) {
            Some(p) => p.clone(),
            None => continue,
        };
        let info = match pkg_exports.get(&path) {
            Some(i) => i,
            None => continue,
        };

        // Skip SCREAMING_SNAKE_CASE constants — pkg.go.dev lists these
        // under section anchors (`#pkg-constants`), not per-symbol hrefs,
        // so they wouldn't appear in parsed exports. Same FP-avoidance
        // pattern as verify_go_bare_functions.
        if symbol.len() >= 2
            && symbol.chars().all(|c| c.is_uppercase() || c == '_')
            && symbol.chars().filter(|c| c.is_uppercase()).count() >= 2
        {
            continue;
        }

        // Skip framework method names (gin/gorm/etc.) — same gate as
        // verify_go_bare_functions. Honors user-configured
        // extra_go_framework_funcs via the unified helper.
        if is_go_framework_func_skip(&symbol) {
            continue;
        }

        if !info.exists(&symbol) {
            match info.closest_match(&symbol) {
                Some(suggestion) => warnings.push(format!(
                    "hallucinated-import-symbol: `{}.{}` — `{}` not exported by `{}`. Did you mean `{}`?",
                    alias, symbol, symbol, path, suggestion
                )),
                None => warnings.push(format!(
                    "hallucinated-import-symbol: `{}.{}` — `{}` not exported by `{}`",
                    alias, symbol, symbol, path
                )),
            }
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_go_receiver_map_catches_var_decl() {
        let content = "var resp http.Response";
        let map = build_go_receiver_map(content);
        let entry = map.get("resp").unwrap();
        assert_eq!(entry.0, "http");
        assert_eq!(entry.1, "Response");
    }

    #[test]
    fn build_go_receiver_map_catches_struct_literal() {
        let content = "cfg := config.Server{Port: 8080}";
        let map = build_go_receiver_map(content);
        let entry = map.get("cfg").unwrap();
        assert_eq!(entry.0, "config");
        assert_eq!(entry.1, "Server");
    }

    #[test]
    fn build_go_receiver_map_catches_constructor() {
        let content = "client := http.NewClient()";
        let map = build_go_receiver_map(content);
        let entry = map.get("client").unwrap();
        assert_eq!(entry.0, "http");
        assert_eq!(entry.1, "Client");
    }

    #[test]
    fn parse_go_doc_methods_extracts_method_names() {
        let doc = "package http\n\nfunc (r *Response) Body() io.ReadCloser\nfunc (r *Response) StatusCode() int\n";
        let methods = parse_go_doc_methods(doc, "Response");
        assert!(methods.contains(&"Body".to_string()));
        assert!(methods.contains(&"StatusCode".to_string()));
    }

    #[test]
    fn parse_go_doc_methods_skips_unrelated() {
        let doc = "func NewRequest(method string) *Request\nfunc (r *Request) Method() string\n";
        let methods = parse_go_doc_methods(doc, "Response");
        assert!(methods.is_empty());
    }

    #[test]
    fn build_go_receiver_map_catches_method_factory() {
        // protoimpl.X.MessageStateOf(...) — derived type "MessageState"
        let content = "ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))";
        let map = build_go_receiver_map(content);
        let entry = map.get("ms").expect("ms should be in receiver_map");
        assert_eq!(entry.0, "protoimpl");
        assert_eq!(entry.1, "MessageState");
    }

    #[test]
    fn build_go_receiver_map_catches_factory_func_of() {
        let content = "v := reflect.ValueOf(x)";
        let map = build_go_receiver_map(content);
        // ValueOf → Value
        let entry = map.get("v").expect("v should be in receiver_map");
        assert_eq!(entry.0, "reflect");
        assert_eq!(entry.1, "Value");
    }

    #[test]
    fn build_go_receiver_map_catches_factory_func_new() {
        let content = "client := http.NewClient()";
        let map = build_go_receiver_map(content);
        // ctor_re: NewClient → Client
        let entry = map.get("client").expect("client should be in receiver_map");
        assert_eq!(entry.0, "http");
        assert_eq!(entry.1, "Client");
    }

    #[test]
    fn build_go_receiver_map_catches_factory_func_build() {
        let content = "req := http.BuildRequest()";
        let map = build_go_receiver_map(content);
        let entry = map.get("req").expect("req should be in receiver_map");
        assert_eq!(entry.0, "http");
        assert_eq!(entry.1, "Request");
    }

    #[test]
    fn derive_type_strips_of_suffix() {
        assert_eq!(derive_type_from_func("MessageStateOf"), Some("MessageState".to_string()));
        assert_eq!(derive_type_from_func("ValueOf"), Some("Value".to_string()));
        assert_eq!(derive_type_from_func("TypeOf"), Some("Type".to_string()));
    }

    #[test]
    fn derive_type_strips_new_prefix() {
        assert_eq!(derive_type_from_func("NewClient"), Some("Client".to_string()));
        assert_eq!(derive_type_from_func("BuildRequest"), Some("Request".to_string()));
    }

    #[test]
    fn derive_type_returns_none_for_unknown() {
        assert_eq!(derive_type_from_func("RandomFunc"), None);
        assert_eq!(derive_type_from_func("Do"), None);  // too short after strip
    }

    #[test]
    fn is_go_framework_pkg_skip_recognises_builtins() {
        // Sanity: built-in static set still resolves after helpers introduced.
        assert!(is_go_framework_pkg_skip("gin"));
        assert!(is_go_framework_pkg_skip("gorm"));
        assert!(is_go_framework_pkg_skip("echo"));
        assert!(is_go_framework_pkg_skip("fiber"));
        assert!(is_go_framework_pkg_skip("chi"));
        assert!(is_go_framework_pkg_skip("gorilla"));
        assert!(is_go_framework_pkg_skip("mux"));
    }

    #[test]
    fn is_go_framework_pkg_skip_rejects_unknown() {
        assert!(!is_go_framework_pkg_skip("totally_unknown_pkg"));
        assert!(!is_go_framework_pkg_skip(""));
        assert!(!is_go_framework_pkg_skip("net/http"));
    }

    #[test]
    fn is_go_framework_func_skip_recognises_builtins() {
        // gin middleware + HTTP verbs
        assert!(is_go_framework_func_skip("Recovery"));
        assert!(is_go_framework_func_skip("Logger"));
        assert!(is_go_framework_func_skip("GET"));
        assert!(is_go_framework_func_skip("POST"));
        // GORM methods
        assert!(is_go_framework_func_skip("TableName"));
        assert!(is_go_framework_func_skip("AutoMigrate"));
        assert!(is_go_framework_func_skip("Where"));
    }

    #[test]
    fn is_go_framework_func_skip_rejects_unknown() {
        assert!(!is_go_framework_func_skip("totally_unknown_func"));
        assert!(!is_go_framework_func_skip(""));
    }

    #[test]
    fn set_extra_go_framework_extends_lists_first_write_wins() {
        // OnceCell semantics: first call wins. Use unique markers to avoid
        // colliding with other tests that might call set_.
        let pkg_marker = "anubis_a7_go_pkg_marker_xyz";
        let func_marker = "anubis_a7_go_func_marker_xyz";
        super::set_extra_go_framework(
            vec![pkg_marker.to_string()],
            vec![func_marker.to_string()],
        );
        assert!(
            is_go_framework_pkg_skip(pkg_marker),
            "user-provided extra_go_framework_pkgs should be honored"
        );
        assert!(
            is_go_framework_func_skip(func_marker),
            "user-provided extra_go_framework_funcs should be honored"
        );
        // Second call should NOT overwrite (OnceCell first-write-wins).
        super::set_extra_go_framework(
            vec!["anubis_a7_go_second_pkg".to_string()],
            vec!["anubis_a7_go_second_func".to_string()],
        );
        assert!(
            is_go_framework_pkg_skip(pkg_marker),
            "OnceCell first-write-wins: original pkg marker should still be present"
        );
        assert!(
            is_go_framework_func_skip(func_marker),
            "OnceCell first-write-wins: original func marker should still be present"
        );
    }

    #[test]
    fn parse_go_imports_block_form() {
        let content = r#"
import (
    "fmt"
    "os"

    colorable "github.com/mattn/go-colorable"
    "golang.org/x/term"
)
"#;
        let imports = parse_go_imports(content);
        let map: std::collections::HashMap<&str, &str> = imports
            .iter()
            .map(|(a, p)| (a.as_str(), p.as_str()))
            .collect();
        assert_eq!(map.get("fmt"), Some(&"fmt"));
        assert_eq!(map.get("os"), Some(&"os"));
        assert_eq!(map.get("colorable"), Some(&"github.com/mattn/go-colorable"));
        assert_eq!(map.get("term"), Some(&"golang.org/x/term"));
    }

    #[test]
    fn parse_go_imports_single_form() {
        let content = r#"import "fmt"
import alias "github.com/x/y"
"#;
        let imports = parse_go_imports(content);
        let map: std::collections::HashMap<&str, &str> = imports
            .iter()
            .map(|(a, p)| (a.as_str(), p.as_str()))
            .collect();
        assert_eq!(map.get("fmt"), Some(&"fmt"));
        assert_eq!(map.get("alias"), Some(&"github.com/x/y"));
    }

    #[test]
    fn parse_go_imports_skips_dot_and_blank() {
        let content = r#"
import (
    . "fmt"
    _ "github.com/some/sideeffect"
    real "github.com/x/real"
)
"#;
        let imports = parse_go_imports(content);
        // Only the explicit alias should be present.
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].0, "real");
        assert_eq!(imports[0].1, "github.com/x/real");
    }

    #[test]
    fn default_go_alias_uses_last_segment() {
        assert_eq!(default_go_alias("golang.org/x/term"), "term");
        assert_eq!(
            default_go_alias("github.com/prometheus/client_golang/prometheus"),
            "prometheus"
        );
        assert_eq!(default_go_alias("fmt"), "fmt");
    }

    #[test]
    fn parse_pkg_go_dev_symbols_extracts_anchors() {
        let html = r##"
<html>
<body>
<li><a href="#IsTerminal" title="IsTerminal(fd)">IsTerminal(fd)</a></li>
<li><a href="#GetSize" title="GetSize(fd)">GetSize(fd)</a></li>
<li><a href="#ReadPassword">ReadPassword(fd)</a></li>
<li><a href="#State" title="type State">type State</a></li>
<li><a href="#Terminal" title="type Terminal">type Terminal</a></li>
<li><a href="#Terminal.ReadLine" title="(t) ReadLine()">ReadLine()</a></li>
<li><a href="#Terminal.ReadPassword" title="(t) ReadPassword()">ReadPassword()</a></li>
<li><a href="#pkg-overview">Overview</a></li>
<li><a href="#section-documentation">Documentation</a></li>
<li><a href="#main-content">Main</a></li>
</body>
</html>
"##;
        let names = parse_pkg_go_dev_symbols(html);
        // Functions and types captured.
        assert!(names.contains(&"IsTerminal".to_string()));
        assert!(names.contains(&"GetSize".to_string()));
        assert!(names.contains(&"ReadPassword".to_string()));
        assert!(names.contains(&"State".to_string()));
        assert!(names.contains(&"Terminal".to_string()));
        // Methods captured by their trailing segment.
        assert!(names.contains(&"ReadLine".to_string()));
        // Section anchors filtered (lowercase prefix).
        assert!(!names.iter().any(|n| n.contains("overview")));
        assert!(!names.iter().any(|n| n.contains("section")));
        assert!(!names.iter().any(|n| n.contains("main")));
    }

    #[test]
    fn parse_pkg_go_dev_symbols_returns_empty_on_no_anchors() {
        let html = "<html><body><h1>404 not found</h1></body></html>";
        let names = parse_pkg_go_dev_symbols(html);
        assert!(names.is_empty());
    }

    #[tokio::test]
    async fn verify_go_import_symbols_returns_empty_when_no_imports() {
        let content = "package main\n\nfunc main() { fmt.Println(\"hi\") }";
        let warnings = verify_go_import_symbols(content).await;
        assert!(warnings.is_empty());
    }

    #[tokio::test]
    async fn verify_go_import_symbols_returns_empty_when_only_stdlib() {
        // Stdlib imports have no domain in first segment → proxy won't
        // verify → no pkg.go.dev fetch → no warnings.
        let content = r#"package main

import (
    "fmt"
    "os"
)

func main() { fmt.Println("hi") }
"#;
        let warnings = verify_go_import_symbols(content).await;
        assert!(warnings.is_empty());
    }
}
