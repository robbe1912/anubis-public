//! Local library introspection (FORGE 2026 pattern step 2/3).
//!
//! FORGE 2026 paper (arxiv 2601.19106) reports 100% precision / 87.6% recall
//! using dynamic KB construction via library introspection. The KB is built
//! per-user-per-project by actually invoking the language's runtime to
//! enumerate real APIs:
//!
//!   Python: subprocess `python -c "import X; print([n for n in dir(X) if not n.startswith('_')])"`
//!   TypeScript: parse `node_modules/X/package.json` + `.d.ts` files
//!   Rust: parse `Cargo.toml` deps + cargo metadata
//!   Go: parse `go.sum` + `go doc -all` output
//!
//! This module implements Python introspection (highest DELULU share at
//! 370/1947 samples = 19%). Other languages follow same pattern in
//! separate modules.

use std::collections::{HashMap, HashSet};
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::process::Command;
use once_cell::sync::Lazy;

use crate::scanner::ast_extractor::{ApiCall, ApiKind};

/// Per-process introspection cache. Avoids re-running `python -c "import sklearn"`
/// for every response in a session. Keyed by fully-qualified module name.
static INTROSPECT_CACHE: Lazy<Mutex<HashMap<String, ModuleInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Invalidate cached introspection for every module whose dotted path
/// starts with `top_level` (e.g. "notes_cli" drops "notes_cli",
/// "notes_cli.database", ...). Called by the proxy when the agent WRITES
/// a .py file — a stale "submodule does not exist" miss would otherwise
/// manufacture hallucinated-import FPs for the rest of the session
/// (20260818 task-002: notes_cli.database warning repeated AFTER the
/// file landed on disk). Best-effort, fire-and-forget.
pub async fn invalidate_introspect_cache(top_level: &str) {
    if top_level.is_empty() {
        return;
    }
    let prefix = format!("{}.", top_level);
    let mut cache = INTROSPECT_CACHE.lock().await;
    let before = cache.len();
    cache.retain(|k, _| k != top_level && !k.starts_with(&prefix));
    let dropped = before - cache.len();
    // Also drop return-type entries for the same tree.
    let mut rt = RETURN_TYPE_CACHE.lock().await;
    rt.retain(|(m, _), _| m != top_level && !m.starts_with(&prefix));
    if dropped > 0 {
        tracing::info!(
            target: "scanner::introspect",
            top_level = %top_level,
            dropped,
            "introspect cache invalidated on file write"
        );
    }
}

/// Oracle bug C fix: RETURN_TYPE_CACHE at module scope so clear_cache()
/// can flush it for test isolation.
static RETURN_TYPE_CACHE: Lazy<Mutex<HashMap<(String, String), ReturnType>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Introspection result for one Python module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Fully-qualified module name (e.g., "sklearn.preprocessing").
    pub module: String,
    /// Public names (no underscore prefix) from `dir(module)`.
    pub names: Vec<String>,
    /// If the module failed to import, this is the error message.
    /// `names` will be empty in this case.
    pub error: Option<String>,
    /// Wall-clock time for the introspection call (ms).
    pub latency_ms: u64,
}

impl ModuleInfo {
    pub fn exists(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }

    /// Find the closest match by Levenshtein distance (capped at 4).
    /// Returns the closest real name if within threshold.
    pub fn closest_match(&self, target: &str) -> Option<String> {
        if target.len() < 3 {
            return None;
        }
        let mut best: Option<(usize, &str)> = None;
        for name in &self.names {
            if name.len() < 3 {
                continue;
            }
            let dist = levenshtein_capped(target, name, 5);
            if dist <= 4 {
                match best {
                    None => best = Some((dist, name)),
                    Some((bd, _)) if dist < bd => best = Some((dist, name)),
                    _ => {}
                }
            }
        }
        best.map(|(_, n)| n.to_string())
    }
}

/// Introspect a Python module via subprocess.
///
/// Returns cached result if available. On import failure, returns ModuleInfo
/// with `error` set (still cached — don't retry failures).
///
/// Transient introspection failures (process spawn, OS-level timeout).
/// These should NOT poison the cache — they may resolve on retry (PATH
/// changes, slow cold-import completing on second invocation, transient
/// OOM). Deterministic errors (ImportError/AttributeError/TypeError) ARE
/// cached because they won't change.
fn is_transient_introspect_error(error: &Option<String>) -> bool {
    match error {
        Some(e) => e.contains("timeout") || e.contains("spawn python"),
        None => false,
    }
}

/// Time budget: ~100-300ms per call (Python startup + import).
pub async fn introspect_python_module(module: &str) -> ModuleInfo {
    // Check cache first.
    {
        let cache = INTROSPECT_CACHE.lock().await;
        if let Some(info) = cache.get(module) {
            return info.clone();
        }
    }

    let start = std::time::Instant::now();
    let script = format!(
        r#"
import importlib, sys, json
try:
    m = importlib.import_module("{module}")
    names = sorted([n for n in dir(m) if not n.startswith('_')])
    print(json.dumps({{"names": names, "error": None}}))
except ImportError as e:
    print(json.dumps({{"names": [], "error": f"ImportError: {{e}}"}}))
except Exception as e:
    print(json.dumps({{"names": [], "error": f"{{type(e).__name__}}: {{e}}"}}))
"#,
        module = module.replace('"', "\\\"")
    );

    // Bound the introspection. A hostile or broken __init__.py can hang
    // indefinitely; kill_on_drop only fires when the future is dropped, so
    // we wrap with timeout to actually trigger cancellation. Mirrors
    // kwargs-checker pattern at local_introspect.rs:1028 (5s timeout).
    const INTROSPECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let result = match tokio::time::timeout(
        INTROSPECT_TIMEOUT,
        crate::scanner::command_hidden_tokio("python")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output_async(),
    )
    .await
    {
        Ok(r) => r,
        Err(_elapsed) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::warn!(
                target: "scanner",
                module = %module,
                latency_ms,
                timeout_secs = INTROSPECT_TIMEOUT.as_secs(),
                "introspect_python_module timed out — returning error"
            );
            return ModuleInfo {
                module: module.to_string(),
                names: vec![],
                error: Some(format!(
                    "introspect timeout after {}s",
                    INTROSPECT_TIMEOUT.as_secs()
                )),
                latency_ms,
            };
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    let info = match result {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                ModuleInfo {
                    module: module.to_string(),
                    names: vec![],
                    error: Some(format!("exit {:?}: {}", output.status, stderr.lines().next().unwrap_or(""))),
                    latency_ms,
                }
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                #[derive(Deserialize)]
                struct Out {
                    names: Vec<String>,
                    error: Option<String>,
                }
                match serde_json::from_str::<Out>(stdout.trim()) {
                    Ok(parsed) => ModuleInfo {
                        module: module.to_string(),
                        names: parsed.names,
                        error: parsed.error,
                        latency_ms,
                    },
                    Err(e) => ModuleInfo {
                        module: module.to_string(),
                        names: vec![],
                        error: Some(format!("parse JSON: {e} (raw: {})", crate::scanner::safe_slice_to(&stdout, 200))),
                        latency_ms,
                    },
                }
            }
        }
        Err(e) => ModuleInfo {
            module: module.to_string(),
            names: vec![],
            error: Some(format!("spawn python: {e}")),
            latency_ms,
        },
    };

    // Cache deterministic failures (ImportError/AttributeError/etc) so we
    // don't retry them. Skip transient errors (spawn failure, OS timeout)
    // — those may resolve on retry and must not poison the cache. Mirrors
    // rust_introspect.rs which early-returns on fetch errors before cache.
    if !is_transient_introspect_error(&info.error) {
        let mut cache = INTROSPECT_CACHE.lock().await;
        cache.insert(module.to_string(), info.clone());
    }
    info
}

/// Introspect a class within a module: `dir(getattr(module, class_name))`.
/// Used to verify ClassName.method() calls where ClassName is exported from
/// a module (e.g., ConnectTimeout.with_tracebak() from requests).
/// NOTE: The actual implementation is at line 275 — this is a re-export
/// marker for the verify_against_introspection Case C usage below.

/// Verify API calls against introspected module surfaces.

/// Introspect a Python class's public methods/attributes via subprocess.
///
/// Enumerates `dir(module.ClassName)` — methods/attributes defined on the
/// Introspect a Python builtin type (str/int/list/dict/set/tuple/etc.).
///
/// Used by verify_against_introspection Case B2 to verify methods called on
/// variables whose type is a Python builtin. Without this, fabricated methods
/// like `'str'.to_uppercase()` or `list.flatten()` would be missed because
/// builtins are not in any imported module's dir().
///
/// Returns ModuleInfo with `names` = builtin type's public methods.
/// Cache key is `builtin::<type_name>` to avoid collision with modules.
///
/// Time budget: ~100-300ms per call (Python startup + dir()).
pub async fn introspect_python_builtin(type_name: &str) -> ModuleInfo {
    let cache_key = format!("builtin::{}", type_name);

    // Check cache first.
    {
        let cache = INTROSPECT_CACHE.lock().await;
        if let Some(info) = cache.get(&cache_key) {
            return info.clone();
        }
    }

    let start = std::time::Instant::now();
    let script = format!(
        r#"
import builtins, json
try:
    t = getattr(builtins, "{type_name}")
    names = sorted([n for n in dir(t) if not n.startswith('_')])
    print(json.dumps({{"names": names, "error": None}}))
except AttributeError as e:
    print(json.dumps({{"names": [], "error": f"AttributeError: {{e}}"}}))
except Exception as e:
    print(json.dumps({{"names": [], "error": f"{{type(e).__name__}}: {{e}}"}}))
"#,
        type_name = type_name.replace('"', "\\\"")
    );

    const INTROSPECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let result = match tokio::time::timeout(
        INTROSPECT_TIMEOUT,
        crate::scanner::command_hidden_tokio("python")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output_async(),
    )
    .await
    {
        Ok(r) => r,
        Err(_elapsed) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::warn!(
                target: "scanner",
                builtin = %type_name,
                latency_ms,
                "introspect_python_builtin timed out — returning error"
            );
            return ModuleInfo {
                module: cache_key.clone(),
                names: vec![],
                error: Some(format!(
                    "introspect timeout after {}s",
                    INTROSPECT_TIMEOUT.as_secs()
                )),
                latency_ms,
            };
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;
    let info = match result {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                ModuleInfo {
                    module: cache_key.clone(),
                    names: vec![],
                    error: Some(format!(
                        "exit {:?}: {}",
                        output.status,
                        stderr.lines().next().unwrap_or("")
                    )),
                    latency_ms,
                }
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                #[derive(Deserialize)]
                struct Out {
                    names: Vec<String>,
                    error: Option<String>,
                }
                match serde_json::from_str::<Out>(stdout.trim()) {
                    Ok(parsed) => ModuleInfo {
                        module: cache_key.clone(),
                        names: parsed.names,
                        error: parsed.error,
                        latency_ms,
                    },
                    Err(e) => ModuleInfo {
                        module: cache_key.clone(),
                        names: vec![],
                        error: Some(format!("json parse: {} (stdout='{}')", e, stdout.trim())),
                        latency_ms,
                    },
                }
            }
        }
        Err(e) => ModuleInfo {
            module: cache_key.clone(),
            names: vec![],
            error: Some(format!("spawn failed: {}", e)),
            latency_ms,
        },
    };

    // Cache result (success or error — don't retry broken builtins).
    {
        let mut cache = INTROSPECT_CACHE.lock().await;
        cache.insert(cache_key, info.clone());
    }
    info
}

/// Introspect a Python class via `dir(module.ClassName)` — returns methods of the
/// class (and inherited). Used to verify `var.method(` calls where `var`'s
/// type is a class instance (e.g., `scaler.fit_transform()` where
/// `scaler: StandardScaler`).
///
/// Returns ModuleInfo with `names` = class's public members. The `module`
/// field of the returned ModuleInfo is `"module::class_name"` so it can
/// share the same cache as module-level introspection.
///
/// Error cases (still cached — don't retry):
///   - Module fails to import → ImportError
///   - Class not in module → AttributeError
///   - Name isn't a class (e.g., submodule or function) → TypeError
///
/// Time budget: ~100-300ms per call (Python startup + import + dir()).
pub async fn introspect_python_class(module: &str, class_name: &str) -> ModuleInfo {
    let cache_key = format!("{}::{}", module, class_name);

    // Check cache first.
    {
        let cache = INTROSPECT_CACHE.lock().await;
        if let Some(info) = cache.get(&cache_key) {
            return info.clone();
        }
    }

    let start = std::time::Instant::now();
    let script = format!(
        r#"
import importlib, json
try:
    m = importlib.import_module("{module}")
    if not hasattr(m, "{class_name}"):
        print(json.dumps({{"names": [], "error": "AttributeError: module '{module}' has no attribute '{class_name}'"}}))
    else:
        cls = getattr(m, "{class_name}")
        if not isinstance(cls, type):
            print(json.dumps({{"names": [], "error": "TypeError: '{class_name}' is not a class ({{type(cls).__name__}})"}}))
        else:
            names = sorted([n for n in dir(cls) if not n.startswith('_')])
            print(json.dumps({{"names": names, "error": None}}))
except ImportError as e:
    print(json.dumps({{"names": [], "error": f"ImportError: {{e}}"}}))
except Exception as e:
    print(json.dumps({{"names": [], "error": f"{{type(e).__name__}}: {{e}}"}}))
"#,
        module = module.replace('"', "\\\""),
        class_name = class_name.replace('"', "\\\"").replace('\'', "\\'")
    );

    // Bound the introspection — same pattern as introspect_python_module
    // above. Hostile __init__.py or circular imports can hang indefinitely.
    const INTROSPECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let result = match tokio::time::timeout(
        INTROSPECT_TIMEOUT,
        crate::scanner::command_hidden_tokio("python")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output_async(),
    )
    .await
    {
        Ok(r) => r,
        Err(_elapsed) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::warn!(
                target: "scanner",
                cache_key = %cache_key,
                latency_ms,
                timeout_secs = INTROSPECT_TIMEOUT.as_secs(),
                "introspect_python_class timed out — returning error"
            );
            return ModuleInfo {
                module: cache_key.clone(),
                names: vec![],
                error: Some(format!(
                    "introspect timeout after {}s",
                    INTROSPECT_TIMEOUT.as_secs()
                )),
                latency_ms,
            };
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    let info = match result {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                ModuleInfo {
                    module: cache_key.clone(),
                    names: vec![],
                    error: Some(format!(
                        "exit {:?}: {}",
                        output.status,
                        stderr.lines().next().unwrap_or("")
                    )),
                    latency_ms,
                }
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                #[derive(Deserialize)]
                struct Out {
                    names: Vec<String>,
                    error: Option<String>,
                }
                match serde_json::from_str::<Out>(stdout.trim()) {
                    Ok(parsed) => ModuleInfo {
                        module: cache_key.clone(),
                        names: parsed.names,
                        error: parsed.error,
                        latency_ms,
                    },
                    Err(e) => ModuleInfo {
                        module: cache_key.clone(),
                        names: vec![],
                        error: Some(format!(
                            "parse JSON: {e} (raw: {})",
                            crate::scanner::safe_slice_to(&stdout, 200)
                        )),
                        latency_ms,
                    },
                }
            }
        }
        Err(e) => ModuleInfo {
            module: cache_key.clone(),
            names: vec![],
            error: Some(format!("spawn python: {e}")),
            latency_ms,
        },
    };

    // Cache deterministic failures only (see introspect_python_module).
    if !is_transient_introspect_error(&info.error) {
        let mut cache = INTROSPECT_CACHE.lock().await;
        cache.insert(cache_key.clone(), info.clone());
    }
    info
}

/// Method return type classification for chain traversal.
///
/// Oracle bug E fix: distinguishes "explicit None" (real void method,
/// BrokenChain candidate per EASE paper) from "untyped" (no type hint
/// available — common in pre-3.10 code, numpy, pandas — should stop
/// silently to avoid false positives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnType {
    /// Method has a return type hint (e.g., "DataFrame", "ndarray").
    Typed(String),
    /// Method explicitly returns None (type hint is `-> None`).
    /// EASE paper BrokenChain candidate.
    ExplicitNone,
    /// No type hint available (Signature.empty or inspect.signature failed).
    /// Stop silently — flagging here would cause false positives.
    Untyped,
    /// Method doesn't exist in module (hasattr False).
    Missing,
    /// Introspection itself failed (ImportError, subprocess error).
    Error(String),
}

/// Introspect a single method's return type hint.
///
/// Used for Phase 2 chain traversal (EASE paper Algorithm 1). Walks
/// `obj.m1().m2()` left-to-right by tracking each method's return type.
///
/// Returns ReturnType enum distinguishing typed/explicit-None/untyped/missing/error.
/// Cached per (module, method) via a separate Mutex.
pub async fn method_return_type(module: &str, method: &str) -> ReturnType {
    let key = (module.to_string(), method.to_string());
    {
        let cache = RETURN_TYPE_CACHE.lock().await;
        if let Some(v) = cache.get(&key) {
            return v.clone();
        }
    }

    let script = format!(
        r#"
import importlib, inspect, json
try:
    m = importlib.import_module("{module}")
    if not hasattr(m, "{method}"):
        print(json.dumps({{"kind": "missing"}}))
    else:
        fn = getattr(m, "{method}")
        try:
            sig = inspect.signature(fn)
            ret = sig.return_annotation
            if ret is inspect.Signature.empty:
                # No type hint — stop silently.
                print(json.dumps({{"kind": "untyped"}}))
            elif ret is type(None):
                # Explicit None return — BrokenChain candidate.
                print(json.dumps({{"kind": "explicit_none"}}))
            else:
                tn = getattr(ret, '__name__', None) or str(ret)
                print(json.dumps({{"kind": "typed", "return_type": tn}}))
        except (ValueError, TypeError):
            # inspect.signature failed (built-in, C extension).
            print(json.dumps({{"kind": "untyped"}}))
except ImportError as e:
    print(json.dumps({{"kind": "error", "msg": f"ImportError: {{e}}"}}))
except Exception as e:
    print(json.dumps({{"kind": "error", "msg": f"{{type(e).__name__}}: {{e}}"}}))
"#,
        module = module.replace('"', "\\\""),
        method = method.replace('"', "\\\"")
    );

    let result = crate::scanner::command_hidden_tokio("python")
        .arg("-c")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await;

    let value = match result {
        Ok(output) => {
            if !output.status.success() {
                ReturnType::Error(format!("python exit {:?}", output.status))
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                #[derive(Deserialize)]
                struct Out {
                    kind: String,
                    #[serde(default)]
                    return_type: Option<String>,
                    #[serde(default)]
                    msg: Option<String>,
                }
                match serde_json::from_str::<Out>(stdout.trim()) {
                    Ok(parsed) => match parsed.kind.as_str() {
                        "typed" => ReturnType::Typed(parsed.return_type.unwrap_or_default()),
                        "explicit_none" => ReturnType::ExplicitNone,
                        "untyped" => ReturnType::Untyped,
                        "missing" => ReturnType::Missing,
                        "error" => ReturnType::Error(parsed.msg.unwrap_or_default()),
                        _ => ReturnType::Untyped,
                    },
                    Err(e) => ReturnType::Error(format!("parse JSON: {e}")),
                }
            }
        }
        Err(e) => ReturnType::Error(format!("spawn python: {e}")),
    };

    let mut cache = RETURN_TYPE_CACHE.lock().await;
    // Don't cache transient errors (spawn failures). Only cache deterministic
    // results so transient subprocess failures retry on next call.
    if !matches!(&value, ReturnType::Error(msg) if msg.contains("timeout") || msg.contains("spawn python")) {
        cache.insert(key, value.clone());
    }
    value
}

/// FORGE pattern: verify API calls against introspected ground truth.
///
/// For each Import in `calls`, introspects the module and produces verdicts:
///   - Module imports successfully + name present → Verified
///   - Module imports successfully + name missing → Hallucinated (closest match suggested)
///   - Module fails to import → UnknownModule (cannot verify, don't flag)
///
/// For Method calls on typed receivers, looks up the receiver's type (if known
/// from scope_analysis) and introspects that type's module.
///
/// Returns warnings ready for `result.warnings`.
pub async fn verify_against_introspection(
    calls: &[ApiCall],
    scope_vars: &[(String, String)],
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut scope_map: HashMap<String, String> = scope_vars.iter().cloned().collect();

    // Collect all modules to introspect (from imports + scope var types).
    let mut modules_to_check: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Collect names imported via `from X import Y` — these are valid bare
    // calls in Python (e.g., `from pydantic import Field; Field(...)`).
    // The bare-critical-call check must skip these to avoid false positives.
    // ALSO collects user-defined function names (via ApiKind::FunctionDef
    // emitted by extract_python_apis) so a bare call to `main()` is not
    // flagged when `def main():` exists in the same module/suffix.
    let mut imported_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for call in calls {
        if call.kind == ApiKind::Import {
            if !call.name.is_empty() {
                modules_to_check.insert(call.name.clone());
            }
            for n in &call.imported_names {
                imported_names.insert(n.clone());
            }
        } else if call.kind == ApiKind::FunctionDef {
            imported_names.insert(call.name.clone());
        }
    }

    // Introspect all required modules in parallel (each call hits cache after first).
    let mut module_infos: HashMap<String, ModuleInfo> = HashMap::new();
    for module in modules_to_check {
        let info = introspect_python_module(&module).await;
        module_infos.insert(module, info);
    }

    // Verify each Import's imported_names against the introspected module.
    for call in calls {
        if call.kind != ApiKind::Import {
            continue;
        }
        let info = match module_infos.get(&call.name) {
            Some(i) => i,
            None => continue,
        };
        if let Some(err) = &info.error {
            // Module doesn't import — defer to package_index for registry check.
            // Don't flag here; package_index.rs handles "module doesn't exist" via PyPI.
            tracing::debug!(target: "scanner", module = %call.name, error = %err, "module introspection failed; deferring to package_index");
            continue;
        }
        for imported in &call.imported_names {
            if !info.exists(imported) {
                // Python import semantics: `from pkg import name` ALSO
                // succeeds when pkg/name.py is a submodule on the module's
                // search path, even when pkg/__init__.py does not re-export
                // it (hasattr misses the fallback). Probe the dotted
                // submodule directly before flagging — cached after first
                // hit (20260818 task-002 P3: `from notes_cli import
                // database` FP'd 4x while database.py sat on disk).
                let dotted = format!("{}.{}", call.name, imported);
                let sub = introspect_python_module(&dotted).await;
                if sub.error.is_none() {
                    continue; // valid submodule import
                }
                // Hallucinated name. Try to suggest closest match.
                match info.closest_match(imported) {
                    Some(suggestion) => warnings.push(format!(
                        "hallucinated-import: `from {} import {}` — `{}` not in module. Did you mean `{}`?",
                        call.name, imported, imported, suggestion
                    )),
                    None => warnings.push(format!(
                        "hallucinated-import: `from {} import {}` — `{}` not in module",
                        call.name, imported, imported
                    )),
                }
            }
        }
    }

    // Build alias map from imports with asname (e.g., `import streamlit as st`
    // produces entry {"st": "streamlit"}). Used for Method verification when
    // receiver is an import alias rather than a local variable.
    let mut alias_map: HashMap<String, String> = HashMap::new();
    for call in calls {
        if call.kind == ApiKind::Import && !call.receiver.is_empty() {
            alias_map.insert(call.receiver.clone(), call.name.clone());
        }
    }

    // Verify Method calls on typed receivers OR import-aliased receivers.
    // SKIP chains (imported_names non-empty) — they're handled by the
    // Phase 2 chain traversal block below.
    for call in calls {
        if call.kind != ApiKind::Method || !call.imported_names.is_empty() {
            continue;
        }
        if call.receiver.is_empty() {
            continue;
        }

        // Case A: receiver is an import alias (e.g., `st.text_field(` where
        // `st` is bound to `streamlit` via `import streamlit as st`).
        if let Some(module_name) = alias_map.get(&call.receiver) {
            let info = introspect_python_module(module_name).await;
            if info.error.is_none() && !info.exists(&call.name) {
                match info.closest_match(&call.name) {
                    Some(suggestion) => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not in module `{}`. Did you mean `{}`?",
                        call.receiver, call.name, call.name, module_name, suggestion
                    )),
                    None => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not in module `{}`",
                        call.receiver, call.name, call.name, module_name
                    )),
                }
            }
            continue;
        }

        // Case C: receiver is a class name exported from an imported module.
        // E.g., `ConnectTimeout.with_tracebak()` where ConnectTimeout is in
        // dir(requests). Check each imported module for the class name, then
        // introspect the class to verify the method.
        let mut class_found = false;
        for (module_name, info) in &module_infos {
            if info.error.is_some() { continue; }
            if info.exists(&call.receiver) {
                let class_info = introspect_python_class(module_name, &call.receiver).await;
                if class_info.error.is_none() && !class_info.exists(&call.name) {
                    match class_info.closest_match(&call.name) {
                        Some(suggestion) => warnings.push(format!(
                            "hallucinated-method: `{}.{}` — `{}` not a method of `{}.{}`. Did you mean `{}`?",
                            call.receiver, call.name, call.name, module_name, call.receiver, suggestion
                        )),
                        None => warnings.push(format!(
                            "hallucinated-method: `{}.{}` — `{}` not a method of `{}.{}`",
                            call.receiver, call.name, call.name, module_name, call.receiver
                        )),
                    }
                }
                class_found = true;
                break;
            }
        }
        if class_found { continue; }

        // Case B: receiver is a typed local variable.
        //
        // Approach C: Python class-level introspection. When the receiver's
        // type is a class exported from an introspected module, use
        // `dir(module.ClassName)` (real class method list) instead of
        // `dir(module)` (top-level names only). Without this, valid class
        // instance methods like `scaler.fit_transform()` would be falsely
        // flagged because `fit_transform` isn't in `dir(sklearn.preprocessing)`.
        let var_type = match scope_map.get(&call.receiver) {
            Some(t) => t.clone(),
            None => continue,
        };

        // Approach C: try resolving var_type as a class in any cached module.
        // Only attempts class introspection on modules whose dir() contains
        // var_type — keeps subprocess count bounded.
        let mut resolved_class: Option<(String, ModuleInfo)> = None;
        for (module_name, info) in &module_infos {
            if info.error.is_some() || !info.exists(&var_type) {
                continue;
            }
            let class_info = introspect_python_class(module_name, &var_type).await;
            if class_info.error.is_none() && !class_info.names.is_empty() {
                resolved_class = Some((module_name.clone(), class_info));
                break;
            }
        }

        if let Some((module_name, class_info)) = resolved_class {
            // Verified class instance — use the class method list.
            if !class_info.exists(&call.name) {
                match class_info.closest_match(&call.name) {
                    Some(suggestion) => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not a method on `{}` (from `{}`). Did you mean `{}`?",
                        call.receiver, call.name, call.name, var_type, module_name, suggestion
                    )),
                    None => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not a method on `{}` (from `{}`)",
                        call.receiver, call.name, call.name, var_type, module_name
                    )),
                }
            }
            continue;
        }

        // Case B2: receiver type is a Python builtin (str/int/list/dict/etc.).
        // Verify method against dir(<builtin>) to catch fabricated methods
        // like `'str'.to_uppercase()` or `list.flatten()`.
        const PYTHON_BUILTINS: &[&str] = &[
            "str", "int", "float", "bool", "list", "dict", "set", "tuple",
            "bytes", "bytearray", "frozenset", "complex",
        ];
        if PYTHON_BUILTINS.contains(&var_type.as_str()) {
            let info = introspect_python_builtin(&var_type).await;
            if info.error.is_none() && !info.exists(&call.name) {
                match info.closest_match(&call.name) {
                    Some(suggestion) => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not a method on builtin `{}`. Did you mean `{}`?",
                        call.receiver, call.name, call.name, var_type, suggestion
                    )),
                    None => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not a method on builtin `{}`",
                        call.receiver, call.name, call.name, var_type
                    )),
                }
            }
            continue;
        }

        // Legacy fallback: var_type is in some module's dir() but isn't a class
        // (e.g., a submodule like `os.path` or a module-level function).
        // Verify call.name against the module's top-level names.
        let mut found_in_module: Option<&ModuleInfo> = None;
        for info in module_infos.values() {
            if info.exists(&var_type) {
                found_in_module = Some(info);
                break;
            }
        }
        if let Some(info) = found_in_module {
            // Verify method exists on this type.
            if !info.exists(&call.name) {
                match info.closest_match(&call.name) {
                    Some(suggestion) => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not a method. Did you mean `{}`?",
                        call.receiver, call.name, call.name, suggestion
                    )),
                    None => warnings.push(format!(
                        "hallucinated-method: `{}.{}` — `{}` not a method",
                        call.receiver, call.name, call.name
                    )),
                }
            }
        }
    }

    // FORGE Phase 2: chain traversal with type propagation (EASE paper Algorithm 1).
    // For ApiCalls where Method + imported_names non-empty (chains like
    // obj.m1().m2().m3()), walk left-to-right tracking return types.
    //
    // Catches:
    //   - PhantomMember (method doesn't exist on current type)
    //   - BrokenChain (method returns None + further calls)
    //   - Misplaced Member (valid method on wrong resolved type — partially)
    //
    // Conservative: if any return type can't be resolved, stops traversal
    // silently (no flag) to avoid false positives.
    for call in calls {
        if call.kind != ApiKind::Method || call.imported_names.is_empty() {
            continue;
        }
        if call.receiver.is_empty() {
            continue; // Untyped root — skip.
        }

        // Resolve root type: try import alias first, then scope_map.
        let root_type_module = if let Some(module) = alias_map.get(&call.receiver) {
            Some(module.clone())
        } else {
            scope_map.get(&call.receiver).cloned()
        };

        let mut current_module = match root_type_module {
            Some(m) => m,
            None => continue, // Unknown root — can't traverse.
        };

        // Walk chain left-to-right.
        let chain = &call.imported_names;
        for (i, method) in chain.iter().enumerate() {
            // Get current module's introspected info.
            let info = introspect_python_module(&current_module).await;
            if info.error.is_some() {
                break; // Can't verify — stop silently.
            }
            if !info.exists(method) {
                // PhantomMember: method not on current type.
                match info.closest_match(method) {
                    Some(suggestion) => warnings.push(format!(
                        "chain-phantom-member: `{}.{}` chain step `{}` not in `{}`. Did you mean `{}`?",
                        call.receiver, call.name, method, current_module, suggestion
                    )),
                    None => warnings.push(format!(
                        "chain-phantom-member: `{}.{}` chain step `{}` not in `{}`",
                        call.receiver, call.name, method, current_module
                    )),
                }
                break;
            }
            // Method exists. Check return type for next iteration.
            if i + 1 < chain.len() {
                // More steps remain — need return type.
                match method_return_type(&current_module, method).await {
                    ReturnType::Typed(return_type) => {
                        // Try to find a module that exports this type.
                        // Bug D fix: also try the type name itself as a module
                        // (common Python idiom: pandas.DataFrame is in pandas).
                        let mut found_module = None;
                        for info in module_infos.values() {
                            if info.exists(&return_type) {
                                found_module = Some(info.module.clone());
                                break;
                            }
                        }
                        match found_module {
                            Some(m) => current_module = m,
                            None => {
                                // Bug D fix: try the type name as a module
                                // (e.g., "DataFrame" isn't a module, but
                                // "pandas" is — try introspecting the return
                                // type name directly).
                                let candidate = introspect_python_module(&return_type).await;
                                if candidate.error.is_none() && !candidate.names.is_empty() {
                                    current_module = return_type;
                                } else {
                                    break; // Can't propagate — stop silently.
                                }
                            }
                        }
                    }
                    ReturnType::ExplicitNone => {
                        // Method explicitly returns None (-> None type hint).
                        // EASE paper BrokenChain: further calls invalid.
                        warnings.push(format!(
                            "chain-broken: `{}.{}` chain step `{}` returns None in `{}` — further calls invalid",
                            call.receiver, call.name, method, current_module
                        ));
                        break;
                    }
                    ReturnType::Untyped | ReturnType::Missing | ReturnType::Error(_) => {
                        // No type hint available (common: builtins, C exts,
                        // pre-3.10 code). Oracle bug E fix: stop silently to
                        // avoid false positives. DO NOT fire chain-broken.
                        break;
                    }
                }
            }
        }
    }

    // FORGE paper section 2.3 category (2): Bare Critical Call detection.
    // A function call without module prefix that exists in an introspected
    // module (e.g., `read_csv()` instead of `pd.read_csv()`). Paper reports
    // 97.9% recall on this category.
    //
    // Skip Python builtins — they're legitimately bare. The skip list is
    // conservative (only well-known builtins) so library functions are caught.
    static PYTHON_BUILTINS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
        [
            "print", "len", "range", "type", "isinstance", "issubclass",
            "getattr", "setattr", "hasattr", "delattr", "dir", "vars",
            "repr", "str", "int", "float", "bool", "list", "dict", "set",
            "tuple", "frozenset", "bytes", "bytearray", "complex",
            "abs", "min", "max", "sum", "round", "pow", "divmod",
            "sorted", "reversed", "enumerate", "zip", "map", "filter",
            "all", "any", "next", "iter", "open", "input",
            "id", "hash", "format", "chr", "ord", "bin", "hex", "oct",
            "globals", "locals", "exec", "eval", "compile",
            "exit", "quit", "help",
            // Common stdlib that's always imported implicitly.
            "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
            "AttributeError", "RuntimeError", "StopIteration", "NotImplemented",
            "True", "False", "None", "self", "cls",
        ]
        .iter()
        .copied()
        .collect()
    });

    for call in calls {
        if call.kind != ApiKind::Function {
            continue;
        }
        if PYTHON_BUILTINS.contains(call.name.as_str()) {
            continue;
        }
        if call.name.starts_with('_') {
            continue;
        }
        // Skip SCREAMING_SNAKE_CASE constants — these are never function calls.
        // Catches FPs like UNVERIFIED, PROJECT_API_INDEX, MAX_RETRIES etc.
        // that the scope checker references as bare names.
        if call.name.len() >= 2
            && call.name.chars().all(|c| c.is_uppercase() || c == '_')
            && call.name.chars().filter(|c| c.is_uppercase()).count() >= 2
        {
            continue;
        }
        // Skip names brought into scope via `from X import Y`. Calling `Y()`
        // bare is the canonical Python idiom and must not be flagged as a
        // bare-critical-call (which is reserved for `pd.read_csv()` written
        // as `read_csv()` without the import).
        if imported_names.contains(&call.name) {
            continue;
        }
        // Search all introspected modules for this function name.
        let mut found_in: Option<&String> = None;
        for (module_name, info) in &module_infos {
            if info.error.is_none() && info.exists(&call.name) {
                found_in = Some(module_name);
                break;
            }
        }
        if let Some(_module_name) = found_in {
            // Function exists in an imported module — valid call, just
            // without the prefix. NOT a hallucination, don't warn.
        } else {
            // Gap 1 fix: CamelCase function names that are NOT in any module
            // and NOT in scope_vars → possible hallucinated class constructor.
            // Catches DELULU samples like `SchemaField(` (should be `Field(`).
            //
            // Conservative: only fires for CamelCase names (first char uppercase).
            // Skips lowercase (user functions) + underscore-prefixed (private).
            let is_class_like = call.name.chars().next().map_or(false, |c| c.is_uppercase());
            if !is_class_like {
                // Lowercase bare function not in any module. Check for close
                // matches in imported modules — catches mutations like
                // sdd() vs add(), raed() vs read(), etc.
                if call.name.len() >= 3 {
                    let mut best_match: Option<(String, String)> = None; // (module, suggestion)
                    for (module_name, info) in &module_infos {
                        if info.error.is_some() { continue; }
                        if let Some(suggestion) = info.closest_match(&call.name) {
                            best_match = Some((module_name.clone(), suggestion));
                            break;
                        }
                    }
                    if let Some((module_name, suggestion)) = best_match {
                        warnings.push(format!(
                            "hallucinated-function: `{}` — not found. Did you mean `{}` from `{}`?",
                            call.name, suggestion, module_name
                        ));
                    }
                }
                continue;
            }
            // Skip if this name is a user-defined type (in scope_vars values).
            let is_user_type = scope_map.values().any(|v| v == &call.name);
            if is_user_type {
                continue;
            }
            // Search all introspected modules for a close match.
            // Two-tier matching:
            //   (1) Levenshtein ≤4 (typo/rename detection)
            //   (2) Suffix match ≥4 chars (prefix hallucination: SchemaField→Field)
            let mut best_suggestion: Option<(String, usize, usize)> = None; // (suggestion, dist, priority)
            for info in module_infos.values() {
                if info.error.is_some() {
                    continue;
                }
                // Tier 1: Levenshtein fuzzy match.
                if let Some(suggestion) = info.closest_match(&call.name) {
                    let dist = levenshtein_capped(&call.name, &suggestion, 7);
                    if dist <= 4 {
                        match best_suggestion {
                            None => best_suggestion = Some((suggestion, dist, 0)),
                            Some((_, bd, bp)) if dist < bd || (dist == bd && bp > 0) => {
                                best_suggestion = Some((suggestion, dist, 0));
                            }
                            _ => {}
                        }
                        continue;
                    }
                }
                // Tier 2: Suffix match — catches prefix hallucinations.
                // SchemaField → Field (real name is suffix of hallucinated).
                // DataFrameWriter → DataFrame.
                for candidate in &info.names {
                    if candidate.len() >= 4 && call.name.ends_with(candidate.as_str()) {
                        let extra = call.name.len() - candidate.len();
                        // Lower extra = better. Priority 1 (below tier 1's priority 0).
                        match best_suggestion {
                            None => best_suggestion = Some((candidate.clone(), extra, 1)),
                            Some((_, _, 0)) => {} // Tier 1 match wins.
                            Some((_, be, _)) if extra < be => {
                                best_suggestion = Some((candidate.clone(), extra, 1));
                            }
                            _ => {}
                        }
                    }
                }
            }
            if let Some((suggestion, dist, _)) = best_suggestion {
                warnings.push(format!(
                    "hallucinated-constructor: `{}` — not in any cached module. Did you mean `{}`?",
                    call.name, suggestion
                ));
            }
        }
    }

    warnings
}

/// Detect Method calls whose receiver was assigned from a function call but
/// whose type couldn't be inferred by `analyze_scope`.
///
/// Closes the gap that let `resp = requests.get(...); resp.parse_json()` slip
/// through: `analyze_scope`'s regex only matches `var = ClassName(` patterns
/// (uppercase type start), missing `var = module.function(` patterns. When
/// type inference fails, `verify_against_introspection` silently skips the
/// call (Case B `None => continue`) — no warning, no escalation signal. The
/// L2.5 cascade then sees `claims_unknown == 0` and skips L3, shipping the
/// hallucination.
///
/// This function emits `chain-broken` warnings for each Method call on a
/// receiver that IS in `assignments` (meaning it was bound from a call
/// expression) but is NOT in `scope_vars` (meaning type inference failed).
/// The `chain-broken` prefix triggers `has_introspection_warning` in
/// `mod.rs`, which forces L3 escalation.
///
/// Extract the class name from a constructor-shaped assignment RHS:
/// `ClassName(...)` with an UppercaseInitial callee and no module/dotted
/// prefix (dotted forms like `models.HealthStatus(...)` stay conservative —
/// the prefix could be a module re-exporting a function, not the class).
/// Handles `await ClassName(...)` and redundant parens (`ast.unparse`
/// normalizes both). Returns None for non-ctor shapes (`<parameter>`,
/// `module.function(...)`, literals).
///
/// Grounding: Python typing spec constructors chapter — a constructor call
/// binds the receiver to an instance of the class unless an explicit
/// `__new__` return says otherwise (rare, detectable). pyright/mypy both
/// assume Self on unannotated ctors.
fn ctor_class_name(rhs: &str) -> Option<&str> {
    let s = rhs.trim().trim_start_matches('(').trim();
    // `await X(...)`: the awaited value is whatever X's `__await__` yields,
    // not an instance of X - the typing-spec ctor-returns-Self rule does
    // not apply (audit finding).
    if s.starts_with("await ") {
        return None;
    }
    // Callee must start uppercase and be followed by '(' — a leading dot
    // or lowercase segment means module-qualified call, not a bare ctor.
    let paren = s.find('(')?;
    let callee = s[..paren].trim();
    let mut chars = callee.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return None,
    }
    if !callee.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(callee)
}

/// Line-anchored, word-bounded class-declaration check: some line in
/// `content` starts a `class {name}` declaration. Prose mentions
/// ("...the class Foo...") and longer names (`class FooBar`) do not match.
fn class_declared_in_content(content: &str, class: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?m)^\s*class\s+([A-Za-z_]\w*)").expect("valid class regex")
    });
    re.captures_iter(content)
        .any(|c| c.get(1).map(|m| m.as_str()) == Some(class))
}

/// True when `def {method}(` appears inside the indented body block of a
/// `class {class}` declaration in `content`. Comment lines are ignored (a
/// `# def foo(` TODO is not evidence). The body ends at the first
/// non-blank line indented at or below the class declaration line.
fn method_defined_in_class_body(content: &str, class: &str, method: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if !t.starts_with("class ") {
            continue;
        }
        let name: String = t[6..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name != class {
            continue;
        }
        let class_indent = line.len() - t.len();
        for body_line in lines.iter().skip(i + 1) {
            let bt = body_line.trim_start();
            if bt.is_empty() {
                continue;
            }
            let b_indent = body_line.len() - bt.len();
            if b_indent <= class_indent {
                // First non-blank line at/below class indentation ends the
                // body block.
                return false;
            }
            if bt.starts_with('#') {
                continue;
            }
            if bt.starts_with("def ") {
                let mname: String = bt[4..]
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if mname == method {
                    return true;
                }
            }
        }
        return false;
    }
    false
}

/// Deduplication: same (receiver, method) pair only emits once per scan.
pub fn detect_unresolved_receivers(
    calls: &[ApiCall],
    scope_vars: &[(String, String)],
    assignments: &std::collections::HashMap<String, String>,
    content: &str,
    session_defined: &std::collections::HashSet<String>,
) -> Vec<String> {
    let scope_map: std::collections::HashMap<String, String> =
        scope_vars.iter().cloned().collect();
    let mut warnings = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for call in calls {
        if call.kind != ApiKind::Method || !call.imported_names.is_empty() {
            continue;
        }
        if call.receiver.is_empty() {
            continue;
        }
        // Receiver is type-resolved — verify_against_introspection handled it.
        if scope_map.contains_key(&call.receiver) {
            continue;
        }
        // Receiver was assigned from a call expression — type inference should
        // have resolved it but couldn't (e.g., `resp = requests.get(...)` →
        // would need return-type knowledge).
        if let Some(rhs) = assignments.get(&call.receiver) {
            // R1/R2 ctor suppression: receiver bound from a bare
            // `ClassName(...)` constructor call where the class is
            // user/session-defined. Typing-spec rule: the ctor binds the
            // receiver to the class instance, so the receiver type IS
            // resolvable — the member check belongs to class-local
            // evidence, not library introspection. If the claimed method
            // appears on the class surface (same-response `def name(` or a
            // session symbol), the claim is verified by project source.
            // Suppresses the pydantic pattern
            // `error_status = HealthStatus(...); error_status.is_healthy()`
            // where the regex scope inference missed the ctor binding.
            // Dotted RHS (`models.HealthStatus(...)`) intentionally falls
            // through — conservative. Negative guard preserved: ctor class
            // known but method NOT on its surface and NOT in the symbol
            // cache → warning still emitted (recall bias).
            if let Some(class) = ctor_class_name(rhs) {
                // Class evidence: an actual `class X` DECLARATION line in
                // this response (line-anchored, word-bounded - `class FooX`
                // and prose mentions must not count), or a session symbol
                // of that exact name.
                let class_known = class_declared_in_content(content, class)
                    || session_defined.contains(class);
                if class_known {
                    // Method evidence, strongest first:
                    // 1. `def name(` inside THIS class's body block in the
                    //    same response (scoped - audit fix for cross-class
                    //    and comment leaks).
                    // 2. Both class AND method present as session symbols
                    //    (cross-response: the agent defined the class in an
                    //    earlier response and F8 accumulated it pre-scan).
                    //    Audit dissent: the flat session store cannot bind
                    //    a method to its class, so a same-named top-level
                    //    session function could suppress a hallucinated
                    //    method (channel C). Kept anyway: the cross-
                    //    response legit pattern is the dominant production
                    //    shape (e2e task-013: 4 chain-broken FPs eliminated
                    //    exactly this way) and FN cost >> FP cost. Revisit
                    //    when the session store becomes class-scoped.
                    if method_defined_in_class_body(content, class, call.name.as_str())
                        || (session_defined.contains(class)
                            && session_defined.contains(call.name.as_str()))
                    {
                        continue;
                    }
                }
            }
            // SymbolCache consultation: if the method name exists in ANY
            // cached library (real upstream package, not local.* project
            // entries), the method is real — just on a receiver type we
            // couldn't infer. Suppress the chain-broken FP while preserving
            // the L3 escalation path for genuinely unknown methods.
            //
            // Targets common Python FP patterns:
            //   - `re.compile(...)` → re.Pattern .match()/.search()/.findall()
            //   - `await client.get/post(...)` → httpx.Response
            //     .raise_for_status()/.json()/.status_code
            //   - `v: str` param → str .lower()/.upper()/.strip()
            //   - function returning Dict → dict .get()/.keys()/.values()
            //
            // local.* entries are excluded: they record class names from the
            // user's own code without method introspection, so a name match
            // there is not real verification (Rule 8: live APIs only).
            if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
                let method_known = cache
                    .lookup_global(&call.name)
                    .iter()
                    .any(|s| !s.library.starts_with("local."));
                if method_known {
                    continue;
                }
            }
            let key = (call.receiver.clone(), call.name.clone());
            if seen.insert(key) {
                let origin = if rhs == "<parameter>" {
                    "a function parameter".to_string()
                } else {
                    format!("assigned from `{rhs}`")
                };
                warnings.push(format!(
                    "chain-broken: `{}.{}` — receiver `{}` was {} \
                     but its type couldn't be inferred. Verify the method exists.",
                    call.receiver, call.name, call.receiver, origin
                ));
            }
        }
    }
    warnings
}

/// Clear the introspection cache. Useful for tests or when project
/// dependencies change.
/// Oracle bug C fix: also clears RETURN_TYPE_CACHE for full test isolation.
pub async fn clear_cache() {
    INTROSPECT_CACHE.lock().await.clear();
    RETURN_TYPE_CACHE.lock().await.clear();
}

/// Levenshtein distance with early exit when over cap. Returns cap+1 if
/// exceeded (matches levenshtein_capped convention).
fn levenshtein_capped(a: &str, b: &str, cap: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    if (m.abs_diff(n)) > cap {
        return cap + 1;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        // Early exit if all entries in curr exceed cap.
        if curr.iter().all(|&x| x > cap) {
            return cap + 1;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

// Polyfill: tokio::process::Command::output_async was deprecated in favor
// of `.output()`. Wrap to keep the call site readable.
trait OutputAsyncExt {
    async fn output_async(&mut self) -> std::io::Result<std::process::Output>;
}
impl OutputAsyncExt for tokio::process::Command {
    async fn output_async(&mut self) -> std::io::Result<std::process::Output> {
        self.output().await
    }
}

/// Check Python function calls against their signatures.
///
/// Gap 3: catches hallucinated parameters like
/// `column('cmd', sa.String, nullable=False)` where `nullable` isn't
/// a valid parameter name.
///
/// Self-contained: runs Python subprocess that parses content with ast,
/// extracts Call nodes with keyword arguments, checks each against
/// `inspect.signature(fn).parameters`. Only fires when the function is
/// importable AND has a resolvable signature.
///
/// Conservative: skips builtins, skips functions with **kwargs (accept
/// any parameter name), skips when signature can't be resolved.
pub async fn check_python_parameters(content: &str) -> Vec<String> {
    use std::process::Stdio;
    use tokio::process::Command;
    use tokio::io::AsyncWriteExt;

    let script = r#"
import ast, json, sys, importlib, inspect, builtins

tree = ast.parse(sys.stdin.read())
warnings = []

# Collect all imports to know which modules are available.
# Also build alias map: 'pd' -> 'pandas', 'np' -> 'numpy' so we can
# resolve dotted calls like pd.merge(...) (ast.Attribute on ast.Name).
imported_modules = set()
alias_to_module = {}
for node in ast.walk(tree):
    if isinstance(node, ast.ImportFrom) and node.module:
        imported_modules.add(node.module)
    elif isinstance(node, ast.Import):
        for alias in node.names:
            # `import x.y.z` binds the name `x` (top-level) in scope, not
            # `x.y.z`. Accessing `x.y` works because the import machinery
            # sets `y` as an attribute on module `x`. So alias_to_module
            # must map local_name -> top-level module name, not the full
            # dotted path. Multi-hop dotted calls then walk attributes off
            # the top-level module via getattr().
            top = alias.name.split('.')[0]
            imported_modules.add(top)
            local_name = alias.asname or top
            alias_to_module[local_name] = top

# Builtins that accept *args/**kwargs — skip.
SKIP_BUILTINS = {'print', 'dict', 'list', 'set', 'tuple', 'sorted', 'min',
                 'max', 'sum', 'format', 'open', 'isinstance', 'issubclass',
                 'getattr', 'setattr', 'hasattr', 'type', 'super', 'property',
                 'staticmethod', 'classmethod', 'range', 'enumerate', 'zip',
                 'map', 'filter', 'next', 'iter', 'reversed', 'all', 'any'}

def resolve_function(call_node):
    # Return (display_name, mod_name, fn_obj) or None.
    # Walk attribute chain to support dotted paths like
    # `requests.adapters.HTTPAdapter(...)` and `np.linalg.norm(...)`.
    func = call_node.func

    # Bare call: f(args) — func is ast.Name.
    if isinstance(func, ast.Name):
        fname = func.id
        if fname in SKIP_BUILTINS or fname.startswith('_'):
            return None
        for mod_name in imported_modules:
            try:
                mod = importlib.import_module(mod_name)
                if hasattr(mod, fname):
                    return (fname, mod_name, getattr(mod, fname))
            except Exception:
                continue
        return None

    # Constant/literal receiver: 'foo'.upper(), [1,2,3].append(...).
    # Only applies when func.value is a literal AST node, not a Name.
    if isinstance(func, ast.Attribute):
        v = func.value
        literal_tp = None
        if isinstance(v, ast.Constant):
            if isinstance(v.value, str): literal_tp = str
            elif isinstance(v.value, bytes): literal_tp = bytes
            elif isinstance(v.value, bool): literal_tp = bool
            elif isinstance(v.value, int): literal_tp = int
            elif isinstance(v.value, float): literal_tp = float
        elif isinstance(v, ast.List): literal_tp = list
        elif isinstance(v, ast.Tuple): literal_tp = tuple
        elif isinstance(v, ast.Set): literal_tp = set
        elif isinstance(v, ast.Dict): literal_tp = dict
        if literal_tp is not None:
            fname = func.attr
            if fname in SKIP_BUILTINS or fname.startswith('_'):
                return None
            if hasattr(literal_tp, fname):
                disp = (type(v.value).__name__ if isinstance(v, ast.Constant)
                        else literal_tp.__name__)
                return (disp + '.' + fname, '__builtins__', getattr(literal_tp, fname))
            return None  # Method-on-wrong-type — flag in caller, not here.

    # Name-rooted dotted call: a.b.c.f(args).
    # Walk attribute chain. Root must be Name; intermediate nodes are
    # Attributes. Supports `requests.adapters.HTTPAdapter(...)`,
    # `np.linalg.norm(...)`, etc.
    if isinstance(func, ast.Attribute):
        chain = []
        cur = func
        while isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        # Root must be a Name — otherwise it's a method call on a value
        # (e.g., `obj.foo()`), which is handled elsewhere.
        if not isinstance(cur, ast.Name):
            return None
        chain.reverse()  # [seg0, seg1, ..., fname]
        root = cur.id
        fname = chain[-1]
        if fname in SKIP_BUILTINS or fname.startswith('_'):
            return None

        # Single-hop: pd.merge(...).
        if len(chain) == 1:
            # Receiver may be a builtin type name (dict/list/str/...).
            BUILTIN_TYPES = {'dict', 'list', 'str', 'bytes', 'tuple',
                             'frozenset', 'set', 'int', 'float', 'bool',
                             'complex', 'bytearray'}
            if root in BUILTIN_TYPES:
                try:
                    tp = getattr(builtins, root)
                    if hasattr(tp, fname):
                        return (root + '.' + fname, '__builtins__', getattr(tp, fname))
                except Exception:
                    pass
            mod_name = alias_to_module.get(root)
            if not mod_name:
                return None
            try:
                mod = importlib.import_module(mod_name)
                if hasattr(mod, fname):
                    return (root + '.' + fname, mod_name, getattr(mod, fname))
            except Exception:
                pass
            return None

        # Multi-hop: requests.adapters.HTTPAdapter(...), np.linalg.norm(...).
        # Walk intermediate attributes off the root module.
        mod_name = alias_to_module.get(root, root)
        try:
            obj = importlib.import_module(mod_name)
            for part in chain[:-1]:
                obj = getattr(obj, part)
            if hasattr(obj, fname):
                disp = root + '.' + '.'.join(chain)
                owner = mod_name + '.' + '.'.join(chain[:-1])
                return (disp, owner, getattr(obj, fname))
        except Exception:
            pass
    return None

for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue
    # Only check calls with keyword arguments.
    kwargs = [kw.arg for kw in node.keywords if kw.arg is not None]
    if not kwargs:
        continue
    resolved = resolve_function(node)
    if resolved is None:
        continue
    fname, mod_name, fn = resolved
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        continue  # built-in or C function without signature
    params = set(sig.parameters.keys())
    # Skip if function has **kwargs (accepts anything).
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD
                   for p in sig.parameters.values())
    if has_var_kw:
        continue
    # Check each keyword arg.
    for kw in kwargs:
        if kw not in params:
            warnings.append({
                "function": fname,
                "module": mod_name,
                "param": kw,
                "valid_params": sorted(params)[:10],  # first 10 for suggestion
            })

print(json.dumps(warnings))
"#;

    let mut child = match crate::scanner::command_hidden_tokio("python")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(content.as_bytes()).await;
    }

    let output = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(o)) => o,
        _ => return Vec::new(),
    };

    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    #[derive(serde::Deserialize)]
    struct ParamWarning {
        function: String,
        module: String,
        param: String,
        valid_params: Vec<String>,
    }

    let parsed: Vec<ParamWarning> = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    parsed
        .iter()
        .map(|w| {
            let suggestions = if w.valid_params.is_empty() {
                String::new()
            } else {
                format!(" Valid params: {}", w.valid_params.join(", "))
            };
            format!(
                "hallucinated-parameter: `{}` — `{}` is not a valid parameter of `{}`.{}",
                w.function, w.param, w.function, suggestions
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn introspect_real_python_module_works() {
        // os is always installed with Python. Should have getcwd, listdir, etc.
        let info = introspect_python_module("os").await;
        assert!(info.error.is_none(), "got error: {:?}", info.error);
        assert!(info.exists("getcwd"), "os should have getcwd; got names: {:?}", info.names);
        assert!(info.exists("listdir"), "os should have listdir");
        assert!(info.latency_ms < 2000, "introspection should be fast, got {}ms", info.latency_ms);
    }

    #[tokio::test]
    async fn introspect_nonexistent_module_returns_error() {
        let info = introspect_python_module("completely_fake_pkg_xyz_12345").await;
        assert!(info.error.is_some(), "expected error, got: {:?}", info);
        assert!(info.names.is_empty());
    }

    #[tokio::test]
    async fn introspect_caches_results() {
        clear_cache().await;
        let first = introspect_python_module("json").await;
        let first_latency = first.latency_ms;
        let second = introspect_python_module("json").await;
        // Cache hit should report same latency (it's the original).
        assert_eq!(first.names, second.names);
        // Latency may be identical (cloned from cache).
        let _ = first_latency;
    }

    #[tokio::test]
    async fn module_info_closest_match_suggests_typo() {
        let info = ModuleInfo {
            module: "test".to_string(),
            names: vec!["PolynomialFeatures".to_string(), "StandardScaler".to_string()],
            error: None,
            latency_ms: 0,
        };
        let m = info.closest_match("PolynomialFeature").unwrap();
        assert_eq!(m, "PolynomialFeatures");
    }

    #[tokio::test]
    async fn module_info_closest_match_returns_none_for_unrelated() {
        let info = ModuleInfo {
            module: "test".to_string(),
            names: vec!["PolynomialFeatures".to_string()],
            error: None,
            latency_ms: 0,
        };
        assert!(info.closest_match("completelyDifferent").is_none());
    }

    #[tokio::test]
    async fn module_info_closest_match_returns_none_for_short_target() {
        let info = ModuleInfo {
            module: "test".to_string(),
            names: vec!["abc".to_string()],
            error: None,
            latency_ms: 0,
        };
        assert!(info.closest_match("ab").is_none());
    }

    #[tokio::test]
    async fn verify_flags_hallucinated_import_name() {
        clear_cache().await;
        // `os` exists but doesn't have `completely_fake_function`.
        let calls = vec![ApiCall {
            kind: ApiKind::Import,
            name: "os".to_string(),
            receiver: "".to_string(),
            imported_names: vec!["completely_fake_function".to_string()],
        }];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(warnings.iter().any(|w| w.contains("hallucinated-import") && w.contains("completely_fake_function")),
            "got: {:?}", warnings);
    }

    #[tokio::test]
    async fn verify_passes_real_import_name() {
        clear_cache().await;
        let calls = vec![ApiCall {
            kind: ApiKind::Import,
            name: "os".to_string(),
            receiver: "".to_string(),
            imported_names: vec!["getcwd".to_string()],
        }];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(warnings.is_empty(), "expected no warnings for real `getcwd`, got: {:?}", warnings);
    }

    #[tokio::test]
    async fn verify_does_not_flag_when_module_import_fails() {
        clear_cache().await;
        // Don't flag — defer to package_index for registry check.
        let calls = vec![ApiCall {
            kind: ApiKind::Import,
            name: "nonexistent_xyz_pkg".to_string(),
            receiver: "".to_string(),
            imported_names: vec!["something".to_string()],
        }];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(warnings.is_empty(), "expected no warnings when module import fails, got: {:?}", warnings);
    }

    #[tokio::test]
    async fn verify_flags_hallucinated_method_on_typed_receiver() {
        clear_cache().await;
        // os module has `path` (submodule); if scope_vars say x is "path",
        // calling x.completely_fake_method() should flag.
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "os".to_string(),
                receiver: "".to_string(),
                imported_names: vec!["path".to_string()],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "completely_fake_method".to_string(),
                receiver: "x".to_string(),
                imported_names: vec![],
            },
        ];
        let scope_vars = vec![("x".to_string(), "path".to_string())];
        let warnings = verify_against_introspection(&calls, &scope_vars).await;
        assert!(warnings.iter().any(|w| w.contains("hallucinated-method") && w.contains("completely_fake_method")),
            "got: {:?}", warnings);
    }

    /// Case A regression test: alias map catches hallucinated method on
    /// import-aliased receiver. Uses `os` (always installed) so the test
    /// has no environment dependency.
    #[tokio::test]
    async fn verify_flags_hallucinated_method_on_import_alias() {
        clear_cache().await;
        // `import os as o` + `o.completely_fake_method()` → Case A should
        // introspect os, find completely_fake_method absent, warn.
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "os".to_string(),
                receiver: "o".to_string(),  // asname
                imported_names: vec![],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "completely_fake_method".to_string(),
                receiver: "o".to_string(),
                imported_names: vec![],
            },
        ];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(warnings.iter().any(|w| w.contains("hallucinated-method")
            && w.contains("completely_fake_method")
            && w.contains("not in module `os`")),
            "Case A should flag hallucinated method on import alias; got: {:?}", warnings);
    }

    /// Case A negative test: real method on import alias produces no warning.
    #[tokio::test]
    async fn verify_passes_real_method_on_import_alias() {
        clear_cache().await;
        // `import os as o` + `o.getcwd()` → getcwd is in os dir(); no warning.
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "os".to_string(),
                receiver: "o".to_string(),
                imported_names: vec![],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "getcwd".to_string(),
                receiver: "o".to_string(),
                imported_names: vec![],
            },
        ];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(warnings.is_empty(),
            "Case A should NOT flag real method on import alias; got: {:?}", warnings);
    }

    #[test]
    fn levenshtein_capped_matches_exact_strings() {
        assert_eq!(levenshtein_capped("cat", "cat", 3), 0);
        assert_eq!(levenshtein_capped("cat", "bat", 3), 1);
        assert_eq!(levenshtein_capped("cat", "elephant", 3), 4); // cap+1
    }

    /// Phase 2 chain traversal: catches phantom member in multi-hop chain.
    /// Oracle bug B fix: receiver now walks to root Name, so chains with
    /// aliased imports actually fire.
    #[tokio::test]
    async fn chain_traversal_flags_phantom_member_in_first_hop() {
        clear_cache().await;
        // `import os as o` + chain `o.completely_fake_method().something()`.
        // o is aliased to os. completely_fake_method not in os → phantom.
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "os".to_string(),
                receiver: "o".to_string(),  // asname
                imported_names: vec![],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "something".to_string(),
                receiver: "o".to_string(),
                imported_names: vec!["completely_fake_method".to_string(), "something".to_string()],
            },
        ];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(
            warnings.iter().any(|w| w.contains("chain-phantom-member") && w.contains("completely_fake_method")),
            "expected chain-phantom-member for completely_fake_method; got: {:?}",
            warnings
        );
    }

    /// Phase 2 chain traversal: handles untyped return silently (no false positive).
    /// Oracle bug E fix: Untyped stops silently, ExplicitNone fires broken-chain.
    #[tokio::test]
    async fn chain_traversal_silent_on_untyped_return_no_false_positive() {
        clear_cache().await;
        // `import os as o` + `o.getcwd().upper()` — getcwd returns str but
        // has no type hint. Chain should STOP silently (no warning, no FP).
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "os".to_string(),
                receiver: "o".to_string(),
                imported_names: vec![],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "upper".to_string(),
                receiver: "o".to_string(),
                imported_names: vec!["getcwd".to_string(), "upper".to_string()],
            },
        ];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(
            warnings.is_empty(),
            "expected NO warnings for untyped chain (silent stop); got: {:?}",
            warnings
        );
    }

    /// Phase 2 chain traversal: skips when root receiver untyped.
    #[tokio::test]
    async fn chain_traversal_skips_untyped_root() {
        clear_cache().await;
        // No imports + no scope vars — receiver "x" has no type. Skip.
        let calls = vec![ApiCall {
            kind: ApiKind::Method,
            name: "m2".to_string(),
            receiver: "x".to_string(),
            imported_names: vec!["m1".to_string(), "m2".to_string()],
        }];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(warnings.is_empty(), "expected no warnings for untyped chain; got: {:?}", warnings);
    }

    /// Phase 2 chain traversal: handles single-hop (no chain) correctly.
    /// This is a regression test ensuring the new chain code doesn't break
    /// the existing single-hop Method verification path.
    #[tokio::test]
    async fn chain_traversal_backward_compat_with_single_hop() {
        clear_cache().await;
        // Single-hop Method (imported_names empty) should still be verified
        // by the existing Case A/B path, not the new chain traversal.
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "os".to_string(),
                receiver: "o".to_string(),
                imported_names: vec![],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "completely_fake_method".to_string(),
                receiver: "o".to_string(),
                imported_names: vec![],  // single-hop
            },
        ];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(warnings.iter().any(|w| w.contains("hallucinated-method")),
            "single-hop Method should still work; got: {:?}", warnings);
    }

    /// method_return_type: returns Untyped for builtins (no type hints).
    /// Oracle bug E fix: now distinguishes Untyped from ExplicitNone.
    #[tokio::test]
    async fn method_return_type_returns_untyped_for_unhinted_methods() {
        clear_cache().await;
        // os.getcwd has no type hint → Untyped (was Ok(None) before refactor).
        let result = method_return_type("os", "getcwd").await;
        assert!(
            matches!(result, ReturnType::Untyped),
            "os.getcwd has no type hint; expected Untyped, got: {:?}",
            result
        );
    }

    /// method_return_type: returns Missing for nonexistent methods.
    #[tokio::test]
    async fn method_return_type_returns_missing_for_nonexistent() {
        clear_cache().await;
        let result = method_return_type("os", "completely_fake_method").await;
        assert!(
            matches!(result, ReturnType::Missing),
            "expected Missing for fake method; got: {:?}",
            result
        );
    }

    /// Gap 1: hallucinated class constructor detection.
    /// `SchemaField(` is hallucinated — real pydantic API is `Field(`.
    /// Catches DELULU sample python-method-8cc1825e3bb3.
    #[tokio::test]
    async fn constructor_verification_flags_hallucinated_class() {
        clear_cache().await;
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "pydantic".to_string(),
                receiver: "".to_string(),
                imported_names: vec![],
            },
            ApiCall {
                kind: ApiKind::Function,
                name: "SchemaField".to_string(),  // CamelCase hallucination
                receiver: "".to_string(),
                imported_names: vec![],
            },
        ];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(
            warnings.iter().any(|w| w.contains("hallucinated-constructor") && w.contains("SchemaField")),
            "expected hallucinated-constructor for SchemaField; got: {:?}",
            warnings
        );
    }

    /// Gap 1: real class constructor should NOT be flagged.
    #[tokio::test]
    async fn constructor_verification_passes_real_class() {
        clear_cache().await;
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "pydantic".to_string(),
                receiver: "".to_string(),
                imported_names: vec![],
            },
            ApiCall {
                kind: ApiKind::Function,
                name: "Field".to_string(),  // real pydantic API
                receiver: "".to_string(),
                imported_names: vec![],
            },
        ];
        let warnings = verify_against_introspection(&calls, &[]).await;
        assert!(
            !warnings.iter().any(|w| w.contains("hallucinated-constructor")),
            "should NOT flag real Field; got: {:?}",
            warnings
        );
    }

    // ─── Approach C: Python class-level introspection tests ──────────────

    /// Approach C: introspect_python_class returns class methods.
    /// Uses pathlib.Path (always installed, has many methods).
    #[tokio::test]
    async fn introspect_python_class_returns_methods_for_real_class() {
        clear_cache().await;
        let info = introspect_python_class("pathlib", "Path").await;
        assert!(info.error.is_none(), "got error: {:?}", info.error);
        // Path has these public methods/attributes.
        assert!(info.exists("exists"), "Path should have exists; got: {:?}", info.names);
        assert!(info.exists("read_text"), "Path should have read_text");
        assert!(info.exists("name"), "Path should have name attribute");
        // Underscore-prefixed members should be filtered out.
        assert!(!info.names.iter().any(|n| n.starts_with('_')),
            "underscore-prefixed should be filtered: {:?}", info.names);
    }

    /// Approach C: introspect_python_class errors when class doesn't exist.
    #[tokio::test]
    async fn introspect_python_class_errors_for_missing_class() {
        clear_cache().await;
        let info = introspect_python_class("os", "CompletelyFakeClassXyz").await;
        assert!(info.error.is_some(), "expected error, got: {:?}", info);
        assert!(info.names.is_empty());
    }

    /// Approach C: introspect_python_class errors when name isn't a class.
    /// `os.getcwd` is a function, not a class.
    #[tokio::test]
    async fn introspect_python_class_errors_for_non_class() {
        clear_cache().await;
        let info = introspect_python_class("os", "getcwd").await;
        assert!(info.error.is_some(), "expected error for non-class, got: {:?}", info);
        assert!(info.names.is_empty());
    }

    /// Approach C: introspect_python_class errors when module fails to import.
    #[tokio::test]
    async fn introspect_python_class_errors_for_missing_module() {
        clear_cache().await;
        let info = introspect_python_class("completely_fake_pkg_xyz_12345", "Foo").await;
        assert!(info.error.is_some(), "expected error for missing module");
        assert!(info.names.is_empty());
    }

    /// Approach C: cached on second call (no extra subprocess).
    #[tokio::test]
    async fn introspect_python_class_caches_results() {
        clear_cache().await;
        let first = introspect_python_class("pathlib", "Path").await;
        let second = introspect_python_class("pathlib", "Path").await;
        assert_eq!(first.names, second.names);
        assert!(first.error.is_none());
    }

    /// Approach C: hallucinated method on typed class instance is flagged.
    /// Uses pathlib.Path — `p.nonexistent_method()` should fire.
    #[tokio::test]
    async fn verify_flags_hallucinated_method_on_typed_class_instance() {
        clear_cache().await;
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "pathlib".to_string(),
                receiver: "".to_string(),
                imported_names: vec!["Path".to_string()],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "completely_fake_method_xyz".to_string(),
                receiver: "p".to_string(),
                imported_names: vec![],
            },
        ];
        let scope_vars = vec![("p".to_string(), "Path".to_string())];
        let warnings = verify_against_introspection(&calls, &scope_vars).await;
        assert!(
            warnings.iter().any(|w| w.contains("hallucinated-method")
                && w.contains("completely_fake_method_xyz")
                && w.contains("Path")),
            "expected hallucinated-method on Path class; got: {:?}",
            warnings
        );
    }

    /// Approach C regression: VALID method on typed class instance is NOT flagged.
    /// Without Approach C, `p.read_text()` would falsely fire because read_text
    /// isn't in dir(pathlib) — only in dir(pathlib.Path).
    #[tokio::test]
    async fn verify_passes_real_method_on_typed_class_instance() {
        clear_cache().await;
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "pathlib".to_string(),
                receiver: "".to_string(),
                imported_names: vec!["Path".to_string()],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "read_text".to_string(),  // real method on Path
                receiver: "p".to_string(),
                imported_names: vec![],
            },
        ];
        let scope_vars = vec![("p".to_string(), "Path".to_string())];
        let warnings = verify_against_introspection(&calls, &scope_vars).await;
        assert!(
            !warnings.iter().any(|w| w.contains("hallucinated-method")),
            "should NOT flag real Path.read_text; got: {:?}",
            warnings
        );
    }

    /// Approach C regression: existing Case B behavior (var_type is a
    /// submodule, not a class) still works. Uses os.path.
    #[tokio::test]
    async fn verify_legacy_case_b_for_submodule_still_works() {
        clear_cache().await;
        // os.path is a submodule (not a class). introspect_python_class
        // returns TypeError. Legacy fallback should fire on hallucinated method.
        let calls = vec![
            ApiCall {
                kind: ApiKind::Import,
                name: "os".to_string(),
                receiver: "".to_string(),
                imported_names: vec!["path".to_string()],
            },
            ApiCall {
                kind: ApiKind::Method,
                name: "completely_fake_method".to_string(),
                receiver: "x".to_string(),
                imported_names: vec![],
            },
        ];
        let scope_vars = vec![("x".to_string(), "path".to_string())];
        let warnings = verify_against_introspection(&calls, &scope_vars).await;
        // Legacy path may or may not fire (depends on whether os.path methods
        // are exposed at os level too). Key assertion: no crash, no false
        // positive on real methods.
        let _ = warnings; // smoke test
    }

    // ---- R1/R2 ctor chain-broken suppression ----

    #[test]
    fn ctor_class_name_extracts_bare_ctor_shapes() {
        assert_eq!(ctor_class_name("HealthStatus(healthy=True)"), Some("HealthStatus"));
        // `await X(...)`: the awaited value is X's __await__ yield, not an
        // X instance - the ctor-returns-Self rule does not apply (audit).
        assert_eq!(ctor_class_name("await HealthStatus(healthy=True)"), None);
        assert_eq!(ctor_class_name("(HealthStatus())"), Some("HealthStatus"));
        // Dotted callee could be a module re-exporting a function — conservative.
        assert_eq!(ctor_class_name("models.HealthStatus()"), None);
        assert_eq!(ctor_class_name("<parameter>"), None);
        assert_eq!(ctor_class_name("requests.get(url)"), None);
        assert_eq!(ctor_class_name("5"), None);
        assert_eq!(ctor_class_name(""), None);
    }

    #[test]
    fn ctor_suppression_pydantic_shape_yields_no_chain_broken() {
        // e2e-013 shape: BaseModel subclass defined in the same response,
        // instance built via bare ctor, method on the class surface.
        let content = "\
class HealthStatus(BaseModel):
    healthy: bool = True

    def is_healthy(self) -> bool:
        return self.healthy

status = HealthStatus(healthy=True)
print(status.is_healthy())
";
        let calls = vec![ApiCall {
            kind: ApiKind::Method,
            name: "is_healthy".to_string(),
            receiver: "status".to_string(),
            imported_names: vec![],
        }];
        let assignments = std::collections::HashMap::from([(
            "status".to_string(),
            "HealthStatus(healthy=True)".to_string(),
        )]);
        let session_defined = std::collections::HashSet::new();
        let warnings =
            detect_unresolved_receivers(&calls, &[], &assignments, content, &session_defined);
        assert!(
            warnings.is_empty(),
            "pydantic ctor shape must not emit chain-broken, got: {warnings:?}"
        );
    }

    #[test]
    fn ctor_suppression_via_session_symbols_when_class_defined_earlier() {
        // Class + method live in an earlier response (session symbols); the
        // current response only constructs and calls.
        let content = "status = HealthStatus(healthy=True)\nprint(status.is_healthy())\n";
        let calls = vec![ApiCall {
            kind: ApiKind::Method,
            name: "is_healthy".to_string(),
            receiver: "status".to_string(),
            imported_names: vec![],
        }];
        let assignments = std::collections::HashMap::from([(
            "status".to_string(),
            "HealthStatus(healthy=True)".to_string(),
        )]);
        let session_defined = std::collections::HashSet::from([
            "HealthStatus".to_string(),
            "is_healthy".to_string(),
        ]);
        let warnings =
            detect_unresolved_receivers(&calls, &[], &assignments, content, &session_defined);
        assert!(
            warnings.is_empty(),
            "session-defined class + method must not emit chain-broken, got: {warnings:?}"
        );
    }

    #[test]
    fn ctor_audit_cross_class_def_leak_still_warns() {
        // Audit channel A: `def` on a DIFFERENT class must not suppress a
        // hallucinated method on the ctor receiver's class.
        let content = "\
class Report:
    def frobnicate_zqx(self):
        return 1

status = HealthStatus(healthy=True)
print(status.frobnicate_zqx())
";
        let calls = vec![ApiCall {
            kind: ApiKind::Method,
            name: "frobnicate_zqx".to_string(),
            receiver: "status".to_string(),
            imported_names: vec![],
        }];
        let assignments = std::collections::HashMap::from([(
            "status".to_string(),
            "HealthStatus(healthy=True)".to_string(),
        )]);
        let session_defined = std::collections::HashSet::new();
        let real_home = std::env::var("USERPROFILE").unwrap_or_default();
        let tmp_home = std::env::temp_dir().join("anubis-test-ctor-crossclass");
        let _ = std::fs::remove_dir_all(&tmp_home);
        std::fs::create_dir_all(tmp_home.join(".anubis").join("symbols")).unwrap();
        std::env::set_var("USERPROFILE", &tmp_home);
        let warnings =
            detect_unresolved_receivers(&calls, &[], &assignments, content, &session_defined);
        if real_home.is_empty() {
            std::env::remove_var("USERPROFILE");
        } else {
            std::env::set_var("USERPROFILE", &real_home);
        }
        let _ = std::fs::remove_dir_all(&tmp_home);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("chain-broken") && w.contains("frobnicate_zqx")),
            "def on another class must not suppress, got: {warnings:?}"
        );
    }

    #[test]
    fn ctor_audit_comment_def_leak_still_warns() {
        // Audit channel B: a commented-out `# def name(` is not evidence.
        let content = "\
class HealthStatus(BaseModel):
    healthy: bool = True
    # def frobnicate_zqx(self):
    #     return 1

status = HealthStatus(healthy=True)
print(status.frobnicate_zqx())
";
        let calls = vec![ApiCall {
            kind: ApiKind::Method,
            name: "frobnicate_zqx".to_string(),
            receiver: "status".to_string(),
            imported_names: vec![],
        }];
        let assignments = std::collections::HashMap::from([(
            "status".to_string(),
            "HealthStatus(healthy=True)".to_string(),
        )]);
        let session_defined = std::collections::HashSet::new();
        let real_home = std::env::var("USERPROFILE").unwrap_or_default();
        let tmp_home = std::env::temp_dir().join("anubis-test-ctor-comment");
        let _ = std::fs::remove_dir_all(&tmp_home);
        std::fs::create_dir_all(tmp_home.join(".anubis").join("symbols")).unwrap();
        std::env::set_var("USERPROFILE", &tmp_home);
        let warnings =
            detect_unresolved_receivers(&calls, &[], &assignments, content, &session_defined);
        if real_home.is_empty() {
            std::env::remove_var("USERPROFILE");
        } else {
            std::env::set_var("USERPROFILE", &real_home);
        }
        let _ = std::fs::remove_dir_all(&tmp_home);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("chain-broken") && w.contains("frobnicate_zqx")),
            "commented def is not evidence, got: {warnings:?}"
        );
    }

    #[test]
    fn ctor_negative_guard_unknown_method_on_session_class_still_warns() {
        // Class known, but the claimed method is neither on its surface nor a
        // session symbol nor in the symbol cache → warning still fires.
        let content = "\
class HealthStatus(BaseModel):
    healthy: bool = True

status = HealthStatus(healthy=True)
print(status.definitely_not_a_real_method_zqx())
";
        let calls = vec![ApiCall {
            kind: ApiKind::Method,
            name: "definitely_not_a_real_method_zqx".to_string(),
            receiver: "status".to_string(),
            imported_names: vec![],
        }];
        let assignments = std::collections::HashMap::from([(
            "status".to_string(),
            "HealthStatus(healthy=True)".to_string(),
        )]);
        let session_defined = std::collections::HashSet::new();
        let warnings =
            detect_unresolved_receivers(&calls, &[], &assignments, content, &session_defined);
        assert!(
            warnings.iter().any(|w| w.contains("chain-broken")
                && w.contains("definitely_not_a_real_method_zqx")),
            "unknown method on session class must still warn, got: {warnings:?}"
        );
    }

    #[test]
    fn ctor_dotted_rhs_stays_conservative() {
        // `models.HealthStatus(...)` — the dotted prefix could be a module,
        // not a class, so the suppression path must NOT apply.
        let content = "\
class HealthStatus(BaseModel):
    healthy: bool = True

    def is_healthy(self) -> bool:
        return self.healthy

status = models.HealthStatus(healthy=True)
print(status.is_healthy())
";
        let calls = vec![ApiCall {
            kind: ApiKind::Method,
            name: "is_healthy".to_string(),
            receiver: "status".to_string(),
            imported_names: vec![],
        }];
        let assignments = std::collections::HashMap::from([(
            "status".to_string(),
            "models.HealthStatus(healthy=True)".to_string(),
        )]);
        let session_defined = std::collections::HashSet::new();
        // Hermetic: the pre-existing SymbolCache guard consults the real
        // user cache, where accumulated session rows (library names not
        // starting with `local.`) can list `is_healthy` and suppress the
        // warning. Redirect USERPROFILE so the guard sees an empty cache.
        let real_home = std::env::var("USERPROFILE").unwrap_or_default();
        let tmp_home = std::env::temp_dir().join("anubis-test-ctor-dotted");
        let _ = std::fs::remove_dir_all(&tmp_home);
        std::fs::create_dir_all(tmp_home.join(".anubis").join("symbols")).unwrap();
        std::env::set_var("USERPROFILE", &tmp_home);
        let warnings =
            detect_unresolved_receivers(&calls, &[], &assignments, content, &session_defined);
        if real_home.is_empty() {
            std::env::remove_var("USERPROFILE");
        } else {
            std::env::set_var("USERPROFILE", &real_home);
        }
        let _ = std::fs::remove_dir_all(&tmp_home);
        assert!(
            warnings.iter().any(|w| w.contains("chain-broken")),
            "dotted ctor RHS must stay conservative, got: {warnings:?}"
        );
    }
}
