//! AST-based API extraction (FORGE 2026 pattern).
//!
//! Replaces regex-based `extract_api_claims` for Python. Uses Python's own
//! `ast` module via subprocess — perfect parsing, no tree-sitter dependency,
//! Python always available when user is writing Python code.
//!
//! FORGE 2026 (arxiv 2601.19106) reports 100% precision / 87.6% recall
//! using AST extraction + dynamic KB introspection, vs ~50-60% recall
//! with regex extraction. This module implements the AST half; see
//! `local_introspect` for the KB half.
//!
//! Future: extend to TypeScript (via `tsc`), Rust (via `syn` crate),
//! Go (via `go/parser` subprocess). Each as a separate module.

use std::collections::HashSet;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Structured API call extracted from AST.
///
/// Distinguishes call kinds because the FORGE pipeline handles them
/// differently:
///   - Function: `printf(` — verify against module functions
///   - Method:   `obj.method(` — verify against obj's type methods
///   - Attribute: `obj.field` (no call) — verify against type fields
///   - Import:   `from X import Y` — verify against package index
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiCall {
    pub kind: ApiKind,
    /// For Function: function name (e.g., "printf").
    /// For Method/Attribute: method/attribute name (e.g., "fit_transform").
    /// For Import: full module path (e.g., "sklearn.preprocessing").
    pub name: String,
    /// For Method/Attribute: receiver expression as it appears in source
    /// (e.g., "PolynomialFeatures" or "df" — verbatim, not type-resolved).
    /// For Function/Import: empty.
    pub receiver: String,
    /// For Import: the imported names (e.g., ["PolynomialFeatures"]). Empty otherwise.
    pub imported_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiKind {
    Function,
    Method,
    Attribute,
    Import,
    /// User-defined function via `def name(...):`. Emitted so callers (e.g.,
    /// verify_against_introspection's bare-call check) can skip bare calls
    /// to functions defined in the same module. Not a call itself.
    FunctionDef,
}

/// Extract API calls from Python source via `python -c` subprocess.
///
/// Returns Err if Python isn't available or source doesn't parse. Caller
/// should fall back to regex `extract_api_claims` on Err.
///
/// Time budget: ~50-100ms per call (Python startup + parse).
pub async fn extract_python_apis(source: &str) -> Result<Vec<ApiCall>, String> {
    // Inline Python script: parse source, walk AST, emit JSON.
    // We feed source via stdin to avoid shell-escaping nightmares.
    let script = r#"
import ast, json, sys

# Read raw bytes and decode with errors='replace' to handle malformed unicode
# (surrogate chars, truncated multi-byte sequences) without crashing ast.parse.
raw = sys.stdin.buffer.read()
source = raw.decode('utf-8', errors='replace')

# Robust parse: when source is a fragment spliced from tool_use JSON values
# (Anthropic Update newString/oldString), it may contain statements that are
# invalid at module scope (e.g., `return` outside a function, dedented
# fragments). Fall back to per-statement parsing so we still extract API
# calls from the valid portions.
def parse_fragments(src):
    try:
        return [ast.parse(src)]
    except SyntaxError:
        trees = []
        # Try parsing each contiguous block separated by blank lines.
        # This catches cases like:
        #   return text.to_snake()  # invalid alone
        #   <blank>
        #   def to_camel_case(text): ...  # valid
        blocks = []
        cur = []
        for line in src.splitlines():
            if line.strip():
                cur.append(line)
            else:
                if cur:
                    blocks.append('\n'.join(cur))
                    cur = []
        if cur:
            blocks.append('\n'.join(cur))
        for block in blocks:
            try:
                trees.append(ast.parse(block))
            except SyntaxError:
                # Last resort: wrap in a dummy function so `return` works.
                try:
                    wrapped = "def _frag():\n" + '\n'.join('    ' + l for l in block.splitlines())
                    trees.append(ast.parse(wrapped))
                except SyntaxError:
                    pass
        return trees

trees = parse_fragments(source)
out = []
def _walk_all(trees):
    for t in trees:
        for n in ast.walk(t):
            yield n
# Oracle bug A fix: track processed Call node ids so we don't emit
# multiple entries for nested Calls in a chain (obj.m1().m2() visits
# 3 Call nodes via ast.walk; only the outermost should emit).
processed_call_ids = set()

def name_of(node):
    """Get dotted name from Attribute/Name node, e.g., sklearn.preprocessing.PolynomialFeatures."""
    if isinstance(node, ast.Attribute):
        parent = name_of(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return name_of(node.func)
    return ""

def walk_chain_root(node):
    """Oracle bug B fix: walk Attribute/Call chain down to terminal Name.
    Returns root variable name (e.g., 'obj' for obj.m1().m2()) or '' for
    literals/complex expressions.
    """
    cur = node
    seen = 0  # prevent infinite loops on pathological trees
    while seen < 50:
        seen += 1
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Name):
            return cur.id
        else:
            return ""
    return ""

def receiver_of(node):
    """Legacy: returns immediate Name or ''. Use walk_chain_root for chains."""
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            return node.value.id
        return ""
    return ""

def walk_chain_marks_processed(call_node, processed):
    """Mark only nested Call nodes IN THE RECEIVER CHAIN as processed.
    
    Oracle Phase 2 fix verification found that walking the ENTIRE subtree
    via ast.walk(call_node) suppressed legitimate argument calls like
    df.fillna(df.mean()) — mean() on different receiver was suppressed.
    
    Fix: only mark the receiver chain (cur.func.value chain walked in the
    Call handler). Argument calls on different receivers stay verifiable.
    """
    cur = call_node.func.value
    while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
        processed.add(id(cur))
        cur = cur.func.value

for node in _walk_all(trees):
    # from X import Y[, Z]
    if isinstance(node, ast.ImportFrom) and node.module:
        for alias in node.names:
            out.append({
                "kind": "Import",
                "name": node.module,
                "receiver": "",
                "imported_names": [a.name for a in node.names],
            })
        continue
    # import X.Y.Z [as alias]
    # receiver field captures asname (e.g., "st" for `import streamlit as st`).
    # Empty receiver = no alias (must use full name as receiver).
    if isinstance(node, ast.Import):
        for alias in node.names:
            out.append({
                "kind": "Import",
                "name": alias.name,
                "receiver": alias.asname or "",
                "imported_names": [],
            })
        continue
    # Function call: foo(...) or obj.method(...)
    if isinstance(node, ast.Call):
        # Oracle bug A fix: skip if already processed as part of an outer chain.
        if id(node) in processed_call_ids:
            continue
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            # Oracle bug B fix: walk to root Name for chain receiver.
            receiver = walk_chain_root(node.func)
            # Walk chained calls: obj.m1().m2().m3()
            # ALSO walk intermediate Attribute access: np.random.randn(...)
            # → chain_methods = ['random', 'randn'] so Case A (module alias
            # check) skips it (would otherwise flag "randn not in module numpy"
            # for what is really a multi-hop submodule call). The chain
            # traversal path (Case B) handles these via return-type walk.
            chain_methods = [method]
            cur = node.func.value
            while True:
                if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
                    chain_methods.append(cur.func.attr)
                    cur = cur.func.value
                elif isinstance(cur, ast.Attribute):
                    chain_methods.append(cur.attr)
                    cur = cur.value
                else:
                    break
            chain_methods.reverse()
            # Oracle bug A fix: mark all inner Calls as processed so ast.walk
            # doesn't emit them as separate entries.
            walk_chain_marks_processed(node, processed_call_ids)
            if len(chain_methods) == 1:
                out.append({
                    "kind": "Method",
                    "name": method,
                    "receiver": receiver,
                    "imported_names": [],
                })
            else:
                # Multi-hop chain. receiver = root variable name.
                # imported_names = chain methods/attrs in order [m1, m2, m3, ...].
                # name = final method (kept for compatibility).
                out.append({
                    "kind": "Method",
                    "name": method,
                    "receiver": receiver,
                    "imported_names": chain_methods,
                })
        elif isinstance(node.func, ast.Name):
            out.append({
                "kind": "Function",
                "name": node.func.id,
                "receiver": "",
                "imported_names": [],
            })
        continue
    # Attribute access (no call): obj.field
    # Skip if already covered by Call handling above.
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        attr = node.attr
        receiver = receiver_of(node)
        # Dedupe against Method entries.
        entry = {
            "kind": "Attribute",
            "name": attr,
            "receiver": receiver,
            "imported_names": [],
        }
        if entry not in out:
            out.append(entry)
        continue
    # Function definitions: def name(...) / async def name(...)
    # Emitted as FunctionDef so callers can build a "user-defined names"
    # skip set (e.g., bare-call check at local_introspect.rs avoids flagging
    # `main()` when `def main()` exists in the same module).
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        out.append({
            "kind": "FunctionDef",
            "name": node.name,
            "receiver": "",
            "imported_names": [],
        })
        continue

print(json.dumps(out))
"#;

    let mut child = crate::scanner::command_hidden_tokio("python")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn python: {e}"))?;

    // Write source to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(source.as_bytes())
            .await
            .map_err(|e| format!("write stdin: {e}"))?;
        // Drop stdin to signal EOF.
    }

    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .map_err(|_| "python subprocess timed out (5s)".to_string())?
        .map_err(|e| format!("wait: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Python parse error → source has syntax issues. Don't crash, just fall back.
        if stderr.contains("SyntaxError") {
            return Err(format!("python SyntaxError: {}", stderr.lines().next().unwrap_or("")));
        }
        return Err(format!("python exit {:?}: {}", output.status, stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Vec<ApiCall> = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("parse JSON: {e} (raw: {})", crate::scanner::safe_slice_to(&stdout, 200)))?;

    // Dedupe (Attribute + Method often duplicate).
    let mut seen = HashSet::new();
    let deduped: Vec<ApiCall> = parsed.into_iter().filter(|c| seen.insert(c.clone())).collect();
    Ok(deduped)
}

/// Extract variable-to-source-expression assignments from Python source.
///
/// Returns a map of variable name → RHS source expression (via `ast.unparse`).
/// Used by `local_introspect::detect_unresolved_receivers` to identify Method
/// calls whose receiver was assigned from a function call (e.g.,
/// `resp = requests.get(...)` → `{"resp": "requests.get(url, timeout=10)"}`).
/// This is the data type inference needs but can't get from regex patterns
/// alone (scope_analysis only catches `var = ClassName(...)` with uppercase
/// type, missing `var = module.function(...)` patterns).
///
/// Time budget: ~50-100ms per call (Python startup + parse).
pub async fn extract_python_assignments(
    source: &str,
) -> Result<std::collections::HashMap<String, String>, String> {
    let script = r#"
import ast, json, sys
raw = sys.stdin.buffer.read()
source = raw.decode('utf-8', errors='replace')

# Robust parse: handle fragments from tool_use JSON (Anthropic Update
# newString/oldString). See extract_python_apis for details.
def parse_fragments(src):
    try:
        return [ast.parse(src)]
    except SyntaxError:
        trees = []
        blocks = []
        cur = []
        for line in src.splitlines():
            if line.strip():
                cur.append(line)
            else:
                if cur:
                    blocks.append('\n'.join(cur))
                    cur = []
        if cur:
            blocks.append('\n'.join(cur))
        for block in blocks:
            try:
                trees.append(ast.parse(block))
            except SyntaxError:
                try:
                    wrapped = "def _frag():\n" + '\n'.join('    ' + l for l in block.splitlines())
                    trees.append(ast.parse(wrapped))
                except SyntaxError:
                    pass
        return trees

trees = parse_fragments(source)
out = {}
def _walk_all(trees):
    for t in trees:
        for n in ast.walk(t):
            yield n
for node in _walk_all(trees):
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        if isinstance(target, ast.Name):
            try:
                rhs = ast.unparse(node.value)
            except Exception:
                rhs = '<unparseable>'
            out[target.id] = rhs
    elif isinstance(node, ast.FunctionDef):
        # Collect function parameters as synthetic assignments so
        # detect_unresolved_receivers can flag Method calls on parameters
        # whose type can't be inferred (no annotation, no first-use pattern).
        # Covers cases like `def f(text): text.reverse()` and
        # `def g(options): options.has_key(key)`.
        for arg in node.args.args:
            if arg.arg not in out and arg.arg not in ('self', 'cls'):
                out[arg.arg] = '<parameter>'
print(json.dumps(out))
"#;
    let mut child = crate::scanner::command_hidden_tokio("python")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn python: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(source.as_bytes())
            .await
            .map_err(|e| format!("write stdin: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("python exit {}: {}", output.status, err));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: std::collections::HashMap<String, String> =
        serde_json::from_str(stdout.trim()).map_err(|e| {
            format!("parse python output: {e} (stdout: {})", stdout.trim())
        })?;
    Ok(parsed)
}

/// Extract undefined variable names from Python source.
///
/// Uses Python's `ast` module to:
/// 1. Collect all defined names (assignments, params, imports, for/with vars, def/class names)
/// 2. Collect all referenced names (Name nodes in Load context)
/// 3. Return the difference (referenced but not defined)
///
/// Catches DELULU samples like:
///   - `matrixA` used but never defined (should be `A`)
///   - `llm_exception` used but never defined (should be `e`)
///
/// Time budget: ~50-100ms per call (Python startup + parse).
pub async fn extract_undefined_variables(source: &str) -> Result<Vec<String>, String> {
    let script = r#"
import ast, json, sys, builtins

# Read raw bytes and decode with errors='replace' to handle malformed unicode
# (surrogate chars, truncated multi-byte sequences) without crashing ast.parse.
# This matters for real-world code that contains unusual unicode in strings/comments.
raw = sys.stdin.buffer.read()
source = raw.decode('utf-8', errors='replace')

# Fragment-based parsing: when source contains multiple code blocks
# (imports in block 1, usage in block 5), single ast.parse can't see
# imports across blocks. Use parse_fragments + _walk_all (same approach
# as extract_python_apis, commit 3c0605e). Kills Django/DRF FPs where
# imports were in a separate code block from usage.
def parse_fragments(src):
    try:
        return [ast.parse(src)]
    except SyntaxError:
        trees = []
        blocks = []
        cur = []
        for line in src.splitlines():
            if line.strip():
                cur.append(line)
            else:
                if cur:
                    blocks.append('\n'.join(cur))
                    cur = []
        if cur:
            blocks.append('\n'.join(cur))
        for block in blocks:
            try:
                trees.append(ast.parse(block))
            except SyntaxError:
                try:
                    wrapped = "def _frag():\n" + '\n'.join('    ' + l for l in block.splitlines())
                    trees.append(ast.parse(wrapped))
                except SyntaxError:
                    pass
        return trees

def _walk_all(trees):
    for t in trees:
        for node in ast.walk(t):
            yield node

trees = parse_fragments(source)
defined = set()
referenced = set()

# Built-in names that are always available.
for name in dir(builtins):
    defined.add(name)
# Common implicit names.
defined.update(['__name__', '__file__', '__doc__', '__package__', '__spec__', '__init__', '__main__'])
# Implicit method receivers. Fragments are frequently partial method bodies
# (quoted or authored mid-class); `self`/`cls` are bound by the enclosing
# method, not the fragment. Flagging them is a fragment-visibility FP.
# (self at true module level is a NameError caught instantly at runtime.)
defined.update(['self', 'cls'])

def collect_target(target):
    """Recursively collect assignment target names."""
    if isinstance(target, ast.Name):
        defined.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            collect_target(elt)
    elif isinstance(target, ast.Starred):
        collect_target(target.value)
    elif isinstance(target, ast.Attribute):
        pass  # obj.attr = ... doesn't define a new name
    elif isinstance(target, ast.Subscript):
        pass  # obj[key] = ... doesn't define a new name

for node in _walk_all(trees):
    # Assignments: x = ..., x, y = ..., x += ...
    if isinstance(node, ast.Assign):
        for target in node.targets:
            collect_target(target)
    elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
        collect_target(node.target)
    # Function/class definitions.
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        defined.add(node.name)
        # Function parameters.
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            defined.add(arg.arg)
        if node.args.vararg:
            defined.add(node.args.vararg.arg)
        if node.args.kwarg:
            defined.add(node.args.kwarg.arg)
    elif isinstance(node, ast.ClassDef):
        defined.add(node.name)
    # Imports: import X, import X as Y, from M import N
    elif isinstance(node, ast.Import):
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name.split('.')[0]
            defined.add(name)
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            defined.add(name)
    # For loop variables.
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        collect_target(node.target)
    # With ... as variables.
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars:
                collect_target(item.optional_vars)
    # Except handler variables: except Exception as e:
    # Without this, `e` would be flagged as undefined in golden completions.
    elif isinstance(node, ast.ExceptHandler):
        if node.name:
            defined.add(node.name)
    # Comprehension targets.
    elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        for gen in node.generators:
            collect_target(gen.target)
    # Walrus operator.
    elif isinstance(node, ast.NamedExpr):
        collect_target(node.target)
    # Lambda parameters.
    elif isinstance(node, ast.Lambda):
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            defined.add(arg.arg)

    # Collect Name references in Load context.
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        referenced.add(node.id)

# Undefined = referenced - defined.
undefined = sorted(referenced - defined)
print(json.dumps(undefined))
"#;

    let mut child = crate::scanner::command_hidden_tokio("python")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn python: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(source.as_bytes())
            .await
            .map_err(|e| format!("write stdin: {e}"))?;
    }

    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .map_err(|_| "python subprocess timed out (5s)".to_string())?
        .map_err(|e| format!("wait: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("SyntaxError") {
            return Err(format!("python SyntaxError: {}", stderr.lines().next().unwrap_or("")));
        }
        return Err(format!("python exit {:?}: {}", output.status, stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let undefined: Vec<String> = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("parse JSON: {e} (raw: {})", crate::scanner::safe_slice_to(&stdout, 200)))?;
    Ok(undefined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn extract_finds_simple_function_call() {
        let src = "print('hello')";
        let calls = extract_python_apis(src).await.unwrap();
        assert!(calls.iter().any(|c| c.kind == ApiKind::Function && c.name == "print"),
            "got: {:?}", calls);
    }

    #[tokio::test]
    async fn extract_finds_method_call_on_name() {
        let src = "df.head()";
        let calls = extract_python_apis(src).await.unwrap();
        assert!(calls.iter().any(|c| c.kind == ApiKind::Method && c.name == "head" && c.receiver == "df"),
            "got: {:?}", calls);
    }

    #[tokio::test]
    async fn extract_finds_from_import() {
        let src = "from sklearn.preprocessing import PolynomialFeatures";
        let calls = extract_python_apis(src).await.unwrap();
        let imp = calls.iter().find(|c| c.kind == ApiKind::Import).unwrap();
        assert_eq!(imp.name, "sklearn.preprocessing");
        assert_eq!(imp.imported_names, vec!["PolynomialFeatures".to_string()]);
    }

    #[tokio::test]
    async fn extract_finds_plain_import() {
        let src = "import os.path";
        let calls = extract_python_apis(src).await.unwrap();
        let imp = calls.iter().find(|c| c.kind == ApiKind::Import).unwrap();
        assert_eq!(imp.name, "os.path");
    }

    #[tokio::test]
    async fn extract_finds_attribute_access() {
        let src = "config.debug = True";
        let calls = extract_python_apis(src).await.unwrap();
        // Attribute store, not load — should not be extracted.
        // But `x = config.debug` should be.
        let src2 = "x = config.debug";
        let calls2 = extract_python_apis(src2).await.unwrap();
        assert!(calls2.iter().any(|c| c.kind == ApiKind::Attribute && c.name == "debug" && c.receiver == "config"),
            "got: {:?}", calls2);
    }

    #[tokio::test]
    async fn extract_handles_chained_calls_gracefully() {
        // obj.method1().method2() — Oracle bug B fix: walk_chain_root resolves
        // root Name "obj" for both methods. Bug A fix: only outermost Call
        // emits; method1 is single-hop, method2 is chain entry.
        let src = "obj.method1().method2()";
        let calls = extract_python_apis(src).await.unwrap();
        // Bug A fix: exactly ONE Method entry, name="method2", receiver="obj",
        // imported_names=[method1, method2].
        let methods: Vec<_> = calls.iter().filter(|c| c.kind == super::ApiKind::Method).collect();
        assert_eq!(methods.len(), 1, "Bug A: exactly one Method entry for chain; got: {:?}", methods);
        let m2 = &methods[0];
        assert_eq!(m2.name, "method2");
        assert_eq!(m2.receiver, "obj", "Bug B fix: receiver walks to root");
        assert_eq!(m2.imported_names, vec!["method1".to_string(), "method2".to_string()],
            "chain methods in left-to-right order");
    }

    /// Oracle Phase 2 verification: regression test for argument-call suppression.
    /// `df.fillna(df.mean())` must emit 2 Method entries (fillna + mean), not 1.
    /// The over-aggressive walk_chain_marks_processed was suppressing arg calls.
    #[tokio::test]
    async fn extract_does_not_suppress_argument_calls_on_different_receivers() {
        let src = "df.fillna(df.mean())";
        let calls = extract_python_apis(src).await.unwrap();
        let methods: Vec<_> = calls.iter().filter(|c| c.kind == super::ApiKind::Method).collect();
        assert!(methods.iter().any(|c| c.name == "fillna" && c.receiver == "df"),
            "fillna must be extracted; got: {:?}", methods);
        assert!(methods.iter().any(|c| c.name == "mean" && c.receiver == "df"),
            "mean (argument call) must be extracted; got: {:?}", methods);
    }

    #[tokio::test]
    async fn extract_returns_err_on_syntax_error() {
        let src = "def broken(:";  // invalid syntax
        let result = extract_python_apis(src).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("SyntaxError"), "got: {}", err);
    }

    #[tokio::test]
    async fn extract_dedupes_attribute_and_method() {
        // df.head accessed as attribute AND called as method should dedupe.
        let src = "a = df.head\nb = df.head()";
        let calls = extract_python_apis(src).await.unwrap();
        // Both Attribute(head, df) and Method(head, df) appear, but each unique.
        let attrs: Vec<_> = calls.iter().filter(|c| c.name == "head").collect();
        assert!(attrs.len() >= 1, "got: {:?}", calls);
    }

    #[tokio::test]
    async fn extract_handles_empty_source() {
        let calls = extract_python_apis("").await.unwrap();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn extract_handles_complex_python_source() {
        let src = r#"
import pandas as pd
from sklearn.preprocessing import StandardScaler
import numpy as np

df = pd.DataFrame({'a': [1, 2, 3]})
scaler = StandardScaler()
X = scaler.fit_transform(df[['a']])
mean = np.mean(df['a'])
result = df.describe()
"#;
        let calls = extract_python_apis(src).await.unwrap();
        // Check key calls present.
        assert!(calls.iter().any(|c| c.kind == ApiKind::Import && c.name == "pandas"));
        assert!(calls.iter().any(|c| c.kind == ApiKind::Import && c.name == "sklearn.preprocessing"));
        assert!(calls.iter().any(|c| c.kind == ApiKind::Import && c.name == "numpy"));
        assert!(calls.iter().any(|c| c.kind == ApiKind::Method && c.name == "fit_transform" && c.receiver == "scaler"));
        assert!(calls.iter().any(|c| c.kind == ApiKind::Method && c.name == "mean" && c.receiver == "np"),
            "np.mean should be Method with receiver=np; got: {:?}", calls);
    }

    // ── extract_undefined_variables tests ──

    #[tokio::test]
    async fn undefined_finds_undefined_variable() {
        let src = "print(matrixA)";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(undefined.contains(&"matrixA".to_string()), "got: {:?}", undefined);
    }

    #[tokio::test]
    async fn undefined_passes_defined_variable() {
        let src = "x = 5\nprint(x)";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(!undefined.contains(&"x".to_string()), "got: {:?}", undefined);
    }

    #[tokio::test]
    async fn undefined_passes_imported_names() {
        let src = "import os\nprint(os.getcwd())";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(undefined.is_empty(), "got: {:?}", undefined);
    }

    #[tokio::test]
    async fn undefined_passes_function_params() {
        let src = "def foo(x):\n    return x";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(undefined.is_empty(), "got: {:?}", undefined);
    }

    #[tokio::test]
    async fn undefined_passes_for_loop_vars() {
        let src = "for i in range(10):\n    print(i)";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(undefined.is_empty(), "got: {:?}", undefined);
    }

    #[tokio::test]
    async fn undefined_skips_builtins() {
        let src = "print(len([]))";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(undefined.is_empty(), "got: {:?}", undefined);
    }

    #[tokio::test]
    async fn undefined_handles_multiple_undefined() {
        let src = "result = foo(bar, matrixA)";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(undefined.contains(&"foo".to_string()), "got: {:?}", undefined);
        assert!(undefined.contains(&"bar".to_string()), "got: {:?}", undefined);
        assert!(undefined.contains(&"matrixA".to_string()), "got: {:?}", undefined);
        assert!(!undefined.contains(&"result".to_string()), "result is defined");
    }

    #[tokio::test]
    async fn undefined_handles_walrus_operator() {
        let src = "if (n := 10) > 5:\n    print(n)";
        let undefined = extract_undefined_variables(src).await.unwrap();
        assert!(undefined.is_empty(), "got: {:?}", undefined);
    }

    #[tokio::test]
    async fn extract_marks_multi_hop_attribute_chain_as_chain() {
        // Regression: st.session_state.config.get(...) must NOT collapse to
        // receiver="st", name="get" — that triggered false "st.get not in
        // module streamlit" warnings. After fix: chain_methods includes the
        // intermediate attribute ("config", "get") so verify_against_introspection's
        // Case A (module-alias check) skips it.
        let src = "import streamlit as st\nst.session_state.config.get('key')";
        let calls = extract_python_apis(src).await.unwrap();
        let chain_call = calls.iter().find(|c| c.kind == ApiKind::Method && c.name == "get")
            .expect("get() Method call must be extracted");
        assert!(!chain_call.imported_names.is_empty(),
            "multi-hop chain must have non-empty imported_names, got: {:?}", chain_call);
        assert!(chain_call.imported_names.contains(&"session_state".to_string()),
            "imported_names must include intermediate attrs, got: {:?}", chain_call.imported_names);
    }

    #[tokio::test]
    async fn extract_keeps_single_hop_call_as_non_chain() {
        // Sanity: st.error(...) must still be a single-hop call (imported_names empty).
        let src = "import streamlit as st\nst.error('boom')";
        let calls = extract_python_apis(src).await.unwrap();
        let call = calls.iter().find(|c| c.kind == ApiKind::Method && c.name == "error")
            .expect("error() Method call must be extracted");
        assert!(call.imported_names.is_empty(),
            "single-hop call must have empty imported_names, got: {:?}", call);
        assert_eq!(call.receiver, "st");
    }

    // ─────────────────────────────────────────────────────────────────
    // REPRO: resp.parse_json() hallucination silently passes L1.5.
    //
    // Real-world bug (2026-08-06): Claude Code generates Python that
    // calls `resp.parse_json()` (a hallucinated method — the real one is
    // `resp.json()`). Anubis does NOT catch it. Scanner log shows
    // "L2.5 cascade: skipping L3 (L1.5 fully resolved) method_calls=0".
    //
    // Root cause (this test demonstrates it):
    //   1. extract_python_apis DOES emit parse_json as a Method call.
    //   2. scope_analysis::analyze_scope CANNOT infer `resp`'s type from
    //      `resp = requests.get(url, timeout=10)` because the Python
    //      inferred-type regex only matches constructor patterns
    //      (`var = ClassName(`). Function-return patterns are unsupported.
    //   3. verify_against_introspection Case B silently `continue`s
    //      when the receiver is missing from scope_vars — no warning,
    //      no counter increment.
    //   4. run_forge_python returns zero hallucinations → cascade skips L3.
    //
    // Run: cargo test extract_repro_resp_parse_json_hallucination --package anubis-daemon -- --nocapture
    // ─────────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn extract_repro_resp_parse_json_hallucination() {
        let src = r#"
import requests
def fetch_user(user_id):
    url = f"https://api.example.com/users/{user_id}"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.parse_json()
"#;

        // (1) extract_python_apis DOES emit parse_json as a Method.
        let calls = extract_python_apis(src).await.expect("python extraction must succeed");
        let parse_json = calls.iter().find(|c| c.kind == ApiKind::Method && c.name == "parse_json")
            .expect("BUG if absent: parse_json Method call MUST be extracted");
        assert_eq!(parse_json.receiver, "resp",
            "receiver must be 'resp', got: {:?}", parse_json);

        // (2) analyze_scope CANNOT infer resp's type from `resp = requests.get(...)`.
        let scope = crate::scanner::scope_analysis::analyze_scope(src);
        assert!(
            !scope.vars.contains_key("resp"),
            "PRECONDITION VIOLATED: if this passes, analyze_scope learned to infer \
             function-return types and the bug may already be fixed. \
             vars seen: {:?}",
            scope.vars,
        );

        // (3) verify_against_introspection returns ZERO warnings when scope_vars is empty
        //     (the production condition — analyze_scope failed to type-infer resp).
        let empty_scope: Vec<(String, String)> = Vec::new();
        // verify_against_introspection alone returns [] — that's by design
        // (Case B silent skip). The fix lives one layer up in run_forge_python,
        // which combines introspection + detect_unresolved_receivers.
        // Documented here so future readers understand the layering.
        let warnings = crate::scanner::local_introspect::verify_against_introspection(&calls, &empty_scope).await;
        eprintln!(
            "REPRO layering: verify_against_introspection alone produces {} warnings \
             (silent skip in Case B is by design); the fix lives in run_forge_python via \
             detect_unresolved_receivers.",
            warnings.len(),
        );

        // (4) End-to-end: run_forge_python must now flag the unresolved receiver
        //     via detect_unresolved_receivers. This bumps claims_hallucinated
        //     and forces L3 escalation in production (mod.rs cascade).
        let forge = crate::scanner::forge_python::run_forge_python(src, &empty_scope, "", "").await;
        assert!(
            forge.claims_extracted > 0,
            "FORGE must extract at least the parse_json claim; got claims_extracted={}",
            forge.claims_extracted,
        );
        assert!(
            forge.claims_hallucinated >= 1,
            "FIXED: detect_unresolved_receivers must emit chain-broken for resp.parse_json. \
             claims_hallucinated={}, warnings: {:?}",
            forge.claims_hallucinated,
            forge.warnings,
        );
        assert!(
            forge
                .warnings
                .iter()
                .any(|w| w.starts_with("chain-broken") && w.contains("parse_json")),
            "FIXED: chain-broken warning for parse_json MUST be present. warnings: {:?}",
            forge.warnings,
        );
        eprintln!(
            "REPRO CONFIRMED FIXED: claims_extracted={}, claims_hallucinated={} → cascade \
             will now escalate to L3. warnings: {:?}",
            forge.claims_extracted,
            forge.claims_hallucinated,
            forge.warnings,
        );
    }

    /// Repro for parameter-based hallucinations like `def f(text): text.reverse()`
    /// and `def g(options): options.has_key(key)`. The receiver is a function
    /// parameter, not an assignment — original `extract_python_assignments`
    /// missed these. The fix extends the script to collect function parameters
    /// as synthetic `<parameter>` markers, so `detect_unresolved_receivers`
    /// flags them with chain-broken → forces L3 escalation.
    #[tokio::test]
    async fn extract_repro_parameter_receiver_hallucination() {
        let src = r#"
def reverse_text(text):
    """Return the reversed version of the given string."""
    return text.reverse()   # HALLUCINATION: str has no reverse() method


def has_setting(options, key):
    """Return True if the given key is present in the options dict."""
    return options.has_key(key)   # HALLUCINATION: dict.has_key() was removed in Python 3
"#;
        let empty_scope: Vec<(String, String)> = vec![];
        let forge = crate::scanner::forge_python::run_forge_python(src, &empty_scope, "", "").await;
        assert!(
            forge.claims_extracted > 0,
            "FORGE must extract the hallucinated calls; got claims_extracted={}",
            forge.claims_extracted,
        );
        // Expect chain-broken for both text.reverse and options.has_key.
        let cb_count = forge
            .warnings
            .iter()
            .filter(|w| w.starts_with("chain-broken"))
            .count();
        assert!(
            cb_count >= 2,
            "FIXED: detect_unresolved_receivers must emit chain-broken for both \
             text.reverse and options.has_key. chain-broken count={}, warnings: {:?}",
            cb_count,
            forge.warnings,
        );
        assert!(
            forge
                .warnings
                .iter()
                .any(|w| w.starts_with("chain-broken") && w.contains("text.reverse")),
            "chain-broken for text.reverse MUST be present. warnings: {:?}",
            forge.warnings,
        );
        assert!(
            forge
                .warnings
                .iter()
                .any(|w| w.starts_with("chain-broken") && w.contains("options.has_key")),
            "chain-broken for options.has_key MUST be present. warnings: {:?}",
            forge.warnings,
        );
        eprintln!(
            "PARAMETER REPRO CONFIRMED FIXED: claims_extracted={}, claims_hallucinated={}, \
             chain-broken count={}, warnings: {:?}",
            forge.claims_extracted,
            forge.claims_hallucinated,
            cb_count,
            forge.warnings,
        );
    }
}
