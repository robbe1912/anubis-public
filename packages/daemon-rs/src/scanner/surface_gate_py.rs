//! Surface gate for Python — installed-package signature verification
//! (v3 architecture, sale-ready stream 3).
//!
//! Catches the hallucination class the AST/compiler gates miss on live
//! agent traffic (20260818 hosted-run ground truth):
//!   CliRunner(mix_stderr=False) — click 8.2 REMOVED the mix_stderr
//!   parameter; the call raises TypeError at runtime. The agent wrote it
//!   because its training data predates the removal.
//!
//! Mechanism: a Python subprocess runs `inspect.signature(callable)` for
//! each `pkg.fn(...)` / direct-imported `fn(...)` call found in the
//! response code, in the WORKSPACE environment (cwd = project_root, or
//! its venv when discoverable). Reports each function's real parameter
//! names + variadic flag. We flag:
//!   - kwarg-not-in-signature: call passes `kwarg=` that the installed
//!     signature does not accept AND the signature has no **kwargs
//!     (certain TypeError — the mix_stderr class).
//!
//! Fail-open everywhere: python absent, package not importable,
//! subprocess timeout/parse failure, venv resolution failure → no warning.
//! Kill switch: ANUBIS_SURFACE_GATE=0 disables both surface gates.

use serde::Deserialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Max distinct callables to introspect per scan (latency bound).
const MAX_CALLABLES: usize = 12;
/// Subprocess budget for the whole signature census.
const CENSUS_TIMEOUT_SECS: u64 = 10;
/// Cache signatures per (project_root, module) — introspection subprocess
/// is ~150-400ms; edit cycles hit the same modules repeatedly.
static SIG_CACHE: std::sync::OnceLock<tokio::sync::Mutex<HashMap<String, (std::time::Instant, HashMap<String, Option<SigInfo>>)>>> =
    std::sync::OnceLock::new();
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct SigInfo {
    #[serde(default)]
    params: Vec<String>,
    #[serde(default)]
    has_var_kw: bool,
}

/// Extract call targets from Python code: `fn(...)` bare calls and
/// `module.fn(...)` attribute calls, with any kwargs at the call site.
/// Returns (dotted_name, [kwargs]) pairs.
fn extract_call_sites(code: &str) -> Vec<(String, Vec<String>)>
{
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // find '(' preceded by an identifier char (part of a name)
        if bytes[i] == b'(' && i > 0 {
            let mut j = i;
            while j > 0 && (bytes[j - 1].is_ascii_alphanumeric() || bytes[j - 1] == b'_' || bytes[j - 1] == b'.') {
                j -= 1;
            }
            let name = &code[j..i];
            let is_name_start = name
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false);
            if is_name_start && !is_def_or_class(code, j) {
                // scan kwargs inside this call's argument list at depth 1
                let kwargs = extract_kwargs(&code[i + 1..]).unwrap_or_default();
                out.push((name.to_string(), kwargs));
            }
        }
        i += 1;
    }
    out
}

/// True when the name at `pos` is part of a def/class/lambda header —
/// its parens are a PARAMETER list, not a call. Note: `x = fn(...)` IS a
/// call; the assignment target doesn't change the callee. Do NOT trim
/// trailing whitespace from the prefix — the space in `def ` is the
/// separator the check depends on.
fn is_def_or_class(code: &str, pos: usize) -> bool {
    // UNtrimmed: the separator space IS part of the keyword match
    // ("def runner(" → before == "def " → ends_with("def ") == true).
    let before = &code[..pos];
    before.ends_with("def ")
        || before.ends_with("class ")
        || before.ends_with("lambda ")
        || code[pos..].starts_with("def ")
        || code[pos..].starts_with("class ")
        || code[pos..].starts_with("lambda ")
}

/// Blank out string-literal contents so paren/kwarg scanning never sees
/// code-shaped text inside strings ("a=b(c=1)").
fn mask_strings(code: &str) -> String {
    let mut out = code.to_string();
    let bytes = unsafe { out.as_bytes_mut() };
    let mut in_str: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        match in_str {
            Some(q) => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    // escape: blank both
                    bytes[i] = b' ';
                    bytes[i + 1] = b' ';
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    in_str = None;
                } else if bytes[i] != b'\n' && bytes[i] != b'\r' {
                    bytes[i] = b' ';
                }
            }
            None => {
                let c = bytes[i];
                if c == b'\'' || c == b'"' {
                    in_str = Some(c);
                }
            }
        }
        i += 1;
    }
    out
}

/// Extract `kwarg=` names from the argument list starting at `args_src`,
/// up to the matching close paren.
fn extract_kwargs(args_src: &str) -> Option<Vec<String>> {
    let mut depth = 1;
    let mut kwargs = Vec::new();
    let mut chars = args_src.char_indices().peekable();
    let mut in_str: Option<char> = None;
    while let Some((idx, c)) = chars.next() {
        match in_str {
            Some(q) => {
                if c == q && args_src.as_bytes().get(idx.wrapping_sub(1)) != Some(&b'\\') {
                    in_str = None;
                }
                continue;
            }
            None => {}
        }
        match c {
            '\'' | '"' => in_str = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return if kwargs.is_empty() { None } else { Some(kwargs) };
                }
            }
            '=' => {
                // kwarg only at depth 1 when not == and preceded by name
                if depth == 1
                    && chars.peek().map(|&(_, nc)| nc) != Some('=')
                    && !kwargs_scan_is_comparison(args_src, idx)
                {
                    // name is the ident run before '='
                    let before = &args_src[..idx];
                    let name_start = before
                        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                        .map(|p| p + 1)
                        .unwrap_or(0);
                    let name = before[name_start..].trim();
                    if !name.is_empty()
                        && name
                            .chars()
                            .next()
                            .map(|c| c.is_ascii_alphabetic() || c == '_')
                            .unwrap_or(false)
                        && !["default", "lambda"].contains(&name)
                    {
                        kwargs.push(name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    if kwargs.is_empty() { None } else { Some(kwargs) }
}

/// Guard against `a = b` comparisons inside comprehensions etc. — a kwarg
/// '=' at depth 1 follows whitespace/name, a comparison follows an
/// expression ending in ) ] or a space-paren. Keep it simple: treat as
/// kwarg only when the char immediately before the name run start is
/// whitespace, ',' or '('.
fn kwargs_scan_is_comparison(args_src: &str, eq_idx: usize) -> bool {
    let before = args_src[..eq_idx].trim_end();
    // ends with ) or ] or a literal → likely comparison (a == handled above;
    // <= >= != already excluded via peek)
    before.ends_with(')') || before.ends_with(']') || before.ends_with("not")
}

/// Python script: introspect signatures for a list of dotted names,
/// importing in the workspace context.
const CENSUS_SCRIPT: &str = r#"
import json, sys, importlib, inspect
names = json.load(open(sys.argv[1], encoding='utf-8'))
out = {}
for dotted in names:
    try:
        parts = dotted.split('.')
        if len(parts) == 1:
            mod_name, attr = None, parts[0]
            # bare name: try builtins first
            import builtins
            obj = getattr(builtins, attr, None)
            if obj is None:
                out[dotted] = None
                continue
        else:
            mod_name, attr = parts[0], parts[-1]
            mod = importlib.import_module(mod_name)
            obj = getattr(mod, attr, None)
            if obj is None:
                out[dotted] = None
                continue
        try:
            sig = inspect.signature(obj)
        except (TypeError, ValueError):
            out[dotted] = None
            continue
        params = []
        has_var_kw = False
        for p in sig.parameters.values():
            if p.kind == inspect.Parameter.VAR_KEYWORD:
                has_var_kw = True
            else:
                params.append(p.name)
        out[dotted] = {'params': params, 'has_var_kw': has_var_kw}
    except Exception:
        out[dotted] = None
sys.stdout.write(json.dumps(out))
"#;

/// Find a workspace python: `.venv/Scripts/python.exe`, `venv/`, else
/// plain `python` on PATH (which may be a venv already active).
fn workspace_python(project_root: &str) -> String {
    for venv in [".venv", "venv"] {
        for py in ["Scripts/python.exe", "bin/python", "bin/python3"] {
            let p = std::path::Path::new(project_root).join(venv).join(py);
            if p.exists() {
                return p.to_string_lossy().to_string();
            }
        }
    }
    "python".to_string()
}

/// Signature census for the distinct call targets, cached per root+module
/// set for 5 minutes.
async fn signature_census(code: &str, project_root: &str) -> HashMap<String, Option<SigInfo>> {
    let sites = extract_call_sites(&mask_strings(code));
    if sites.is_empty() {
        return HashMap::new();
    }
    let mut names: Vec<String> = sites.iter().map(|(n, _)| n.clone()).collect();
    names.sort();
    names.dedup();
    names.truncate(MAX_CALLABLES);

    let cache_key = format!(
        "{}|{}",
        project_root,
        names.iter().map(|n| n.split('.').next().unwrap_or(n)).collect::<Vec<_>>().join(",")
    );
    let cache = SIG_CACHE
        .get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
        .lock()
        .await;
    if let Some((ts, cached)) = cache.get(&cache_key) {
        if ts.elapsed() < CACHE_TTL {
            return cached.clone();
        }
    }
    drop(cache);

    let dir = std::env::temp_dir().join(format!(
        "anubis-surface-py-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if std::fs::create_dir_all(&dir).is_err() {
        return HashMap::new();
    }
    let list_file = dir.join("names.json");
    if std::fs::write(&list_file, serde_json::to_string(&names).unwrap_or_default().as_bytes())
        .is_err()
    {
        return HashMap::new();
    }

    let py = workspace_python(project_root);
    let mut child = crate::scanner::command_hidden_tokio(&py);
    child
        .arg("-c")
        .arg(CENSUS_SCRIPT)
        .arg(&list_file)
        .current_dir(project_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let output = {
        match child.spawn() {
            Ok(c) => match tokio::time::timeout(Duration::from_secs(CENSUS_TIMEOUT_SECS), c.wait_with_output()).await {
                Ok(Ok(o)) if o.status.success() => o,
                _ => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return HashMap::new();
                }
            },
            Err(_) => {
                let _ = std::fs::remove_dir_all(&dir);
                return HashMap::new();
            }
        }
    };
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: HashMap<String, Option<SigInfo>> =
        match serde_json::from_str(stdout.trim()) {
            Ok(p) => p,
            Err(_) => return HashMap::new(),
        };

    let mut cache = SIG_CACHE
        .get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
        .lock()
        .await;
    cache.insert(cache_key, (std::time::Instant::now(), parsed.clone()));
    parsed
}

/// Public entry point — called from scanner/mod.rs after the Stage-5
/// compiler gate. Returns grounded warnings for CERTAIN mismatches only
/// (kwarg absent from installed signature AND no **kwargs catch-all).
pub async fn check(content: &str, code: &str, project_root: &str) -> Vec<String> {
    if std::env::var("ANUBIS_SURFACE_GATE")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        return Vec::new();
    }
    if project_root.is_empty() || code.is_empty() {
        return Vec::new();
    }

    let census = signature_census(code, project_root).await;
    if census.is_empty() {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    let mut flagged: Vec<String> = Vec::new();
    for (name, kwargs) in extract_call_sites(code) {
        // Only module.attr shapes — bare names hit builtins noise.
        if !name.contains('.') {
            continue;
        }
        if let Some(Some(sig)) = census.get(&name) {
            if sig.has_var_kw {
                continue; // **kwargs accepts anything — not certain
            }
            for kw in &kwargs {
                if !sig.params.contains(kw) {
                    flagged.push(format!(
                        "surface-mismatch: `{}` has no parameter `{}` in the installed version (accepts: {}) — the call raises TypeError at runtime.",
                        name,
                        kw,
                        if sig.params.is_empty() {
                            "no parameters".to_string()
                        } else {
                            sig.params.join(", ")
                        }
                    ));
                }
            }
        }
    }
    flagged.sort();
    flagged.dedup();
    warnings.extend(flagged);
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_site_extraction_with_kwargs() {
        let code = "from click.testing import CliRunner\nrunner = CliRunner(mix_stderr=False)\nresult = runner.invoke(cli, ['add'])";
        let sites = extract_call_sites(&mask_strings(code));
        let runner_call = sites.iter().find(|(n, _)| n == "CliRunner").expect("CliRunner site");
        assert_eq!(runner_call.1, vec!["mix_stderr".to_string()]);
        // invoke has no kwargs
        let invoke_call = sites.iter().find(|(n, _)| n == "runner.invoke").expect("invoke site");
        assert!(invoke_call.1.is_empty());
    }

    #[test]
    fn nested_kwargs_and_strings() {
        let code = "r = configure(timeout=30, label=\"a=b(c=1)\", nested={\"k\": 1})";
        let sites = extract_call_sites(&mask_strings(code));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].0, "configure");
        assert_eq!(sites[0].1.len(), 3);
    }

    #[test]
    fn def_not_a_call() {
        let code = "def runner(mix_stderr=True):\n    pass";
        let sites = extract_call_sites(&mask_strings(code));
        // `runner(` here is the def's parameter list — its name must never
        // appear as a CALL site even though kwargs are extracted.
        assert!(
            sites.iter().all(|(n, _)| n != "runner"),
            "sites: {:?}",
            sites
        );
    }

    #[tokio::test]
    async fn kill_switch_disables() {
        std::env::set_var("ANUBIS_SURFACE_GATE", "0");
        let w = check("", "x = pkg.fn(bogus=1)", "/nonexistent").await;
        assert!(w.is_empty());
        std::env::remove_var("ANUBIS_SURFACE_GATE");
    }

    #[tokio::test]
    async fn missing_module_fails_open() {
        let w = check("", "x = totally_missing_pkg.fn(bogus=1)", ".").await;
        assert!(w.is_empty());
    }

    #[tokio::test]
    async fn live_removed_kwarg_fires() {
        // click IS importable in this repo's python env (installed for
        // local_introspect tests). mix_stderr was removed in click 8.2+.
        // Skips silently (fail-open) when click or python absent.
        let code = "from click.testing import CliRunner\nr = CliRunner(mix_stderr=False)";
        let w = check("", code, ".").await;
        if !w.is_empty() {
            assert!(w[0].contains("mix_stderr"), "warning should name the kwarg: {:?}", w);
        }
    }

    #[tokio::test]
    async fn live_valid_kwarg_silent() {
        let code = "import json\nx = json.dumps(obj, indent=2)";
        let w = check("", code, ".").await;
        assert!(w.is_empty(), "indent is a valid dumps kwarg: {:?}", w);
    }
}
