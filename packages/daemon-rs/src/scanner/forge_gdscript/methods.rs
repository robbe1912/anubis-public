//! GDScript FORGE — method/property verification + arity checks.
//!
//! Extracted from `forge_gdscript.rs` (M1 council #3 finding #10).
//!
//! Provides:
//!   - `verify_gdscript_methods` — `obj.member` access against Godot cache
//!   - `verify_gdscript_call_arity` — extra-arg detection on cached signatures
//!   - `verify_gdscript_user_func_arity` — bare user-defined `func` call arity
//!   - `lookup_godot_member_symbol_recursive` — inherited defining Symbol lookup
//!   - `resolve_receiver_class` — receiver → Godot class inference
//!   - `count_args_balanced` / `find_matching_paren` / `count_params` — arg parsing

use crate::scanner::forge_types::ForgeResult;
use crate::scanner::levenshtein::capped as levenshtein_capped_internal;
use crate::scanner::forge_gdscript::extends::{
    class_has_members, collect_godot_members_recursive, is_known_godot_class,
    lookup_godot_member_with_inheritance, resolve_gdscript_init_type,
};
use crate::scanner::forge_gdscript::strip_gdscript_strings_and_comments;
use crate::symbols::cache::SymbolCache;

/// Verify `obj.method` and `obj.property` accesses against the Godot symbol cache.
///
/// Tracks variable types from initializers (`var x = init`) and the implicit
/// class context from `extends ClassName`, then for every `receiver.member`
/// pattern resolves the receiver to a Godot class and looks up
/// `Class.member` in the cache. Misses with a close levenshtein match
/// produce a hallucinated-method warning with a "did you mean" suggestion.
pub(super) fn verify_gdscript_methods(
    content: &str,
    cache: &SymbolCache,
    result: &mut ForgeResult,
) {
    use std::collections::HashMap;

    // Cache-cold guard: member verification looks up `Class.member` against
    // the symbol cache's godot.* entries. The seed bundle ships zero such
    // entries (live fetch is opt-in), so without this guard every receiver
    // typed as Dictionary/Node/Array/etc. would be flagged as a missing
    // member — a broad FP across every real Godot script. Skip until the
    // cache is populated.
    if cache.lookup_prefix("godot", "").is_empty() {
        return;
    }

    // Parse `extends ClassName` to get the implicit self/parent context.
    let extends_re = regex::Regex::new(r"(?m)^\s*extends\s+([A-Za-z_]\w*)").unwrap();
    let mut ctx_class: Option<String> = None;
    for caps in extends_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            ctx_class = Some(m.as_str().to_string());
            break;
        }
    }

    // Track variable → Godot class type from `var name = init` / `var name: Type = init`.
    let mut var_types: HashMap<String, String> = HashMap::new();
    let var_decl_re = regex::Regex::new(
        r"(?m)^\s*(?:export\s+|onready\s+|@(?:export|onready)\s+)*var\s+([A-Za-z_]\w*)\s*(?::\s*([A-Za-z_]\w*))?\s*(?:=\s*(.+?))?\s*$",
    ).unwrap();
    for caps in var_decl_re.captures_iter(content) {
        let name = match caps.get(1) {
            Some(m) => m.as_str().to_string(),
            None => continue,
        };
        // Prefer the initializer when present — it gives the concrete runtime
        // type. `var x: Variant = []` should resolve to Array, not Variant,
        // because Variant is Godot's "any" type with no own members.
        let mut resolved: Option<String> = None;
        if let Some(init_m) = caps.get(3) {
            let init = init_m.as_str().trim();
            if init == "self" || init == "super" {
                // `var x = self` → inherits the extends class.
                resolved = ctx_class.clone();
            } else {
                resolved = resolve_gdscript_init_type(init, cache);
            }
        }
        if resolved.is_none() {
            if let Some(ty_m) = caps.get(2) {
                let ty = ty_m.as_str();
                // Only trust the annotation if the class actually has members
                // in the cache. Variant/Object/etc. are too generic.
                if is_known_godot_class(cache, ty) && class_has_members(cache, ty) {
                    resolved = Some(ty.to_string());
                }
            }
        }
        if let Some(class) = resolved {
            var_types.insert(name, class);
        }
    }

    // Also pick up assignments inside function bodies: `x = <init>` (no `var`).
    let assign_re = regex::Regex::new(
        r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*$",
    ).unwrap();
    for caps in assign_re.captures_iter(content) {
        let name = match caps.get(1) {
            Some(m) => m.as_str().to_string(),
            None => continue,
        };
        // Skip if it's a `==` comparison (regex should not match `==`, but defensive).
        if name.is_empty() { continue; }
        if let Some(init_m) = caps.get(2) {
            if let Some(class) = resolve_gdscript_init_type(init_m.as_str(), cache) {
                var_types.insert(name, class);
            }
        }
    }

    // Strip strings/comments before scanning for member access — paths inside
    // `load("res://foo.gd")` would otherwise create false positives.
    let stripped = strip_gdscript_strings_and_comments(content);

    // Find all `receiver.member` patterns. `receiver` must be a bare identifier
    // (so we can resolve it); chained access like `a.b.c` is handled left-to-right.
    let member_re = regex::Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)").unwrap();
    for caps in member_re.captures_iter(&stripped) {
        let receiver = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        let member = match caps.get(2) {
            Some(m) => m.as_str(),
            None => continue,
        };
        // Skip private/dunder.
        if member.starts_with('_') { continue; }
        if member.len() < 2 { continue; }

        // Resolve receiver to a Godot class.
        let class = if receiver == "self" || receiver == "super" {
            ctx_class.clone()
        } else if let Some(ty) = var_types.get(receiver) {
            Some(ty.clone())
        } else {
            // Receiver is itself a known class (Vector3, Array, etc.) — verify statically.
            if is_known_godot_class(cache, receiver) {
                Some(receiver.to_string())
            } else {
                None
            }
        };

        let Some(class) = class else { continue; };

        // Look up `Class.member` in the cache. Hits cover both methods and properties.
        // Walk the inheritance chain: Godot's `Symbol.return_type` on Class rows
        // stores the parent class (Node2D -> CanvasItem -> Node -> Object). Without
        // this walk, `Node2D.add_child` would miss because `add_child` is on `Node`.
        if lookup_godot_member_with_inheritance(cache, &class, member) {
            continue;
        }

        // Miss — find closest real member on this class via levenshtein,
        // including inherited members so suggestions match what Godot actually
        // offers on the receiver.
        let candidates = collect_godot_members_recursive(cache, &class);
        let closest = candidates
            .iter()
            .map(|c| (levenshtein_capped_internal(member, c, 4), c))
            .filter(|(d, c)| {
                if *d > 2 { return false; }
                // Skip very short names
                if member.len() < 4 || c.len() < 4 { return false; }
                // Length ratio check
                let ratio = c.len().min(member.len()) as f64
                    / c.len().max(member.len()) as f64;
                ratio >= 0.60
            })
            .min_by_key(|(d, _)| *d);

        result.claims_extracted += 1;
        match closest {
            Some((dist, suggestion)) => {
                result.warnings.push(format!(
                    "hallucinated-method: `{receiver}.{member}` — not a member of `{class}`. Did you mean `{suggestion}` (distance {dist})?"
                ));
            }
            None => {
                result.warnings.push(format!(
                    "hallucinated-method: `{receiver}.{member}` — not a member of `{class}`"
                ));
            }
        }
        result.claims_hallucinated += 1;
    }
}

/// Verify call arity against cached Godot method signatures.
///
/// For each `obj.method(args)` call where `obj` resolves to a known Godot class,
/// looks up the cached `Class.method` signature and compares argument count.
/// Flags when call has more args than the signature declares (extra args).
pub(super) fn verify_gdscript_call_arity(
    content: &str,
    cache: &SymbolCache,
    result: &mut ForgeResult,
) {
    let stripped = strip_gdscript_strings_and_comments(content);
    let call_re = regex::Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(([^)]*)\)").unwrap();
    for caps in call_re.captures_iter(&stripped) {
        let receiver = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        let method = match caps.get(2) {
            Some(m) => m.as_str(),
            None => continue,
        };
        let args_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        // Resolve via the same var-types map built in verify_gdscript_methods
        // (re-derived here cheaply — single scan is fine).
        let class = resolve_receiver_class(content, receiver, cache);
        let Some(class) = class else { continue; };

        // Walk inheritance to find the actual defining class.
        let dotted = format!("{class}.{method}");
        let sym = cache
            .lookup("godot", &dotted)
            .or_else(|| lookup_godot_member_symbol_recursive(cache, &class, method));
        let Some(sym) = sym else { continue; };

        // Skip variadic / no-signature / default-heavy signatures.
        let Some(sig) = sym.signature.as_deref() else { continue; };
        if sig.contains("...") { continue; }

        let actual = count_args_balanced(args_str);
        let declared = sym.params.len();
        // Allow fewer args (defaults) but flag strictly more.
        if actual > declared {
            result.claims_extracted += 1;
            result.warnings.push(format!(
                "hallucinated-parameter: `{receiver}.{method}(...)` called with {actual} arguments but `{class}.{method}` declares {declared}"
            ));
            result.claims_hallucinated += 1;
        }
    }
}

/// Walk the Godot inheritance chain to find the defining Symbol for `member`.
///
/// Returns the actual cached Symbol (with full signature + params) so arity
/// checks work on inherited methods, not just directly-defined ones.
fn lookup_godot_member_symbol_recursive(
    cache: &SymbolCache,
    start_class: &str,
    member: &str,
) -> Option<crate::symbols::types::Symbol> {
    let mut current = start_class.to_string();
    for _ in 0..12 {
        let dotted = format!("{current}.{member}");
        if let Some(sym) = cache.lookup("godot", &dotted) {
            return Some(sym);
        }
        match cache.lookup("godot", &current) {
            Some(sym) => match sym.return_type.as_deref() {
                Some(parent) if !parent.is_empty() && parent != current => {
                    current = parent.to_string();
                }
                _ => break,
            },
            None => break,
        }
    }
    None
}

/// Resolve a receiver identifier to a Godot class name (cheap re-derivation).
fn resolve_receiver_class(
    content: &str,
    receiver: &str,
    cache: &SymbolCache,
) -> Option<String> {
    if receiver == "self" || receiver == "super" {
        let extends_re = regex::Regex::new(r"(?m)^\s*extends\s+([A-Za-z_]\w*)").unwrap();
        return extends_re
            .captures(content)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
    }
    // Re-scan var declarations. Prefer initializer (concrete runtime type)
    // over annotation when annotation is too generic (Variant/Object).
    let var_decl_re = regex::Regex::new(
        r"(?m)^\s*(?:export\s+|onready\s+|@(?:export|onready)\s+)*var\s+([A-Za-z_]\w*)\s*(?::\s*([A-Za-z_]\w*))?\s*(?:=\s*(.+?))?\s*$",
    ).unwrap();
    for caps in var_decl_re.captures_iter(content) {
        let n = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if n != receiver { continue; }
        if let Some(init) = caps.get(3) {
            if let Some(class) = resolve_gdscript_init_type(init.as_str(), cache) {
                return Some(class);
            }
        }
        if let Some(ty) = caps.get(2) {
            let ty = ty.as_str();
            if is_known_godot_class(cache, ty) && class_has_members(cache, ty) {
                return Some(ty.to_string());
            }
        }
    }
    if is_known_godot_class(cache, receiver) {
        Some(receiver.to_string())
    } else {
        None
    }
}

/// Count comma-separated args respecting nested parens/brackets.
fn count_args_balanced(args: &str) -> usize {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return 0;
    }
    let mut depth: i32 = 0;
    let mut count = 1;
    for c in trimmed.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count.max(1)
}

/// Verify arity of bare calls to user-defined GDScript functions.
///
/// Parses `func name(params)` declarations, then for each `name(args)` call
/// (not preceded by `.`) compares arg counts. Flags when caller passes
/// strictly more args than declared — extra args are always wrong; fewer
/// args may be valid via defaults.
pub(super) fn verify_gdscript_user_func_arity(content: &str, result: &mut ForgeResult) {
    use std::collections::HashMap;

    // Parse user function signatures.
    let func_re = regex::Regex::new(r"\bfunc\s+([A-Za-z_]\w*)\s*\(([^)]*)\)").unwrap();
    let mut sigs: HashMap<String, usize> = HashMap::new();
    for caps in func_re.captures_iter(content) {
        let name = match caps.get(1) {
            Some(m) => m.as_str().to_string(),
            None => continue,
        };
        let params_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let count = count_params(params_str);
        sigs.insert(name, count);
    }
    if sigs.is_empty() {
        return;
    }

    let stripped = strip_gdscript_strings_and_comments(content);
    let bytes = stripped.as_bytes();

    // Scan for every `ident(` occurrence, then balance-match to extract args.
    // This handles nested calls like `print(clamp_val(1, 2, 3, 4))` correctly
    // — the outer regex would otherwise swallow the inner call.
    let ident_start_re = regex::Regex::new(r"\b([A-Za-z_]\w*)\s*\(").unwrap();
    for caps in ident_start_re.captures_iter(&stripped) {
        let name = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        // Skip if not a known user function.
        let Some(&declared) = sigs.get(name) else { continue; };

        let m_start = caps.get(1).unwrap().start();
        // Locate the `(` position (right after the identifier + optional ws).
        let paren_open = caps.get(0).unwrap().end() - 1;
        // Balance-match from `(` to its closing `)`.
        let Some(args_end) = find_matching_paren(bytes, paren_open) else { continue; };
        let args_str = &stripped[paren_open + 1..args_end];

        // Skip if preceded by `.` (member call — handled elsewhere).
        if m_start > 0 {
            let mut p = m_start;
            while p > 0 && bytes[p - 1].is_ascii_whitespace() { p -= 1; }
            if p > 0 && bytes[p - 1] == b'.' { continue; }
        }
        // Skip if this is the func declaration itself.
        if m_start >= 5 {
            let bytes = stripped.as_bytes();
            if &bytes[m_start.saturating_sub(5)..m_start] == b"func " {
                continue;
            }
        }

        let actual = count_args_balanced(args_str);
        if actual > declared {
            result.claims_extracted += 1;
            result.warnings.push(format!(
                "hallucinated-parameter: `{name}(...)` called with {actual} arguments but `func {name}` declares {declared}"
            ));
            result.claims_hallucinated += 1;
        }
    }
}

/// Find the index of the closing paren matching the opening paren at `open`.
/// Returns None if unbalanced.
fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Count formal parameters in a GDScript function signature.
/// `a: int, b: int = 0` → 2.
fn count_params(params_str: &str) -> usize {
    let trimmed = params_str.trim();
    if trimmed.is_empty() {
        return 0;
    }
    let mut depth: i32 = 0;
    let mut count = 1;
    for c in trimmed.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count.max(1)
}
