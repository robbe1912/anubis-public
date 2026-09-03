//! GDScript FORGE — extends verification + class/init/inheritance helpers.
//!
//! Extracted from `forge_gdscript.rs` (M1 council #3 finding #10). All
//! verification is local against the cached Godot symbol table.
//!
//! Provides:
//!   - `is_known_godot_class` / `class_has_members` — class-existence checks
//!   - `resolve_gdscript_init_type` — initializer → Godot class inference
//!   - `lookup_godot_member_with_inheritance` — inherited member hit check
//!   - `collect_godot_members_recursive` — levenshtein candidate set
//!
//! All functions are `pub(super)` — visible only within `forge_gdscript`.

use crate::symbols::cache::SymbolCache;

/// Check whether `class` is a known Godot class (any version, by path or name).
///
/// **Kind matters**: only Class-kind rows count. Without this check, any
/// property or method named "v" / "node" / etc. cached from project syncs
/// would falsely resolve as a class.
pub(super) fn is_known_godot_class(cache: &SymbolCache, class: &str) -> bool {
    use crate::symbols::types::SymbolKind;
    let is_class = |s: &crate::symbols::types::Symbol| {
        s.library == "godot" && s.kind == SymbolKind::Class
    };
    cache
        .lookup_global(class)
        .iter()
        .any(is_class)
}

/// True if `class` (or any ancestor) has at least one cached member.
/// Used to filter out member-less classes like `Variant`/`Object` from
/// type annotations — those should fall back to initializer inference.
pub(super) fn class_has_members(cache: &SymbolCache, class: &str) -> bool {
    let mut current = class.to_string();
    for _ in 0..12 {
        let prefix = format!("{current}.");
        if cache.lookup_prefix("godot", &prefix).len() > 0 {
            return true;
        }
        match cache.lookup("godot", &current) {
            Some(sym) => match sym.return_type.as_deref() {
                Some(parent) if !parent.is_empty() && parent != current => {
                    current = parent.to_string();
                }
                _ => return false,
            },
            None => return false,
        }
    }
    false
}

/// Resolve a GDScript initializer expression to a Godot class name.
///
/// Handles the common literals: `[]` → Array, `{}` → Dictionary, numeric → int/float,
/// string → String, `ClassName.new(...)` → ClassName, bare known class → itself.
pub(super) fn resolve_gdscript_init_type(
    init: &str,
    cache: &SymbolCache,
) -> Option<String> {
    let trimmed = init.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Collection literals.
    if trimmed.starts_with('[') { return Some("Array".to_string()); }
    if trimmed.starts_with('{') { return Some("Dictionary".to_string()); }
    if trimmed.starts_with('"') || trimmed.starts_with('\'') {
        return Some("String".to_string());
    }
    if trimmed == "self" {
        return None; // resolved by caller via ctx_class.
    }
    // ClassName.new(...) OR ClassName(...) — Godot allows both constructor forms.
    let new_re = regex::Regex::new(r"^([A-Z][A-Za-z0-9_]*)\s*\.\s*new\s*\(").unwrap();
    if let Some(c) = new_re.captures(trimmed) {
        if let Some(m) = c.get(1) {
            let class = m.as_str();
            if is_known_godot_class(cache, class) {
                return Some(class.to_string());
            }
        }
        return None;
    }
    let ctor_re = regex::Regex::new(r"^([A-Z][A-Za-z0-9_]*)\s*\(").unwrap();
    if let Some(c) = ctor_re.captures(trimmed) {
        if let Some(m) = c.get(1) {
            let class = m.as_str();
            // Only trust capitalized calls when the name is a real Godot class.
            // This avoids false positives for user-defined function calls.
            if is_known_godot_class(cache, class) {
                return Some(class.to_string());
            }
        }
        return None;
    }
    // Numeric literal → int or float.
    if trimmed.parse::<i64>().is_ok() {
        return Some("int".to_string());
    }
    if trimmed.parse::<f64>().is_ok() {
        return Some("float".to_string());
    }
    // Bare known class name (e.g. Vector3 used as a type witness).
    if is_known_godot_class(cache, trimmed) {
        return Some(trimmed.to_string());
    }
    None
}

/// Walk the Godot inheritance chain looking for `Class.member`.
///
/// `Class.return_type` on Class-kind rows stores the parent class
/// (e.g. Node2D -> CanvasItem, CanvasItem -> Node, Node -> Object).
/// Without this walk, a call like `node2d_instance.add_child(...)`
/// misses because `add_child` is defined on `Node`, not `Node2D`.
///
/// Caps at 12 hops to bound cost on degenerate chains.
pub(super) fn lookup_godot_member_with_inheritance(
    cache: &SymbolCache,
    start_class: &str,
    member: &str,
) -> bool {
    let mut current = start_class.to_string();
    for _ in 0..12 {
        let dotted = format!("{current}.{member}");
        if cache.lookup("godot", &dotted).is_some() {
            return true;
        }
        // Walk to parent.
        match cache.lookup("godot", &current) {
            Some(sym) => match sym.return_type.as_deref() {
                Some(parent) if !parent.is_empty() && parent != current => {
                    current = parent.to_string();
                }
                _ => break,
            },
            None => {
                // Fall back to global lookup (covers cross-version definitions).
                let hits = cache.lookup_global(&current);
                let Some(sym) = hits.iter().find(|s| s.library == "godot") else { break; };
                match sym.return_type.as_deref() {
                    Some(parent) if !parent.is_empty() && parent != current => {
                        current = parent.to_string();
                    }
                    _ => break,
                }
            }
        }
    }
    false
}

/// Collect all member names reachable on `start_class` and its ancestors.
///
/// Used to populate the levenshtein candidate set so suggestions match what
/// Godot actually offers on the receiver (inherited members included).
pub(super) fn collect_godot_members_recursive(
    cache: &SymbolCache,
    start_class: &str,
) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    let mut current = start_class.to_string();
    for _ in 0..12 {
        let prefix = format!("{current}.");
        for sym in cache.lookup_prefix("godot", &prefix) {
            if seen.insert(sym.name.clone()) {
                out.push(sym.name);
            }
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the GDScript Variant init-resolution bug:
    /// `var v: Variant = Vector3(0, 1, 0)` should resolve to Vector3,
    /// not Variant, because Variant has no own members.
    #[test]
    fn gdscript_variant_init_resolves_to_concrete_type() {
        let cache = match crate::symbols::cache::SymbolCache::open() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("skip: no symbol cache available");
                return;
            }
        };
        // Direct call: init resolver should return Vector3.
        let r = resolve_gdscript_init_type("Vector3(0, 1, 0)", &cache);
        assert_eq!(r.as_deref(), Some("Vector3"));
        // And Vector3.normalized should be a hit (inherited chain walk unnecessary).
        assert!(lookup_godot_member_with_inheritance(&cache, "Vector3", "normalized"));
        // Variant has no own members and no parent — class_has_members returns false.
        assert!(!class_has_members(&cache, "Variant"));
    }
}
