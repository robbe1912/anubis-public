//! Rust symbol parser.
//!
//! Parses rustdoc JSON format_version 60+ from docs.rs.
//! Earlier versions had different structure — we only support v60+.

use serde_json::Value;

use crate::symbols::types::{Param, Symbol, SymbolKind, Visibility};

pub fn parse_rustdoc_json(
    json: &str,
    crate_name: &str,
    version: &str,
) -> Result<Vec<Symbol>, String> {
    let root: Value = serde_json::from_str(json)
        .map_err(|e| format!("invalid JSON: {}", e))?;

    // docs.rs occasionally ships rustdoc JSON in older format_versions with
    // different schemas (different `inner` shapes, different impl ID encoding).
    // We only support v60+. Earlier versions silently mis-parse — better to
    // fail loudly than emit a partial/incorrect symbol surface.
    let format_version = root
        .get("format_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if format_version < 60 {
        return Err(format!(
            "unsupported rustdoc format_version {} (need >=60)",
            format_version
        ));
    }

    let index = root
        .get("index")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "rustdoc JSON missing 'index' field".to_string())?;

    let mut symbols = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut struct_impls: Vec<(String, Vec<&Value>)> = Vec::new();
    let mut trait_default_items: Vec<(String, Vec<&Value>)> = Vec::new();

    for (_id, item) in index.iter() {
        let Some(inner) = item.get("inner") else { continue; };
        let Some(inner_obj) = inner.as_object() else { continue; };
        let name = item.get("name").and_then(|v| v.as_str());

        if inner_obj.get("function").is_some() {
            let name = match name { Some(n) => n, None => continue };
            if let Some(sym) = build_function(item, name, crate_name, version, SymbolKind::Function, now) {
                symbols.push(sym);
            }
        } else if let Some(struct_data) = inner_obj.get("struct") {
            let name = match name { Some(n) => n, None => continue };
            if let Some(sym) = build_named(SymbolKind::Class, name, crate_name, version, item, "struct", now) {
                symbols.push(sym);
            }
            let impl_ids = struct_data.get("impls").and_then(|v| v.as_array())
                .map(|arr| arr.iter().collect::<Vec<_>>()).unwrap_or_default();
            if !impl_ids.is_empty() {
                struct_impls.push((name.to_string(), impl_ids));
            }
        } else if let Some(enum_data) = inner_obj.get("enum").and_then(|v| v.as_object()) {
            let name = match name { Some(n) => n, None => continue };
            if let Some(sym) = build_named(SymbolKind::Enum, name, crate_name, version, item, "enum", now) {
                symbols.push(sym);
            }
            // Enums also carry inherent impls (e.g., Option::is_some,
            // Result::is_ok). Collect them so the second pass below picks
            // up enum methods — previously enums silently dropped their
            // impl list, leaving roughly half of all type kinds without
            // method extraction.
            let impl_ids = enum_data.get("impls").and_then(|v| v.as_array())
                .map(|arr| arr.iter().collect::<Vec<_>>()).unwrap_or_default();
            if !impl_ids.is_empty() {
                struct_impls.push((name.to_string(), impl_ids));
            }
        } else if let Some(trait_data) = inner_obj.get("trait").and_then(|v| v.as_object()) {
            let name = match name { Some(n) => n, None => continue };
            if let Some(sym) = build_named(SymbolKind::Interface, name, crate_name, version, item, "trait", now) {
                symbols.push(sym);
            }
            // Trait default methods (provided_method) and required method
            // signatures live in `inner.trait.items`. Calls of the form
            // `TraitName.method(...)` are valid whether the method has a
            // default body or is required; collecting all of them here
            // means trait method calls are not mis-flagged as hallucinated.
            if let Some(items) = trait_data.get("items").and_then(|v| v.as_array()) {
                let items_vec: Vec<&Value> = items.iter().collect();
                if !items_vec.is_empty() {
                    trait_default_items.push((name.to_string(), items_vec));
                }
            }
        } else if inner_obj.get("module").is_some() {
            let name = match name { Some(n) => n, None => continue };
            if let Some(sym) = build_named(SymbolKind::Module, name, crate_name, version, item, "mod", now) {
                symbols.push(sym);
            }
        }
    }

    // Second pass: walk struct/enum impls to extract methods.
    for (struct_name, impl_id_values) in &struct_impls {
        for impl_id_val in impl_id_values {
            let Some(impl_id) = impl_id_val.as_u64() else { continue; };
            let Some(impl_item) = index.get(&impl_id.to_string()) else { continue; };
            let Some(impl_data) = impl_item.get("inner").and_then(|v| v.get("impl")) else { continue; };
            let Some(items) = impl_data.get("items").and_then(|v| v.as_array()) else { continue; };

            for item_ref in items {
                let Some(item_id_num) = item_ref.as_u64() else { continue; };
                let Some(item) = index.get(&item_id_num.to_string()) else { continue; };
                if item.get("inner").and_then(|v| v.get("function")).is_none() { continue; }
                let Some(method_name) = item.get("name").and_then(|v| v.as_str()) else { continue; };
                if let Some(mut sym) = build_function(item, method_name, crate_name, version, SymbolKind::Method, now) {
                    sym.path = format!("{}.{}.{}", crate_name, struct_name, method_name);
                    symbols.push(sym);
                }
            }
        }
    }

    // Third pass: walk trait items to extract default/required methods.
    for (trait_name, item_id_values) in &trait_default_items {
        for item_id_val in item_id_values {
            let Some(item_id) = item_id_val.as_u64() else { continue; };
            let Some(item) = index.get(&item_id.to_string()) else { continue; };
            if item.get("inner").and_then(|v| v.get("function")).is_none() { continue; }
            let Some(method_name) = item.get("name").and_then(|v| v.as_str()) else { continue; };
            if let Some(mut sym) = build_function(item, method_name, crate_name, version, SymbolKind::Method, now) {
                sym.path = format!("{}.{}.{}", crate_name, trait_name, method_name);
                symbols.push(sym);
            }
        }
    }

    Ok(symbols)
}

fn build_function(item: &Value, name: &str, crate_name: &str, version: &str, kind: SymbolKind, now: u64) -> Option<Symbol> {
    let path = format!("{}.{}", crate_name, name);
    let doc = item.get("docs").and_then(|v| v.as_str()).map(|s| s.to_string());
    let inputs = extract_inputs(item);
    let return_type = extract_return_type(item);
    let sig = build_signature_string(name, &inputs, &return_type);
    let params = inputs_to_params(&inputs);

    Some(Symbol {
        library: crate_name.to_string(),
        version: version.to_string(),
        path,
        name: name.to_string(),
        kind,
        signature: Some(sig),
        params,
        return_type: return_type.filter(|s| !s.is_empty() && s != "()"),
        doc_text: doc,
        source_file: extract_source_file(item),
        visibility: Visibility::Public,
        is_deprecated: is_deprecated(item),
        deprecated_message: None,
        extracted_at: now,
    })
}

fn build_named(kind: SymbolKind, name: &str, crate_name: &str, version: &str, item: &Value, kind_keyword: &str, now: u64) -> Option<Symbol> {
    let path = format!("{}.{}", crate_name, name);
    let doc = item.get("docs").and_then(|v| v.as_str()).map(|s| s.to_string());
    let sig = format!("{} {}", kind_keyword, name);

    Some(Symbol {
        library: crate_name.to_string(),
        version: version.to_string(),
        path,
        name: name.to_string(),
        kind,
        signature: Some(sig),
        params: Vec::new(),
        return_type: None,
        doc_text: doc,
        source_file: extract_source_file(item),
        visibility: Visibility::Public,
        is_deprecated: is_deprecated(item),
        deprecated_message: None,
        extracted_at: now,
    })
}

fn build_signature_string(name: &str, inputs: &[(String, String)], return_type: &Option<String>) -> String {
    let inputs_str = inputs.iter().map(|(n, t)| format!("{}: {}", n, t)).collect::<Vec<_>>().join(", ");
    match return_type {
        Some(rt) if !rt.is_empty() && rt != "()" => format!("fn {}({}) -> {}", name, inputs_str, rt),
        _ => format!("fn {}({})", name, inputs_str),
    }
}

fn extract_inputs(item: &Value) -> Vec<(String, String)> {
    let Some(sig) = item.get("inner").and_then(|v| v.get("function")).and_then(|v| v.get("sig")) else {
        return Vec::new();
    };
    let Some(inputs) = sig.get("inputs").and_then(|v| v.as_array()) else { return Vec::new(); };
    inputs.iter().filter_map(|input| {
        let arr = input.as_array()?;
        if arr.len() != 2 { return None; }
        let arg_name = arr[0].as_str().unwrap_or("_").to_string();
        let ty = type_to_string(&arr[1]);
        Some((arg_name, ty))
    }).collect()
}

fn extract_return_type(item: &Value) -> Option<String> {
    let output = item.get("inner")?.get("function")?.get("sig")?.get("output")?;
    Some(type_to_string(output))
}

fn inputs_to_params(inputs: &[(String, String)]) -> Vec<Param> {
    inputs.iter().map(|(name, type_name)| Param {
        name: name.clone(),
        type_name: type_name.clone(),
        default_value: None,
    }).collect()
}

fn extract_source_file(item: &Value) -> Option<String> {
    item.get("span").and_then(|v| v.get("filename")).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn is_deprecated(item: &Value) -> bool {
    item.get("deprecation").map(|d| !d.is_null()).unwrap_or(false)
}

fn type_to_string(v: &Value) -> String {
    if let Some(s) = v.as_str() { return s.to_string(); }
    let Some(obj) = v.as_object() else { return "?".to_string(); };

    if let Some(rp) = obj.get("resolved_path").and_then(|v| v.as_object()) {
        if let Some(path) = rp.get("path").and_then(|v| v.as_str()) {
            return path.rsplit("::").next().unwrap_or(path).to_string();
        }
    }
    if let Some(g) = obj.get("generic").and_then(|v| v.as_str()) { return g.to_string(); }
    if let Some(p) = obj.get("primitive").and_then(|v| v.as_str()) { return p.to_string(); }
    if let Some(t) = obj.get("tuple").and_then(|v| v.as_array()) {
        if t.is_empty() { return "()".to_string(); }
        return format!("({})", t.iter().map(type_to_string).collect::<Vec<_>>().join(", "));
    }
    if let Some(s) = obj.get("slice").and_then(|v| v.as_array()) {
        if let Some(first) = s.first() { return format!("[{}]", type_to_string(first)); }
        return "[]".to_string();
    }
    if let Some(r) = obj.get("reference").and_then(|v| v.as_object()) {
        let inner = r.get("type").map(type_to_string).unwrap_or_else(|| "?".to_string());
        let mutability = if r.get("is_mut").and_then(|v| v.as_bool()).unwrap_or(false) { "mut " } else { "" };
        return format!("&{}{}", mutability, inner);
    }
    if let Some(a) = obj.get("array").and_then(|v| v.as_object()) {
        let inner = a.get("type").map(type_to_string).unwrap_or_else(|| "?".to_string());
        let len = a.get("len").and_then(|v| v.as_u64()).map(|n| n.to_string()).unwrap_or_else(|| "?".to_string());
        return format!("[{}; {}]", inner, len);
    }
    if let Some(rp) = obj.get("borrowed_ref").and_then(|v| v.as_object()) {
        let inner = rp.get("type").map(type_to_string).unwrap_or_else(|| "?".to_string());
        return format!("&{}", inner);
    }
    if let Some(it) = obj.get("impl_trait").and_then(|v| v.as_array()) {
        return format!("impl {}", it.iter().map(type_to_string).collect::<Vec<_>>().join(" + "));
    }
    "?".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_V60: &str = r#"{
      "root": "1", "crate_version": "1.0.0", "includes_private": false,
      "format_version": 60, "target": "x86_64-unknown-linux-gnu",
      "index": {
        "1": {"id": 1, "name": "demo", "docs": "demo module", "span": null, "inner": {"module": {"items": [2,3,4,5]}}},
        "2": {"id": 2, "name": "do_thing", "docs": "Does a thing.", "span": {"filename": "src/lib.rs", "begin": [10, 4]},
              "inner": {"function": {"sig": {"inputs": [["x", {"resolved_path": {"path": "i32"}}]], "output": {"resolved_path": {"path": "String"}}}, "header": {"abi": "Rust"}, "has_body": false}}},
        "3": {"id": 3, "name": "Widget", "docs": "A widget.", "span": null,
              "inner": {"struct": {"kind": {"plain": {"fields": []}}, "impls": [10]}}},
        "4": {"id": 4, "name": "Status", "docs": "Status enum.", "span": null,
              "inner": {"enum": {"variants": [], "impls": []}}},
        "5": {"id": 5, "name": "Render", "docs": "Render trait.", "span": null,
              "inner": {"trait": {"items": []}}},
        "10": {"id": 10, "name": null, "docs": null, "span": null,
               "inner": {"impl": {"is_unsafe": false, "generics": {"params": [], "where_predicates": []},
                                  "provided_trait_methods": [], "trait": null, "for": null,
                                  "items": [11], "is_negative": false, "is_synthetic": false, "blanket_impl": null}}},
        "11": {"id": 11, "name": "build", "docs": "Builds the widget.", "span": null,
               "inner": {"function": {"sig": {"inputs": [], "output": {"resolved_path": {"path": "Widget"}}},
                                       "header": {"abi": "Rust"}, "has_body": true}}}
      },
      "paths": {}, "external_crates": {}
    }"#;

    #[test]
    fn parse_minimal_v60_emits_all_top_level_kinds() {
        let symbols = parse_rustdoc_json(MINIMAL_V60, "demo", "1.0.0").unwrap();
        let kinds: Vec<_> = symbols.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SymbolKind::Module));
        assert!(kinds.contains(&SymbolKind::Function));
        assert!(kinds.contains(&SymbolKind::Class));
        assert!(kinds.contains(&SymbolKind::Enum));
        assert!(kinds.contains(&SymbolKind::Interface));
    }

    #[test]
    fn function_signature_includes_inputs_and_return() {
        let symbols = parse_rustdoc_json(MINIMAL_V60, "demo", "1.0.0").unwrap();
        let func = symbols.iter().find(|s| s.name == "do_thing").expect("do_thing not found");
        let sig = func.signature.as_deref().unwrap_or("");
        assert!(sig.contains("fn do_thing"), "sig was: {}", sig);
        assert!(sig.contains("x: i32"), "sig was: {}", sig);
        assert!(sig.contains("-> String"), "sig was: {}", sig);
        assert_eq!(func.params.len(), 1);
        assert_eq!(func.params[0].name, "x");
        assert_eq!(func.params[0].type_name, "i32");
    }

    #[test]
    fn method_extracted_from_impl() {
        let symbols = parse_rustdoc_json(MINIMAL_V60, "demo", "1.0.0").unwrap();
        let method = symbols.iter().find(|s| s.kind == SymbolKind::Method).expect("method not found");
        assert_eq!(method.name, "build");
        assert_eq!(method.path, "demo.Widget.build");
    }

    #[test]
    fn parses_enum_and_trait_methods() {
        // Regression for P1.4: enum impls (`Option::is_some`-style methods)
        // and trait default/required methods were previously dropped.
        // Fixture covers both kinds in a single parse.
        const FIXTURE: &str = r#"{
          "root": "1", "crate_version": "1.0.0", "includes_private": false,
          "format_version": 60, "target": "x86_64-unknown-linux-gnu",
          "index": {
            "1": {"id": 1, "name": "demo", "docs": null, "span": null, "inner": {"module": {"items": [2, 3]}}},
            "2": {"id": 2, "name": "Status", "docs": "Status enum.", "span": null,
                  "inner": {"enum": {"variants": [], "impls": [10]}}},
            "3": {"id": 3, "name": "Render", "docs": "Render trait.", "span": null,
                  "inner": {"trait": {"items": [20]}}},
            "10": {"id": 10, "name": null, "docs": null, "span": null,
                   "inner": {"impl": {"is_unsafe": false, "generics": {"params": [], "where_predicates": []},
                                      "provided_trait_methods": [], "trait": null, "for": null,
                                      "items": [11], "is_negative": false, "is_synthetic": false, "blanket_impl": null}}},
            "11": {"id": 11, "name": "is_active", "docs": "Enum method.", "span": null,
                   "inner": {"function": {"sig": {"inputs": [["self", {"borrowed_ref": {"type": {"generic": "Self"}, "is_mut": false}}]], "output": {"primitive": "bool"}}, "header": {"abi": "Rust"}, "has_body": true}}},
            "20": {"id": 20, "name": "build", "docs": "Trait default method.", "span": null,
                   "inner": {"function": {"sig": {"inputs": [], "output": {"resolved_path": {"path": "Self"}}}, "header": {"abi": "Rust"}, "has_body": true}}}
          },
          "paths": {}, "external_crates": {}
        }"#;

        let symbols = parse_rustdoc_json(FIXTURE, "demo", "1.0.0").unwrap();

        // Enum method extracted via the impl walk.
        let enum_method = symbols
            .iter()
            .find(|s| s.path == "demo.Status.is_active")
            .unwrap_or_else(|| panic!("enum method missing; got paths: {:?}",
                symbols.iter().map(|s| &s.path).collect::<Vec<_>>()));
        assert_eq!(enum_method.kind, SymbolKind::Method);
        assert_eq!(enum_method.name, "is_active");

        // Trait method extracted via the trait-items walk.
        let trait_method = symbols
            .iter()
            .find(|s| s.path == "demo.Render.build")
            .unwrap_or_else(|| panic!("trait method missing; got paths: {:?}",
                symbols.iter().map(|s| &s.path).collect::<Vec<_>>()));
        assert_eq!(trait_method.kind, SymbolKind::Method);
        assert_eq!(trait_method.name, "build");
    }

    #[test]
    fn struct_maps_to_class() {
        let symbols = parse_rustdoc_json(MINIMAL_V60, "demo", "1.0.0").unwrap();
        let s = symbols.iter().find(|s| s.name == "Widget").expect("Widget not found");
        assert_eq!(s.kind, SymbolKind::Class);
        assert_eq!(s.path, "demo.Widget");
    }

    #[test]
    fn trait_maps_to_interface() {
        let symbols = parse_rustdoc_json(MINIMAL_V60, "demo", "1.0.0").unwrap();
        let t = symbols.iter().find(|s| s.name == "Render").expect("Render not found");
        assert_eq!(t.kind, SymbolKind::Interface);
    }

    #[test]
    fn invalid_json_errors() {
        assert!(parse_rustdoc_json("{not valid", "x", "1.0.0").is_err());
    }

    #[test]
    fn missing_index_errors() {
        assert!(parse_rustdoc_json(r#"{"format_version": 60}"#, "x", "1.0.0").is_err());
    }

    #[test]
    fn wrong_format_version_errors() {
        // v59 (predates the impl/inner shape we parse) — must reject.
        let too_old = r#"{"format_version": 59, "index": {}}"#;
        let err = parse_rustdoc_json(too_old, "x", "1.0.0").unwrap_err();
        assert!(err.contains("format_version"), "err was: {}", err);
        // Missing field entirely (unwrap_or(0) path) — must also reject.
        let missing = r#"{"index": {}}"#;
        let err = parse_rustdoc_json(missing, "x", "1.0.0").unwrap_err();
        assert!(err.contains("format_version"), "err was: {}", err);
    }

    #[test]
    fn empty_index_returns_empty_symbols() {
        let s = parse_rustdoc_json(r#"{"format_version": 60, "index": {}}"#, "x", "1.0.0").unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn type_to_string_handles_resolved_path() {
        let v: Value = serde_json::from_str(r#"{"resolved_path": {"path": "std::string::String"}}"#).unwrap();
        assert_eq!(type_to_string(&v), "String");
    }

    #[test]
    fn type_to_string_handles_primitive() {
        let v: Value = serde_json::from_str(r#"{"primitive": "i32"}"#).unwrap();
        assert_eq!(type_to_string(&v), "i32");
    }

    #[test]
    fn type_to_string_handles_generic() {
        let v: Value = serde_json::from_str(r#"{"generic": "T"}"#).unwrap();
        assert_eq!(type_to_string(&v), "T");
    }

    #[test]
    fn type_to_string_handles_tuple() {
        let v: Value = serde_json::from_str(r#"{"tuple": [{"primitive":"i32"}, {"primitive":"bool"}]}"#).unwrap();
        assert_eq!(type_to_string(&v), "(i32, bool)");
    }

    #[test]
    fn type_to_string_handles_empty_tuple() {
        let v: Value = serde_json::from_str(r#"{"tuple": []}"#).unwrap();
        assert_eq!(type_to_string(&v), "()");
    }

    #[test]
    fn type_to_string_handles_reference() {
        let v: Value = serde_json::from_str(r#"{"reference": {"type": {"primitive":"i32"}, "is_mut": false}}"#).unwrap();
        assert_eq!(type_to_string(&v), "&i32");
    }

    #[test]
    fn type_to_string_handles_slice() {
        let v: Value = serde_json::from_str(r#"{"slice": [{"primitive":"u8"}]}"#).unwrap();
        assert_eq!(type_to_string(&v), "[u8]");
    }
}
