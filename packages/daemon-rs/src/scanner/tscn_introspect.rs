//! Godot scene file (`.tscn`) introspection.
//!
//! Scene files use an INI-like format. The relevant verifiable structures:
//!
//! ```text
//! [gd_scene load_steps=2 format=3]
//!
//! [ext_resource type="Script" path="res://player.gd" id="1"]
//!
//! [node name="Player" type="CharacterBody2D"]
//! script = ExtResource("1")
//! ```
//!
//! FORGE checks performed (no filesystem access required — pure static):
//!
//! 1. **`type="X"` in section headers** — `X` must be a known Godot class
//!    (for `[node]` and `[sub_resource]`) or a known resource type (for
//!    `[ext_resource]`). Misses get a levenshtein suggestion.
//! 2. **`ExtResource("N")` / `SubResource("N")` references** — `N` must
//!    match a previously-declared `id="N"`. Hallucinated IDs flag.
//!
//! `path="res://..."` is NOT verified — it requires project filesystem
//! access and is a runtime-loaded resource.

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::SymbolKind;
use once_cell::sync::Lazy;
use std::collections::HashSet;

/// Common Godot resource types for `[ext_resource type="..."]`.
///
/// These aren't always Class-kind in the symbol cache (some are abstract
/// type tags), so we keep an allowlist separate from `is_known_godot_class`.
static KNOWN_EXT_RESOURCE_TYPES: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        // Resource kinds.
        "Resource", "Script", "GDScript", "CSharpScript",
        "Texture", "Texture2D", "CompressedTexture2D", "PortableCompressedTexture2D",
        "ImageTexture", "AnimatedTexture", "AtlasTexture",
        "Material", "StandardMaterial3D", "ORMMaterial3D",
        "Shader", "ShaderMaterial", "ShaderInclude",
        "Mesh", "ArrayMesh", "PrimitiveMesh", "BoxMesh", "QuadMesh", "SphereMesh",
        "MeshLibrary", "TileSet", "TileSetAtlasSource", "TileMap",
        "PackedScene", "Scene",
        "AudioStream", "AudioStreamWAV", "AudioStreamMP3", "AudioStreamOggVorbis",
        "Font", "FontFile", "SystemFont",
        "StyleBox", "StyleBoxFlat", "StyleBoxTexture", "StyleBoxLine",
        "Gradient", "GradientTexture1D", "GradientTexture2D",
        "Curve", "Curve2D", "Curve3D",
        "Animation", "AnimationLibrary", "AnimationNode", "AnimationNodeBlendTree",
        "JSON", "BMFont",
        "BitMap", "OccluderPolygon2D", "ConvexPolygonShape2D",
        "Environment", "WorldEnvironment", "Sky", "ProceduralSkyMaterial",
        "Theme",
        "BinaryInputStream", // not Godot but seen in some test fixtures
    ]
    .iter()
    .copied()
    .collect()
});

/// Built-in scalars that may appear in node properties or `sub_resource type=`.
/// Not strictly classes but valid types in scene files.
static SCALAR_TYPE_NAMES: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        "Vector2", "Vector3", "Vector4",
        "Color", "Rect2", "Rect2i", "AABB",
        "Transform2D", "Transform3D", "Basis", "Quaternion",
        "int", "float", "bool", "String", "StringName", "NodePath",
        "Array", "PackedStringArray", "PackedInt32Array", "PackedFloat32Array",
        "Dictionary", "Variant", "Object",
    ]
    .iter()
    .copied()
    .collect()
});

/// Result of a tscn FORGE scan.
#[derive(Debug, Default)]
pub struct TscnResult {
    pub warnings: Vec<String>,
    pub claims_extracted: usize,
    pub claims_hallucinated: usize,
}

/// Verify a `.tscn` (Godot scene) file's static structure.
pub fn verify_tscn(content: &str, cache: &SymbolCache) -> TscnResult {
    let mut result = TscnResult::default();
    let mut declared_ids: HashSet<String> = HashSet::new();

    // Pass 1: collect declared ext_resource / sub_resource IDs.
    for line in content.lines() {
        if let Some(attrs) = parse_section(line) {
            let section = attrs.section.as_str();
            if section == "ext_resource" || section == "sub_resource" {
                if let Some(id) = attrs.get_str("id") {
                    declared_ids.insert(id.to_string());
                }
            }
        }
    }

    // Pass 2: verify type attributes + ExtResource/SubResource references.
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if let Some(attrs) = parse_section(line) {
            match attrs.section.as_str() {
                "ext_resource" => {
                    if let Some(ty) = attrs.get_str("type") {
                        verify_resource_type(ty, cache, &mut result);
                    }
                }
                "node" => {
                    if let Some(ty) = attrs.get_str("type") {
                        verify_node_type(ty, cache, &mut result);
                    }
                }
                "sub_resource" => {
                    if let Some(ty) = attrs.get_str("type") {
                        verify_resource_type(ty, cache, &mut result);
                    }
                }
                _ => {}
            }
        } else if line.contains('=') {
            // Property assignment line — look for ExtResource("N") / SubResource("N").
            verify_resource_references(line, &declared_ids, &mut result);
        }
    }

    result
}

/// Verify a `type=` attribute on `[ext_resource]` or `[sub_resource]`.
fn verify_resource_type(ty: &str, cache: &SymbolCache, result: &mut TscnResult) {
    if KNOWN_EXT_RESOURCE_TYPES.contains(ty) || SCALAR_TYPE_NAMES.contains(ty) {
        return;
    }
    if is_known_godot_class(cache, ty) {
        return;
    }
    // Miss — hallucinated type. Find closest suggestion across cached classes
    // and the static allowlist.
    result.claims_extracted += 1;
    let suggestion = closest_resource_type(ty, cache);
    match suggestion {
        Some(s) => {
            result.warnings.push(format!(
                "hallucinated-resource-type: `{ty}` — not a known Godot resource type. Did you mean `{s}`?"
            ));
        }
        None => {
            result.warnings.push(format!(
                "hallucinated-resource-type: `{ty}` — not a known Godot resource type"
            ));
        }
    }
    result.claims_hallucinated += 1;
}

/// Verify a `type=` attribute on `[node]`. Node types must be Godot Node-derived classes.
fn verify_node_type(ty: &str, cache: &SymbolCache, result: &mut TscnResult) {
    // Allow the bare keyword for the scene root.
    if ty.is_empty() {
        return;
    }
    if is_known_godot_class(cache, ty) {
        return;
    }
    result.claims_extracted += 1;
    let suggestion = closest_node_type(ty, cache);
    match suggestion {
        Some(s) => {
            result.warnings.push(format!(
                "hallucinated-node-type: `{ty}` — not a known Godot Node class. Did you mean `{s}`?"
            ));
        }
        None => {
            result.warnings.push(format!(
                "hallucinated-node-type: `{ty}` — not a known Godot Node class"
            ));
        }
    }
    result.claims_hallucinated += 1;
}

/// Verify `ExtResource("N")` / `SubResource("N")` references against declared IDs.
fn verify_resource_references(line: &str, declared: &HashSet<String>, result: &mut TscnResult) {
    let re = regex::Regex::new(r#"(ExtResource|SubResource)\s*\(\s*"([^"]+)"\s*\)"#).unwrap();
    for caps in re.captures_iter(line) {
        let kind = caps.get(1).map(|m| m.as_str()).unwrap_or("Resource");
        let id = match caps.get(2) {
            Some(m) => m.as_str(),
            None => continue,
        };
        result.claims_extracted += 1;
        if !declared.contains(id) {
            result.warnings.push(format!(
                "hallucinated-reference: `{kind}(\"{id}\")` — no `[ext_resource id=\"{id}\"]` declaration found"
            ));
            result.claims_hallucinated += 1;
        }
    }
}

/// Find the closest known resource type to `ty` via levenshtein.
/// Tightened: distance ≤ 3 (was ≤4), minimum name length 4, length ratio ≥ 0.60.
fn closest_resource_type(ty: &str, cache: &SymbolCache) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for &known in KNOWN_EXT_RESOURCE_TYPES.iter() {
        if ty.len() < 4 || known.len() < 4 { continue; }
        let ratio = known.len().min(ty.len()) as f64
            / known.len().max(ty.len()) as f64;
        if ratio < 0.60 { continue; }
        let d = levenshtein_capped(ty, known, 4);
        match d {
            Some(d) if d <= 3 && best.as_ref().map_or(true, |(bd, _)| d < *bd) => {
                best = Some((d, known.to_string()));
            }
            _ => {}
        }
    }
    if let Some((_, name)) = best {
        return Some(name);
    }
    // Fall back to cached classes.
    cache
        .find_classes_with_prefix(&ty.chars().take(3).collect::<String>())
        .into_iter()
        .next()
        .map(|(_, name)| name)
}

/// Find the closest Node-derived class to `ty` via prefix + levenshtein.
/// Tightened: 4-char prefix (was 3), distance ≤ 3 (was ≤4), length ratio ≥ 0.60.
/// Class/type names use ≤3 because compound names like CharacterBody2D↔CharacterActor2D
/// can have distance 4 — tight ≤2 would miss legitimate hallucinations.
fn closest_node_type(ty: &str, cache: &SymbolCache) -> Option<String> {
    let prefix: String = ty.chars().take(4).collect();
    let candidates = cache.find_classes_with_prefix(&prefix);
    let mut best: Option<(usize, String)> = None;
    for (_, name) in candidates {
        if ty.len() < 4 || name.len() < 4 { continue; }
        let ratio = name.len().min(ty.len()) as f64
            / name.len().max(ty.len()) as f64;
        if ratio < 0.60 { continue; }
        let d = levenshtein_capped(ty, &name, 4)?;
        if d <= 3 && best.as_ref().map_or(true, |(bd, _)| d < *bd) {
            best = Some((d, name));
        }
    }
    best.map(|(_, name)| name)
}

/// Check whether `class` is a known Godot class (kind = Class) in the cache.
fn is_known_godot_class(cache: &SymbolCache, class: &str) -> bool {
    cache
        .lookup_global(class)
        .iter()
        .any(|s| s.library == "godot" && s.kind == SymbolKind::Class)
}

/// Levenshtein distance capped at `max`. Returns None if exceeds.
fn levenshtein_capped(a: &str, b: &str, max: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        let mut row_min = curr[0];
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
            row_min = row_min.min(curr[j]);
        }
        if row_min > max {
            return None;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    let d = prev[b.len()];
    if d > max { None } else { Some(d) }
}

/// Parsed `[section key="val" ...]` line.
struct SectionAttrs {
    section: String,
    pairs: Vec<(String, String)>,
}

impl SectionAttrs {
    fn get_str(&self, key: &str) -> Option<&str> {
        self.pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// Parse a `[section key="val" ...]` line. Returns None if not a section header.
fn parse_section(line: &str) -> Option<SectionAttrs> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix('[')?;
    let rest = rest.strip_suffix(']')?;
    if rest.is_empty() {
        return None;
    }
    // First token = section name.
    let (section, rest) = match rest.find(char::is_whitespace) {
        Some(i) => (rest[..i].to_string(), rest[i..].trim_start()),
        None => (rest.to_string(), ""),
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    // Walk `key="value"` or `key=value` pairs.
    let pair_re = regex::Regex::new(r#"(\w+)\s*=\s*(?:"([^"]*)"|(\S+))"#).unwrap();
    for caps in pair_re.captures_iter(rest) {
        let key = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let val = caps.get(2)
            .or_else(|| caps.get(3))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if !key.is_empty() {
            pairs.push((key, val));
        }
    }
    Some(SectionAttrs { section, pairs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_node_section() {
        let s = parse_section(r#"[node name="Player" type="CharacterBody2D"]"#).unwrap();
        assert_eq!(s.section, "node");
        assert_eq!(s.get_str("name"), Some("Player"));
        assert_eq!(s.get_str("type"), Some("CharacterBody2D"));
    }

    #[test]
    fn parses_ext_resource_section() {
        let s = parse_section(r#"[ext_resource type="Script" path="res://player.gd" id="1"]"#).unwrap();
        assert_eq!(s.section, "ext_resource");
        assert_eq!(s.get_str("type"), Some("Script"));
        assert_eq!(s.get_str("id"), Some("1"));
    }

    #[test]
    fn rejects_non_section_line() {
        assert!(parse_section("not a section").is_none());
        assert!(parse_section("[only").is_none());
    }

    #[test]
    fn levenshtein_capped_basic() {
        assert_eq!(levenshtein_capped("kitten", "sitting", 3), Some(3));
        assert_eq!(levenshtein_capped("abc", "xyz", 5), Some(3));
        assert_eq!(levenshtein_capped("abc", "xyz", 1), None);
    }

    #[test]
    fn detects_hallucinated_node_type() {
        let cache = match SymbolCache::open() {
            Ok(c) => c,
            Err(_) => { eprintln!("skip: no cache"); return; }
        };
        let content = r#"[gd_scene load_steps=1 format=3]

[node name="Player" type="CharacterActor2D"]
"#;
        let r = verify_tscn(content, &cache);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("CharacterActor2D")));
    }

    #[test]
    fn accepts_real_node_type() {
        let cache = match SymbolCache::open() {
            Ok(c) => c,
            Err(_) => { eprintln!("skip: no cache"); return; }
        };
        let content = r#"[gd_scene load_steps=1 format=3]

[node name="Player" type="CharacterBody2D"]
"#;
        let r = verify_tscn(content, &cache);
        assert_eq!(r.claims_hallucinated, 0);
    }

    #[test]
    fn flags_undeclared_ext_resource_reference() {
        let cache = match SymbolCache::open() {
            Ok(c) => c,
            Err(_) => { eprintln!("skip: no cache"); return; }
        };
        let content = r#"[gd_scene load_steps=1 format=3]

[ext_resource type="Script" path="res://player.gd" id="1"]

[node name="Player" type="CharacterBody2D"]
script = ExtResource("99")
"#;
        let r = verify_tscn(content, &cache);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("99")));
    }

    #[test]
    fn accepts_declared_ext_resource_reference() {
        let cache = match SymbolCache::open() {
            Ok(c) => c,
            Err(_) => { eprintln!("skip: no cache"); return; }
        };
        let content = r#"[gd_scene load_steps=1 format=3]

[ext_resource type="Script" path="res://player.gd" id="1"]

[node name="Player" type="CharacterBody2D"]
script = ExtResource("1")
"#;
        let r = verify_tscn(content, &cache);
        assert_eq!(r.claims_hallucinated, 0);
    }
}
