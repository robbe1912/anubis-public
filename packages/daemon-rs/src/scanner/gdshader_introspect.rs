//! Godot shader (`.gdshader`) introspection.
//!
//! Shader grammar is a closed, stable set — no symbol cache needed.
//! Reference: <https://docs.godotengine.org/en/stable/tutorials/shaders/shader_reference/index.html>
//!
//! Verifiable structures:
//!
//! ```text
//! shader_type canvas_item;       // canvas_item | spatial | sky | particles
//! render_mode blend_mix, unshaded;
//! uniform float strength : source_color;
//! uniform vec4 tint : hint_default_white;
//! uniform sampler2D main_tex;
//!
//! void fragment() {
//!     vec4 c = textureLod(TEXTURE, UV, 0.0);
//!     COLOR = mix(c, tint, strength);
//! }
//! ```
//!
//! FORGE checks (all use closed keyword lists, no cache queries):
//! 1. `shader_type` value — must be in `{spatial, canvas_item, sky, particles}`.
//! 2. `render_mode` value — checked against the union of all modes (loses
//!    per-shader-type precision but still catches typos).
//! 3. `uniform <type>` — type must be a valid GLSL/Godot scalar.
//! 4. `uniform <name> : <hint>` — hint must be a valid Godot hint.
//! 5. Bare function calls — must be in the GLSL + Godot built-in set.

use once_cell::sync::Lazy;
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct GdshaderResult {
    pub warnings: Vec<String>,
    pub claims_extracted: usize,
    pub claims_hallucinated: usize,
}

/// Valid `shader_type` values (Godot 4.x).
static SHADER_TYPES: Lazy<HashSet<&str>> = Lazy::new(|| {
    ["spatial", "canvas_item", "sky", "particles"].iter().copied().collect()
});

/// Valid `render_mode` values — union across all shader types.
/// (Per-type filtering would require tracking which `shader_type` is active.)
static RENDER_MODES: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        // Blend modes (canvas_item + spatial).
        "blend_mix", "blend_add", "blend_sub", "blend_mul", "blend_premul_alpha",
        "blend_disabled",
        // Spatial-specific.
        "unshaded", "wireframe", "depth_test_disabled", "depth_draw_opaque",
        "depth_draw_always", "depth_draw_never", "cull_front", "cull_back",
        "cull_disabled", "world_vertex_coords",
        // Canvas-item-specific.
        "skip_vertex_transform",
        // Particle-specific.
        "disable_velocity", "disable_scale", "disable_force", "keep_data",
        // Sky.
        "use_half_res", "use_quarter_res", "disable_depth",
        // Common.
        "shadows_disabled", "ambient_light_disabled", "shadow_to_opacity",
    ]
    .iter()
    .copied()
    .collect()
});

/// Valid uniform scalar/vector/matrix types.
static UNIFORM_TYPES: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        // Scalars.
        "float", "int", "uint", "bool",
        // Vectors.
        "vec2", "vec3", "vec4", "ivec2", "ivec3", "ivec4", "uvec2", "uvec3", "uvec4",
        "bvec2", "bvec3", "bvec4",
        // Matrices.
        "mat2", "mat3", "mat4",
        // Samplers.
        "sampler2D", "sampler2DArray", "sampler3D", "samplerCube",
        "samplerCubeArray", "samplerExternalOES",
    ]
    .iter()
    .copied()
    .collect()
});

/// Valid `uniform name : hint` hints.
static UNIFORM_HINTS: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        "source_color", "source_color_srgb",
        "hint_default_white", "hint_default_black", "hint_default_transparent",
        "hint_anisotropy", "hint_range",
        // Sampler hints (Godot 3-style, sometimes still seen).
        "filter_linear", "filter_nearest", "filter_linear_mipmap",
        "filter_nearest_mipmap", "repeat_enable", "repeat_disable",
        "hint_normal", "hint_roughness", "hint_roughness_r", "hint_roughness_g",
        "hint_roughness_b", "hint_roughness_a", "hint_roughness_normal",
    ]
    .iter()
    .copied()
    .collect()
});

/// Built-in GLSL + Godot shader functions.
static BUILTIN_FUNCTIONS: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        // GLSL builtins.
        "abs", "acos", "acosh", "all", "any", "asin", "asinh", "atan", "atanh",
        "ceil", "clamp", "cos", "cosh", "cross", "degrees", "determinant",
        "distance", "dot", "equal", "exp", "exp2", "faceforward", "floor",
        "fract", "greaterThan", "greaterThanEqual", "inversesqrt", "isinf",
        "isnan", "length", "lessThan", "lessThanEqual", "log", "log2", "matrixCompMult",
        "max", "min", "mix", "mod", "modf", "normalize", "notEqual", "outerProduct",
        "pow", "radians", "reflect", "refract", "round", "roundEven", "sign",
        "sin", "sinh", "smoothstep", "sqrt", "step", "tan", "tanh", "transpose",
        "trunc",
        // Godot extensions.
        "texture", "textureLod", "textureGrad", "textureProj", "textureSize",
        "texelFetch", "dFdx", "dFdy", "fwidth",
        // Matrix constructors.
        "vec2", "vec3", "vec4", "ivec2", "ivec3", "ivec4", "mat2", "mat3", "mat4",
    ]
    .iter()
    .copied()
    .collect()
});



/// Verify a `.gdshader` file.
pub fn verify_gdshader(content: &str) -> GdshaderResult {
    let mut result = GdshaderResult::default();
    let stripped = strip_comments(content);

    // 1. shader_type X;
    let st_re = regex::Regex::new(r"\bshader_type\s+([a-z_]\w*)").unwrap();
    for caps in st_re.captures_iter(&stripped) {
        let ty = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        result.claims_extracted += 1;
        if !SHADER_TYPES.contains(ty) {
            let sugg = closest(ty, &SHADER_TYPES);
            result.warnings.push(format!(
                "hallucinated-shader-type: `{ty}` — not a valid shader_type. Did you mean `{sugg}`?"
            ));
            result.claims_hallucinated += 1;
        }
    }

    // 2. render_mode a, b, c;
    let rm_re = regex::Regex::new(r"\brender_mode\s+([^;]+)").unwrap();
    for caps in rm_re.captures_iter(&stripped) {
        let modes_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        for mode in modes_str.split(',') {
            let mode = mode.trim();
            if mode.is_empty() { continue; }
            // Strip trailing modifiers like "depth_draw_opaque=false".
            let name = mode.split('=').next().unwrap_or("").trim();
            if name.is_empty() { continue; }
            result.claims_extracted += 1;
            if !RENDER_MODES.contains(name) {
                let sugg = closest(name, &RENDER_MODES);
                result.warnings.push(format!(
                    "hallucinated-render-mode: `{name}` — not a valid render_mode. Did you mean `{sugg}`?"
                ));
                result.claims_hallucinated += 1;
            }
        }
    }

    // 3 + 4. uniform <type> <name> [: hint];
    let uniform_re = regex::Regex::new(
        r"\buniform\s+(\w+)\s+(\w+)\s*(?::\s*([a-z_]\w+))?",
    ).unwrap();
    for caps in uniform_re.captures_iter(&stripped) {
        let ty = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let _name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let hint = caps.get(3).map(|m| m.as_str());
        if !UNIFORM_TYPES.contains(ty) {
            result.claims_extracted += 1;
            let sugg = closest(ty, &UNIFORM_TYPES);
            result.warnings.push(format!(
                "hallucinated-uniform-type: `{ty}` — not a valid uniform type. Did you mean `{sugg}`?"
            ));
            result.claims_hallucinated += 1;
        }
        if let Some(h) = hint {
            result.claims_extracted += 1;
            if !UNIFORM_HINTS.contains(h) {
                let sugg = closest(h, &UNIFORM_HINTS);
                result.warnings.push(format!(
                    "hallucinated-uniform-hint: `{h}` — not a valid uniform hint. Did you mean `{sugg}`?"
                ));
                result.claims_hallucinated += 1;
            }
        }
    }

    // 5. Bare function calls — `name(` not preceded by `.`.
    // Skip user-defined functions (void/int/float/vec* return types).
    let bytes = stripped.as_bytes();
    let user_funcs = collect_user_functions(&stripped);
    let call_re = regex::Regex::new(r"\b([a-zA-Z_]\w*)\s*\(").unwrap();
    for caps in call_re.captures_iter(&stripped) {
        let name = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        // Skip user-defined functions.
        if user_funcs.contains(name) { continue; }
        // Skip type constructors (already in BUILTIN_FUNCTIONS).
        // Skip if preceded by `.` (member access — fragment() in foo.fragment()).
        let start = caps.get(1).unwrap().start();
        if start > 0 {
            let mut p = start;
            while p > 0 && bytes[p - 1].is_ascii_whitespace() { p -= 1; }
            if p > 0 && bytes[p - 1] == b'.' { continue; }
        }
        // Skip declaration: `void foo(`, `float bar(`, etc.
        if is_function_declaration(&stripped, start) { continue; }
        result.claims_extracted += 1;
        if !BUILTIN_FUNCTIONS.contains(name) {
            let sugg = closest(name, &BUILTIN_FUNCTIONS);
            result.warnings.push(format!(
                "hallucinated-method: `{name}(...)` — not a known GLSL/Godot builtin. Did you mean `{sugg}`?"
            ));
            result.claims_hallucinated += 1;
        }
    }

    result
}

/// Collect user-defined function names from `void/int/float/etc. name(...)` declarations.
fn collect_user_functions(stripped: &str) -> HashSet<String> {
    let re = regex::Regex::new(r"\b(?:void|int|float|bool|vec2|vec3|vec4|mat2|mat3|mat4)\s+([a-zA-Z_]\w*)\s*\(").unwrap();
    let mut out = HashSet::new();
    for caps in re.captures_iter(stripped) {
        if let Some(m) = caps.get(1) {
            out.insert(m.as_str().to_string());
        }
    }
    out
}

/// True if the identifier at `start` is preceded by a return-type keyword
/// (i.e., this is a function declaration, not a call).
fn is_function_declaration(stripped: &str, start: usize) -> bool {
    let before = &stripped[..start];
    let trimmed = before.trim_end();
    let last_word = trimmed
        .rsplit([' ', '\t', '\n', ';', '{', '}', '('])
        .next()
        .unwrap_or("");
    matches!(last_word, "void" | "int" | "float" | "bool" | "vec2" | "vec3" | "vec4" | "mat2" | "mat3" | "mat4")
}

/// Find closest match in `set` via capped levenshtein.
/// Tightened from original: distance ≤ 3 (was ≤4), minimum name length 4,
/// length ratio ≥ 0.60. Class/type names use ≤3 (looser than method ≤2)
/// because compound shader types often differ by more than 2 chars.
fn closest(ty: &str, set: &HashSet<&str>) -> String {
    let mut best: Option<(usize, &str)> = None;
    for &candidate in set.iter() {
        if ty.len() < 4 || candidate.len() < 4 { continue; }
        let ratio = candidate.len().min(ty.len()) as f64
            / candidate.len().max(ty.len()) as f64;
        if ratio < 0.60 { continue; }
        let d = levenshtein_capped(ty, candidate, 4);
        if let Some(d) = d {
            if d <= 3 && best.as_ref().map_or(true, |(bd, _)| d < *bd) {
                best = Some((d, candidate));
            }
        }
    }
    best.map(|(_, name)| name.to_string()).unwrap_or_else(|| "?".into())
}

/// Levenshtein capped at `max`.
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

/// Strip `//` and `/* */` comments. Strings aren't common in shaders so
/// we skip string-literal stripping for simplicity.
fn strip_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < n && bytes[i] != b'\n' { i += 1; }
            continue;
        }
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') { i += 1; }
            i += 2;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_shader_type() {
        let src = "shader_type canvas_item;\nvoid fragment(){}\n";
        let r = verify_gdshader(src);
        assert_eq!(r.claims_hallucinated, 0);
    }

    #[test]
    fn flags_invalid_shader_type() {
        let src = "shader_type canvas_widget;\nvoid fragment(){}\n";
        let r = verify_gdshader(src);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("canvas_widget")));
    }

    #[test]
    fn flags_invalid_render_mode() {
        let src = "shader_type canvas_item;\nrender_mode blend_mixed;\nvoid fragment(){}\n";
        let r = verify_gdshader(src);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("blend_mixed")));
    }

    #[test]
    fn flags_invalid_uniform_type() {
        let src = "shader_type canvas_item;\nuniform realscalar x;\nvoid fragment(){}\n";
        let r = verify_gdshader(src);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("realscalar")));
    }

    #[test]
    fn flags_invalid_uniform_hint() {
        let src = "shader_type canvas_item;\nuniform vec4 tint : source_color_albedo;\nvoid fragment(){}\n";
        let r = verify_gdshader(src);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("source_color_albedo")));
    }

    #[test]
    fn flags_invalid_builtin_call() {
        let src = "shader_type canvas_item;\nvoid fragment(){ float d = dot_product(vec3(1.0), vec3(1.0)); }\n";
        let r = verify_gdshader(src);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("dot_product")));
    }

    #[test]
    fn accepts_valid_builtin_call_case_sensitive() {
        // textureLod is correct; textureLOD is the hallucination.
        let src = "shader_type canvas_item;\nvoid fragment(){ vec4 c = textureLod(TEXTURE, UV, 0.0); }\n";
        let r = verify_gdshader(src);
        // textureLod is valid builtin, should not be flagged.
        assert!(!r.warnings.iter().any(|w| w.contains("textureLod")));
    }

    #[test]
    fn flags_textureLOD_typo() {
        let src = "shader_type canvas_item;\nvoid fragment(){ vec4 c = textureLOD(TEXTURE, UV, 0.0); }\n";
        let r = verify_gdshader(src);
        assert!(r.claims_hallucinated >= 1);
        assert!(r.warnings.iter().any(|w| w.contains("textureLOD")));
    }
}
