//! GDScript/Godot FORGE runner — extracted from forge_pipeline.rs (M1 chunk 6).
//!
//! Verifies GDScript source against the cached Godot symbol table
//! (77K+ symbols fetched by godot_fetcher.rs). All verification is
//! local — no subprocess, no network.
//!
//! Submodules:
//!   - `extends` — class/init/inheritance helpers
//!   - `methods` — method/property verification + arity
//!
//! This module (runner + strip + undefined-vars):
//!   1. `extends ClassName` — ClassName must exist in Godot cache
//!   2. `obj.method` / `obj.property` — member must exist on resolved class
//!   3. Call arity — flag extra args against cached method signatures
//!   4. User-defined function arity — `func name(a, b)` vs `name(1, 2, 3)`
//!   5. Undefined variables — regex scope checker (var/const/param/for)

mod extends;
mod methods;

use crate::scanner::forge_types::ForgeResult;
use crate::scanner::levenshtein::capped as levenshtein_capped_internal;
use crate::scanner::string_filters::filter_function_calls;

/// GDScript FORGE pipeline.
///
/// GDScript is Godot's scripting language. The symbol cache already has
/// 77K+ Godot symbols (Node2D, Vector2, get_node, add_child, etc.) fetched
/// by godot_fetcher.rs. This pipeline verifies:
///   1. `extends ClassName` — checks if ClassName exists in Godot cache
///   2. Method calls on self/known nodes — checks against Godot API
///   3. Undefined variables — scope checker (var/const/param/for tracking)
///
/// No subprocess needed — all verification against existing SQLite cache.
pub(crate) async fn run_forge_gdscript(content: &str) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();

    // Scene-file guard: .tscn is a declarative resource format, NOT code.
    // Each `[node]` block lists property assignments like
    //   collision_layer = 1
    //   mouse_filter = 2
    //   margin_left = 10.0
    // The undefined-var scope checker treats every property name as an
    // undefined identifier. This produced 15+ FPs on task-011-godot.
    // Skip the entire pipeline — there is no GDScript code to verify.
    let scene_marker_re = regex::Regex::new(
        r"(?m)^\s*\[(?:gd_scene|ext_resource|sub_resource|node|connection|editable_instance)"
    ).unwrap();
    if scene_marker_re.is_match(content) {
        result.latency_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    // Language-contamination + prose guard (mirror forge_cpp / forge_csharp).
    let lower = content.to_lowercase();
    let english_count = [
        "the ", " a ", " an ", " is ", " are ", " was ", " were ", " to ",
        " of ", " in ", " on ", " at ", " by ", " for ", " with ", " from ",
        " this ", " that ", " it ", " its ", " as ", " be ", " have ",
        " has ", " do ", " does ", " will ", " would ", " could ", " should ",
        " can ", " may ", " might ",
    ].iter().map(|w| lower.matches(w).count()).sum::<usize>();
    let gd_kw_count = [
        "extends ", "class_name ", "func ", "var ", "const ", "signal ",
        "enum ", "export ", "onready ", "@onready ", "@export ",
        "if ", "elif ", "else:", "for ", "while ", "match ", "return ",
        "pass", "self.", "super.", "$", "%", "print(", "preload(",
        "load(", "get_node(", "_ready(", "_process(", "_physics_process(",
        "_input(", "Vector2", "Vector3", "Rect2", "Color", "Transform2D",
        "->", ":=", ": int", ": float", ": string", ": bool",
    ].iter().map(|w| lower.matches(w).count()).sum::<usize>();
    let other_lang_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("def ") || t.starts_with("import ") || t.starts_with("from ")
            || t.starts_with("func ") && t.contains(" {") // Go, not GDScript
            || t.starts_with("package ")
            || t.starts_with("pub fn ") || t.starts_with("fn ")
            || t.starts_with("public class") || t.starts_with("private ")
            || t.starts_with("using ") && t.contains(';')
            || t.starts_with("#include")
    }).count();
    let gd_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("extends ") || t.starts_with("class_name ")
            || t.starts_with("func ") || t.starts_with("var ")
            || t.starts_with("const ") || t.starts_with("signal ")
            || t.starts_with("export ") || t.starts_with("onready ")
            || t.starts_with("@onready") || t.starts_with("@export")
            || t.starts_with("if ") || t.starts_with("elif ")
            || t.starts_with("else:") || t.starts_with("else:")
            || t.starts_with("for ") || t.starts_with("while ")
            || t.starts_with("match ") || t.starts_with("return")
            || t.starts_with("pass") || t.starts_with("#")
            || t.starts_with("\t") || t.starts_with("    ")
    }).count();
    if other_lang_lines > gd_lines
        || gd_kw_count == 0
        || english_count > gd_kw_count * 3
    {
        result.latency_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    let extends_re = regex::Regex::new(r"(?m)^\s*extends\s+(\w+)").unwrap();
    if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
        // Cache-cold guard: the Godot class check below is only meaningful
        // when the symbol cache actually contains Godot symbols. The seed
        // bundle ships zero godot.* entries (live fetch is opt-in via the
        // CLI), so without this guard every `extends Node2D` / `extends Resource`
        // would be flagged as hallucinated-class — a broad FP across every
        // real Godot script. Skip until the cache is populated.
        let cache_has_godot = !cache.lookup_prefix("godot", "").is_empty();
        if cache_has_godot {
            for caps in extends_re.captures_iter(content) {
                if let Some(m) = caps.get(1) {
                    let class_name = m.as_str();
                    result.claims_extracted += 1;
                    // Check if this Godot class exists in cache.
                    if cache.lookup_global(class_name).is_empty() {
                        // Try fuzzy match against cached class names.
                        let candidates = cache.find_classes_with_prefix(&class_name.chars().take(5).collect::<String>());
                        let closest = candidates.iter()
                            .map(|(_, c)| (levenshtein_capped_internal(class_name, c, 4), c))
                            .filter(|(d, c)| {
                                if *d > 2 { return false; }
                                if class_name.len() < 4 || c.len() < 4 { return false; }
                                let ratio = c.len().min(class_name.len()) as f64
                                    / c.len().max(class_name.len()) as f64;
                                ratio >= 0.60
                            })
                            .min_by_key(|(d, _)| *d);
                        match closest {
                            Some((dist, suggestion)) => {
                                result.warnings.push(format!(
                                    "hallucinated-class: `{}` — not a valid Godot class. Did you mean `{}` (distance {})?",
                                    class_name, suggestion, dist
                                ));
                                result.claims_hallucinated += 1;
                            }
                            None => {
                                result.warnings.push(format!(
                                    "hallucinated-class: `{}` — not a valid Godot class",
                                    class_name
                                ));
                                result.claims_hallucinated += 1;
                            }
                        }
                    } else {
                        result.claims_verified += 1;
                    }
                }
            }
        }
    }

    // Step 2: Verify `obj.method` and `obj.property` against Godot cache.
    // Tracks variable types from initializers and the implicit class context
    // from `extends ClassName`, then flags hallucinated members with levenshtein
    // suggestions.
    if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
        methods::verify_gdscript_methods(content, &cache, &mut result);
        // Step 3: Arity check on resolved `obj.method(args)` calls.
        methods::verify_gdscript_call_arity(content, &cache, &mut result);
    }

    // Step 4: User-defined function arity check. Catches calls like `add(1)`
    // when the user declared `func add(a: int, b: int)` — too few args.
    methods::verify_gdscript_user_func_arity(content, &mut result);

    // Step 5: Undefined variable detection via regex scope checker.
    let undefined = extract_gdscript_undefined_variables(content);
    for name in &undefined {
        if name.len() >= 3 {
            result.warnings.push(format!(
                "hallucinated-variable: `{}` — referenced but not defined in scope",
                name
            ));
            result.claims_hallucinated += 1;
        }
    }
    result.claims_extracted += undefined.len();

    // Step 6: GDScript structural checks (deprecated APIs, reserved shadowing).
    // `.scancode` is Godot 3 API — removed in Godot 4. Use `.keycode` instead.
    if content.contains(".scancode") {
        result.warnings.push(
            "hallucinated-api: `.scancode` is Godot 3 API, removed in Godot 4. Use `.keycode` instead.".into()
        );
        result.claims_hallucinated += 1;
    }
    // Multiple `class_name` per file — GDScript allows exactly one.
    // NOTE: warning text avoids backticks around 'class_name' to prevent
    // the cross-response FP filter (mod.rs) from treating it as a
    // user-defined symbol and suppressing the warning.
    let class_name_count = content.matches("class_name").count();
    if class_name_count > 1 {
        result.warnings.push(format!(
            "hallucinated-api: found {} class_name declarations in one file — GDScript allows exactly one class_name per file.",
            class_name_count
        ));
        result.claims_hallucinated += 1;
    }
    // `@export var name` shadows Node.name — reserved property.
    if content.contains("@export var name") || content.contains("@export var name:") {
        result.warnings.push(
            "hallucinated-api: `@export var name` shadows reserved Node.name property. Use a different variable name.".into()
        );
        result.claims_hallucinated += 1;
    }

    // Step 7: Undefined function call detection.
    // Catches calls to functions that are never defined in the file
    // (no `func name(` declaration). Catches hallucinated methods like
    // `transition_to("idle")` when no `func transition_to` exists.
    //
    // Known methods come from FOUR sources:
    // 1. `func name(` declarations in this script
    // 2. `signal name` declarations — signals are callable (.connect/.emit)
    // 3. Symbol cache — all methods on the `extends ClassName` type.
    //    This automatically includes get_node, add_child, queue_free, etc.
    //    from the Godot class hierarchy. Data comes from live godot_fetcher.
    // 4. GDScript utility functions (print, load, range, etc.) in gd_keywords.
    //
    // Runs UNCONDITIONALLY — even with cold cache. When cache lacks Godot data,
    // inherited Node methods (get_node, add_child) may appear as FPs, but this
    // is recall-biased per constraint #7 (FN cost ≫ FP cost). The gd_keywords
    // set covers Godot global utility functions. L3 can adjudicate uncertain cases.
    let func_def_re = regex::Regex::new(r"(?m)^\s*func\s+([a-z_]\w*)\s*\(").unwrap();
    let mut known_funcs: std::collections::HashSet<String> = func_def_re
        .captures_iter(content)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();
    // Signals are callable: `signal_name.connect(...)` / `signal_name.emit(...)`.
    // Without this, every signal reference gets flagged as a hallucinated method.
    let signal_decl_re = regex::Regex::new(r"(?m)^\s*signal\s+(\w+)").unwrap();
    for caps in signal_decl_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            known_funcs.insert(m.as_str().to_string());
        }
    }
    let extends_re2 = regex::Regex::new(r"(?m)^\s*extends\s+(\w+)").unwrap();
    if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
        let add_class_methods = |class_name: &str, set: &mut std::collections::HashSet<String>| {
            let syms = cache.lookup_global(class_name);
            let lib = syms.iter()
                .find(|s| s.library.starts_with("godot."))
                .or_else(|| syms.first())
                .map(|s| s.library.as_str());
            if let Some(lib) = lib {
                let prefix = format!("{}.", class_name);
                for m in cache.lookup_prefix(lib, &prefix) {
                    let bare = m.path.rsplit('.').next().unwrap_or(&m.name);
                    set.insert(bare.to_string());
                }
            }
        };
        for caps in extends_re2.captures_iter(content) {
            add_class_methods(caps.get(1).unwrap().as_str(), &mut known_funcs);
        }
        add_class_methods("Object", &mut known_funcs);
    }

    // Run undefined-function check unconditionally.
    let gd_keywords: std::collections::HashSet<&str> = [
        "if", "elif", "else", "for", "while", "match", "func", "var",
        "const", "enum", "class", "extends", "class_name", "signal",
        "static", "await", "return", "pass", "breakpoint", "break",
        "continue", "and", "or", "not", "in", "as", "is", "self",
        "super", "tool", "void", "null", "true", "false", "NaN", "INF",
        // Godot 4 global utility functions — always available, no import needed.
        "print", "print_rich", "printerr", "printraw", "prints", "printt",
        "push_error", "push_warning", "load", "preload", "len", "range",
        "min", "max", "abs", "absf", "absi", "sign", "signf", "clamp",
        "clampf", "clampi", "lerp", "lerp_angle", "inverse_lerp", "remap",
        "smoothstep", "move_toward", "rotate_toward", "deg_to_rad",
        "rad_to_deg", "linear_to_db", "db_to_linear", "sin", "cos", "tan",
        "sinh", "cosh", "tanh", "asin", "acos", "atan", "atan2", "sqrt",
        "pow", "exp", "log", "fmod", "fposmod", "posmod", "floor", "ceil",
        "round", "snapped", "randf", "randi", "randf_range", "randi_range",
        "randomize", "rand_from_seed", "weakref", "funcref", "Color8",
        "type_exists", "type_string", "typeof", "instance_from_id",
        "is_instance_valid", "get_stack", "is_same", "is_floating",
        "is_instance_of", "is_class", "is_class_instance", "get_meta",
        "set_meta", "validate_instance_html",
        // Common Node inherited methods — called without self. prefix in GDScript.
        // These are the most frequently used methods from Node/CanvasItem/Node2D,
        // included as fallback when cache lacks Godot class hierarchy data.
        "get_node", "get_node_or_null", "has_node", "has_node_and_resource",
        "get_parent", "get_children", "add_child", "remove_child",
        "get_tree", "get_viewport", "queue_free", "is_inside_tree",
        "get_name", "set_name", "get_path", "get_path_to",
        "get_owner", "set_owner", "add_to_group", "remove_from_group",
        "is_in_group", "get_groups", "print_tree", "print_tree_pretty",
        "get_index", "get_child_count", "get_child", "move_child",
        "reparent", "get_window", "set_process", "set_physics_process",
        "set_process_input", "set_process_unhandled_input",
        "is_processing", "is_physics_processing",
        "create_tween", "emit_signal", "connect", "disconnect",
        "is_connected", "set_deferred", "call_deferred", "callv",
        "has_signal", "has_method", "has_feature", "get_class",
        "set", "get", "set_indexed", "get_indexed", "property_can_revert",
        "property_get_revert", "notification", "to_string", "duplicate",
        "find_child", "find_children", "find_parent", "get_child_count",
    ].iter().copied().collect();
    // Use STRIPPED content for the call scan so identifiers inside `# comment`
    // text and string literals don't get captured. Without this, a comment like
    // `# checking is_pressed() and InputEventKey` flags `is_pressed` as an
    // undefined method (task-17-gdscript-signals FP).
    let call_stripped = strip_gdscript_strings_and_comments(content);
    let call_re = regex::Regex::new(r"(?m)(?:^|[^.\w])([a-z_]\w*)\s*\(").unwrap();
    // Truncation guard: when the script is mid-statement (unbalanced brackets),
    // `_`-prefixed private-method calls are likely defined just past the cut.
    // Suppress those — the benchmark counts them as FPs.
    let is_truncated = gdscript_looks_truncated(content);
    let mut checked: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for caps in call_re.captures_iter(&call_stripped) {
        let name = caps.get(1).unwrap().as_str();
        if checked.contains(name) { continue; }
        checked.insert(name);
        if name.len() < 3 { continue; }
        if gd_keywords.contains(name) { continue; }
        if known_funcs.contains(name) { continue; }
        if is_truncated && name.starts_with('_') { continue; }
        result.warnings.push(format!(
            "hallucinated-method: `{}` — function called but not defined in this script",
            name
        ));
        result.claims_hallucinated += 1;
    }

    result.latency_ms = start.elapsed().as_millis() as u64;
    result
}

/// Strip string literals and comments from GDScript source so identifiers
/// inside them don't get collected as references. Replaces contents with
/// spaces (preserves byte offsets and line structure).
///
/// Handles:
/// - Triple-quoted strings `"""..."""` and `'''...'''` (multi-line)
/// - Single-line `"..."` and `'...'` (with backslash escapes)
/// - `#` line comments
/// - `\$Placeholder` interpolation markers (kept as `$` + identifier treated
///   as code — they ARE references and should be checked)
pub(super) fn strip_gdscript_strings_and_comments(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let b = bytes[i];
        // Triple-quoted string.
        if (b == b'"' && i + 2 < n && bytes[i + 1] == b'"' && bytes[i + 2] == b'"')
            || (b == b'\'' && i + 2 < n && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\'')
        {
            let quote = b;
            out.push(b' ');
            out.push(b' ');
            out.push(b' ');
            i += 3;
            while i + 2 < n && !(bytes[i] == quote && bytes[i + 1] == quote && bytes[i + 2] == quote)
            {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i + 2 < n {
                out.push(b' ');
                out.push(b' ');
                out.push(b' ');
                i += 3;
            }
            continue;
        }
        // Single-line string.
        if b == b'"' || b == b'\'' {
            let quote = b;
            out.push(b' ');
            i += 1;
            while i < n && bytes[i] != quote && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < n {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                out.push(b' ');
                i += 1;
            }
            if i < n && bytes[i] == quote {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Comment.
        if b == b'#' {
            while i < n && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| content.to_string())
}

/// Extract undefined variables from GDScript source via regex.
///
/// GDScript variable definitions:
///   var x, var x: Type, var x = val, onready var x, export var x
///   const X, func _ready(param), for x in, class_name X
///   enum Name { A, B, C }, class Inner extends Parent:, signal s(a, b)
///
/// Type annotations (`: Type`, `-> Type`) and `extends ClassName` references
/// are added to the defined set so Godot builtin types (String, Texture2D,
/// Resource, etc.) don't get flagged.
///
/// References: bare identifiers not after `.` (member access).
fn extract_gdscript_undefined_variables(content: &str) -> Vec<String> {
    use once_cell::sync::Lazy;
    use std::collections::HashSet;

    static GD_KEYWORDS: Lazy<HashSet<&str>> = Lazy::new(|| {
        [
            "extends", "class_name", "func", "var", "const", "enum", "signal",
            "export", "onready", "tool", "static", "pass", "return", "if",
            "elif", "else", "for", "in", "while", "match", "break", "continue",
            "and", "or", "not", "true", "false", "null", "self", "super",
            "breakpoint", "assert", "yield", "preload", "load", "remote",
            "master", "puppet", "slave", "sync", "renormalize", "as", "is",
            "setget", "property", "PI", "TAU", "INF", "NAN",
            "class", "void",
            // Common Godot builtins.
            "print", "str", "int", "float", "bool", "Vector2", "Vector3",
            "Rect2", "Transform2D", "Color", "Array", "Dictionary", "Node",
            "Node2D", "Node3D", "Sprite2D", "Label", "Button", "TextureRect",
            "Tween", "Timer", "AudioStreamPlayer", "Input", "Engine",
            "get_node", "get_parent", "add_child", "remove_child", "connect",
            "emit_signal", "set", "get", "call", "call_deferred", "queue_free",
            "print_rich", "push_error", "push_warning", "range", "len",
            "randf", "randi", "randomize", "sin", "cos", "tan", "sqrt",
            "abs", "sign", "clamp", "lerp", "range_lerp", "smoothstep",
            "deg_to_rad", "rad_to_deg", "floor", "ceil", "round", "pow",
            "_ready", "_process", "_physics_process", "_input", "_draw",
            "_enter_tree", "_exit_tree", "_get_configuration_warning",
            // Godot 4 global types (available without import).
            "String", "Resource", "Texture2D", "InputEvent", "Panel",
            "File", "PackedStringArray", "PackedScene", "Material", "Shader",
            "InputEventKey", "InputEventMouseButton", "InputEventMouseMotion",
            "InputEventJoypadButton", "InputEventScreenTouch", "InputEventAction",
            "InputEventJoypadMotion", "InputEventMagnifyGesture", "InputEventPanGesture",
            "OS", "ProjectSettings", "DisplayServer", "RenderingServer",
            "PhysicsServer2D", "PhysicsServer3D", "NavigationServer2D",
            "NavigationServer3D", "AudioServer", "TranslationServer",
            "ClassDB", "Engine", "Geometry2D", "Geometry3D", "Marshalls",
            "ResourceLoader", "ResourceSaver", "IP", "JSON", "ConfigFile",
            "DirAccess", "FileAccess", "Thread", "Mutex", "Semaphore",
        ]
        .iter()
        .copied()
        .collect()
    });

    let mut defined: HashSet<String> = HashSet::new();
    let mut referenced: HashSet<String> = HashSet::new();

    // var X, var X: Type, var X = ..., onready var X, export var X
    let var_re = regex::Regex::new(r"\b(?:onready\s+|export\s+|@(?:onready|export)\s+)*var\s+(\w+)").unwrap();
    for caps in var_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // const X
    let const_re = regex::Regex::new(r"\bconst\s+(\w+)").unwrap();
    for caps in const_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // func _name(params) — name + params
    let func_re = regex::Regex::new(r"\bfunc\s+(\w+)\s*\(([^)]*)\)").unwrap();
    for caps in func_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
        if let Some(params) = caps.get(2) {
            for param in params.as_str().split(',') {
                let name = param.trim().split(':').next().unwrap_or("").trim();
                if !name.is_empty() && name.chars().next().map_or(false, |c| c.is_alphabetic()) {
                    defined.insert(name.to_string());
                }
            }
        }
    }

    // class_name X (top-level) and `class X extends Y:` (inner classes).
    // Both forms define a new name that can be referenced later.
    // (e.g. `class ItemData extends Resource:` — ItemData is a user type.)
    let class_name_re = regex::Regex::new(r"\bclass_name\s+(\w+)").unwrap();
    for caps in class_name_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }
    let inner_class_re = regex::Regex::new(r"(?m)^\s*class\s+(\w+)").unwrap();
    for caps in inner_class_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // for X in
    let for_re = regex::Regex::new(r"\bfor\s+(\w+)\s+in\b").unwrap();
    for caps in for_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // signal X — declaration name + parameter names.
    // `signal item_collected(item_name: String, count: int)` defines
    // item_collected, item_name, and count so later references don't flag.
    let signal_re = regex::Regex::new(r"\bsignal\s+(\w+)\s*(?:\(([^)]*)\))?").unwrap();
    for caps in signal_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
        if let Some(params) = caps.get(2) {
            for param in params.as_str().split(',') {
                let name = param.trim().split(':').next().unwrap_or("").trim();
                if !name.is_empty() && name.chars().next().map_or(false, |c| c.is_alphabetic()) {
                    defined.insert(name.to_string());
                }
            }
        }
    }

    // enum Name { V1, V2, V3 } — name + every value is a defined constant.
    // `Rarity.COMMON` references COMMON; without this, every enum value gets
    // flagged as a hallucinated variable.
    let enum_re = regex::Regex::new(r"\benum\s+(\w+)\s*\{([^}]*)\}").unwrap();
    for caps in enum_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
        if let Some(body) = caps.get(2) {
            for value in body.as_str().split(',') {
                let name = value.trim().split('=').next().unwrap_or("").trim();
                if !name.is_empty() && name.chars().next().map_or(false, |c| c.is_alphabetic()) {
                    defined.insert(name.to_string());
                }
            }
        }
    }

    // extends ClassName — ClassName is a Godot builtin reference, not user code.
    let extends_ref_re = regex::Regex::new(r"\bextends\s+(\w+)").unwrap();
    for caps in extends_ref_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // Strip string literals so identifiers inside them aren't treated as
    // references. Critical for paths like `load("res://actors/player.gd")`
    // which would otherwise flag `res`, `actors`, `player` as undefined.
    // Covers single/double/triple-quoted strings + # comments.
    let stripped = strip_gdscript_strings_and_comments(content);

    // Type annotations: `: Type`, `-> Type`. The Type identifier is a Godot
    // builtin (String, Texture2D, ...) or user class (ItemData, Rarity) —
    // never a hallucinated variable. Run on stripped content so `# Foo:`
    // comments don't contribute false types.
    let type_annot_re = regex::Regex::new(r"(?::|->)\s*([A-Z]\w*)").unwrap();
    for caps in type_annot_re.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // Collect referenced identifiers (not after .).
    let ident_re = regex::Regex::new(r"\b([a-zA-Z_]\w{1,})\b").unwrap();
    for caps in ident_re.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) {
            let name = m.as_str();
            let before_pos = m.start();
            let bytes = stripped.as_bytes();
            // Check if preceded by '.' (member access — skip).
            let mut p = before_pos;
            while p > 0 && bytes[p - 1].is_ascii_whitespace() { p -= 1; }
            if p > 0 && bytes[p - 1] == b'.' { continue; }
            referenced.insert(name.to_string());
        }
    }

    // Filter against defined set + keywords + Godot constant prefixes.
    // KEY_* / BUTTON_* / MOUSE_BUTTON_* are Godot input constants — the list
    // is huge and version-dependent, so prefix-filter instead of enumerating.
    let mut undefined: Vec<String> = referenced
        .into_iter()
        .filter(|n| !defined.contains(n) && !GD_KEYWORDS.contains(n.as_str()))
        .filter(|n| !(n.starts_with("KEY_")
            || n.starts_with("BUTTON_")
            || n.starts_with("MOUSE_BUTTON_")
            || n.starts_with("JOY_BUTTON_")
            || n.starts_with("MIDI_")))
        .collect();

    // Consult symbol cache — accept names that exist in any library.
    // Mirrors the C# undefined-variable check (forge_csharp.rs). With a warm
    // Godot cache this catches Resource/Node/etc.; with a cold cache this is
    // a no-op and the keyword + extractor filters above do the work.
    if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
        undefined.retain(|n| cache.lookup_global(n).is_empty());
    }

    undefined.sort();
    undefined = filter_function_calls(content, undefined);
    undefined.sort();
    undefined
}

/// Heuristic: does this GDScript source look syntactically incomplete?
///
/// Used to suppress `_`-prefixed (private-by-convention) "function called but
/// not defined" warnings when the script was truncated mid-statement — the
/// missing definitions may simply have been cut off. Counts unbalanced
/// `()`, `[]`, `{}` on comment-stripped source.
fn gdscript_looks_truncated(content: &str) -> bool {
    let stripped = strip_gdscript_strings_and_comments(content);
    let mut paren: i32 = 0;
    let mut brace: i32 = 0;
    let mut bracket: i32 = 0;
    for c in stripped.chars() {
        match c {
            '(' => paren += 1,
            ')' => paren -= 1,
            '{' => brace += 1,
            '}' => brace -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            _ => {}
        }
    }
    paren > 0 || brace > 0 || bracket > 0
}

#[cfg(test)]
mod guards_tests {
    use super::*;

    async fn run_and_count(content: &str) -> usize {
        let result = run_forge_gdscript(content).await;
        result.warnings.len()
    }

    #[tokio::test]
    async fn tscn_scene_file_no_warnings() {
        // Real .tscn content extracted from task-011 agent output.
        // Was 15+ hallucinated-variable FPs: collision_layer, mouse_filter,
        // margin_left, gd_scene, ext_resource, sub_resource, etc.
        let content = "\
[gd_scene load_steps=3 format=3 uid=\"uid://abc123\"]

[ext_resource type=\"Script\" path=\"res://player.gd\" id=\"1_xlkvq\"]
[ext_resource type=\"Texture2D\" path=\"res://icon.svg\" id=\"2_yyfjw\"]

[sub_resource type=\"RectangleShape2D\" id=\"RectangleShape2D_abc\"]
size = Vector2(20, 30)

[node name=\"Player\" type=\"CharacterBody2D\"]
collision_layer = 1
collision_mask = 2

[node name=\"Sprite\" type=\"Sprite2D\" parent=\".\"]
texture = ExtResource(\"2_yyfjw\")
offset_left = -10.0
offset_right = 10.0
offset_top = -10.0
offset_bottom = 10.0

[node name=\"CollisionShape2D\" type=\"CollisionShape2D\" parent=\".\"]
shape = SubResource(\"RectangleShape2D_abc\")

[node name=\"Label\" type=\"Label\" parent=\".\"]
text = \"Hello\"
mouse_filter = 1
anchor_right = 1.0
anchors_preset = 1
theme_override_constants/font_size = 16
unique_name_in_owner = true
";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn prose_only_explanation_no_warnings() {
        // Pure-English Godot explanation.
        let content = "Now create the player scene. Add a CharacterBody2D \
                       root node with a Sprite2D child for the texture and \
                       a CollisionShape2D for physics. Wire up the input \
                       actions in the InputMap.";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn python_code_contamination_no_warnings() {
        let content = "import pygame\n\ndef main():\n    screen = pygame.display.set_mode((800, 600))\n    pass\n";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn multiple_class_name_declarations_flagged() {
        let content = "\
extends Node
class_name State

func _ready():
    pass

class_name StateMachine

class_name Player
";
        let result = run_forge_gdscript(content).await;
        assert!(
            result.warnings.iter().any(|w| w.contains("class_name") && w.contains("declarations")),
            "expected multiple class_name warning, got: {:?}", result.warnings
        );
    }

    #[tokio::test]
    async fn single_class_name_not_flagged() {
        let content = "\
extends Node
class_name State

func _ready():
    pass
";
        let result = run_forge_gdscript(content).await;
        assert!(
            !result.warnings.iter().any(|w| w.contains("class_name") && w.contains("declarations")),
            "should not flag single class_name, got: {:?}", result.warnings
        );
    }

    #[tokio::test]
    async fn csharp_code_contamination_no_warnings() {
        let content = "using System;\n\npublic class Foo {\n    public void Bar() {\n        Console.WriteLine(\"hi\");\n    }\n}\n";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn real_gdscript_undefined_var_still_flagged() {
        // GDScript with a real undefined identifier — must still be flagged.
        let content = "\
extends Node2D

func _ready():
    undefinedThing.do_stuff()
";
        let result = run_forge_gdscript(content).await;
        assert!(
            result.warnings.iter().any(|w| w.contains("undefinedThing")),
            "expected undefinedThing warning, got: {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn real_gdscript_extends_known_class_passes() {
        // extends Node2D — Node2D is a real Godot class in the bundle.
        // Should not produce any hallucinated-class warning.
        let content = "\
extends Node2D

func _ready():
    print(\"hello\")
";
        let result = run_forge_gdscript(content).await;
        assert!(
            !result.warnings.iter().any(|w| w.contains("hallucinated-class")),
            "extends Node2D must not be flagged, got: {:?}",
            result.warnings
        );
    }
}
