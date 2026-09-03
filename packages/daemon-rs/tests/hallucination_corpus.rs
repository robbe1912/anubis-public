// Hallucination detection corpus — golden set for Godot symbols.
// Expanded Phase 3 corpus with 3 Godot classes (Node2D, Vector2, Sprite2D).
//
// Tests that check_symbols correctly identifies:
//   - VALID Godot API calls → no hallucination warnings (precision)
//   - HALLUCINATED Godot API calls → hallucination warnings (recall)
//   - Cross-class hallucinations (method from class A used on class B)
//   - Tool-call-embedded code → same detection as chat content
//   - Unknown custom classes → no false positives

use anubis_daemon::symbols::cache::SymbolCache;
use anubis_daemon::symbols::godot_parser;
use anubis_daemon::symbols;

// ─── Fixtures ────────────────────────────────────────────────────────

/// Node2D fixture: 6 methods, 1 member, 1 signal.
const NODE2D_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Node2D" inherits="CanvasItem">
    <brief_description>2D game node.</brief_description>
    <methods>
        <method name="apply_scale" qualifiers="const">
            <return type="void" />
            <param index="0" name="ratio" type="Vector2" />
        </method>
        <method name="get_angle_to" qualifiers="const">
            <return type="float" />
            <param index="0" name="node" type="Node2D" />
        </method>
        <method name="rotate">
            <return type="void" />
            <param index="0" name="radians" type="float" />
        </method>
        <method name="look_at">
            <return type="void" />
            <param index="0" name="position" type="Vector2" />
        </method>
        <method name="set_position">
            <return type="void" />
            <param index="0" name="position" type="Vector2" />
        </method>
        <method name="get_position" qualifiers="const">
            <return type="Vector2" />
        </method>
    </methods>
    <members>
        <member name="global_position" type="Vector2" setter="set_global_position" getter="get_global_position">
            Global position.
        </member>
    </members>
    <signals>
        <signal name="position_changed">
            <description>Position changed.</description>
        </signal>
    </signals>
</class>"#;

/// Vector2 fixture: 7 methods for math operations.
const VECTOR2_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Vector2">
    <brief_description>2D vector.</brief_description>
    <methods>
        <method name="length" qualifiers="const">
            <return type="float" />
        </method>
        <method name="normalized" qualifiers="const">
            <return type="Vector2" />
        </method>
        <method name="angle" qualifiers="const">
            <return type="float" />
        </method>
        <method name="distance_to" qualifiers="const">
            <return type="float" />
            <param index="0" name="to" type="Vector2" />
        </method>
        <method name="direction_to" qualifiers="const">
            <return type="Vector2" />
            <param index="0" name="to" type="Vector2" />
        </method>
        <method name="dot" qualifiers="const">
            <return type="float" />
            <param index="0" name="with" type="Vector2" />
        </method>
        <method name="lerp" qualifiers="const">
            <return type="Vector2" />
            <param index="0" name="to" type="Vector2" />
            <param index="1" name="weight" type="float" />
        </method>
    </methods>
</class>"#;

/// Sprite2D fixture: 4 methods + 2 members (inherits Node2D).
const SPRITE2D_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Sprite2D" inherits="Node2D">
    <brief_description>Sprite node.</brief_description>
    <methods>
        <method name="set_texture">
            <return type="void" />
            <param index="0" name="texture" type="Texture2D" />
        </method>
        <method name="get_texture" qualifiers="const">
            <return type="Texture2D" />
        </method>
        <method name="set_flip_h">
            <return type="void" />
            <param index="0" name="flip" type="bool" />
        </method>
        <method name="is_flipped_h" qualifiers="const">
            <return type="bool" />
        </method>
    </methods>
    <members>
        <member name="texture" type="Texture2D" setter="set_texture" getter="get_texture">
            Sprite texture.
        </member>
        <member name="hframes" type="int" setter="set_hframes" getter="get_hframes">
            Horizontal frames.
        </member>
    </members>
</class>"#;

/// Set up isolated HOME with all 3 Godot classes in cache.
fn setup_isolated_cache(_test_name: &str) -> (tempfile::TempDir,) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let home = tmp.path().to_str().unwrap();
    std::env::set_var("HOME", home);
    #[cfg(target_os = "windows")]
    std::env::set_var("USERPROFILE", home);

    let cache = SymbolCache::open().expect("open cache");
    for xml in [NODE2D_XML, VECTOR2_XML, SPRITE2D_XML] {
        let parsed = godot_parser::parse_xml(xml, "test-master").expect("parse fixture");
        cache.insert_many(&parsed).expect("insert symbols");
    }
    (tmp,)
}

// ─── Test data ───────────────────────────────────────────────────────

/// 25 valid snippets using REAL methods from the 3 cached classes.
const VALID_SNIPPETS: &[&str] = &[
    // Node2D
    "Node2D.apply_scale(Vector2(2, 2))",
    "Node2D.get_angle_to(target)",
    "Node2D.rotate(1.57)",
    "Node2D.look_at(Vector2(100, 100))",
    "Node2D.set_position(Vector2(0, 0))",
    "Node2D.get_position()",
    // Vector2
    "Vector2.length()",
    "Vector2.normalized()",
    "Vector2.angle()",
    "Vector2.distance_to(Vector2(10, 10))",
    "Vector2.direction_to(target_pos)",
    "Vector2.dot(other_vec)",
    "Vector2.lerp(end_pos, 0.5)",
    // Sprite2D
    "Sprite2D.set_texture(my_tex)",
    "Sprite2D.get_texture()",
    "Sprite2D.set_flip_h(true)",
    "Sprite2D.is_flipped_h()",
    // Mixed valid usage in real code context
    "var dist = Vector2(0,0).distance_to(player.get_position())",
    "Node2D.rotate(delta * 0.01)",
    "sprite.look_at(get_global_mouse_position())",
    "var dir = start.direction_to(end).normalized()",
    "Node2D.apply_scale(Vector2(1.5, 1.5))",
    "var angle = vec.angle()",
    "Sprite2D.set_flip_h(facing_left)",
    "var len = velocity.length()",
];

/// 25 hallucinated snippets — methods that DON'T exist on the cached classes.
const HALLUCINATED_SNIPPETS: &[&str] = &[
    // Fake methods on Node2D
    "Node2D.rotate_around(target)",
    "Node2D.bounce_off(wall)",
    "Node2D.warp_to(Vector2(0, 0))",
    "Node2D.dash_toward(direction)",
    "Node2D.scale_proportional(1.5)",
    "Node2D.teleport(pos)",
    "Node2D.snap_to_grid(grid_size)",
    "Node2D.apply_physics(delta)",
    // Fake methods on Vector2
    "Vector2.flatten()",
    "Vector2.invert()",
    "Vector2.clamp_length(max)",
    "Vector2.rotate_90()",
    "Vector2.multiply(scalar)",
    "Vector2.to_degrees()",
    "Vector2.round_to_decimals(2)",
    "Vector2.squared()",
    // Fake methods on Sprite2D
    "Sprite2D.play_animation(name)",
    "Sprite2D.set_frame_index(3)",
    "Sprite2D.fade_in(duration)",
    "Sprite2D.set_opacity(0.5)",
    "Sprite2D.crop(rect)",
    "Sprite2D.set_sprite_sheet(tex)",
    "Sprite2D.flip_vertically()",
    "Sprite2D.set_pixel_size(size)",
    "Sprite2D.apply_shader(material)",
];

// ─── Tests ───────────────────────────────────────────────────────────

#[test]
fn valid_snippets_produce_no_hallucination_warnings() {
    let _cache = setup_isolated_cache("valid_snippets");
    let mut false_positives = Vec::new();

    for snippet in VALID_SNIPPETS {
        let result = symbols::check_symbols(snippet, "unknown");
        let lower = result.markdown.to_lowercase();
        if lower.contains("hallucinat") || lower.contains("does not exist") {
            false_positives.push(*snippet);
        }
    }

    // PRECISION GATE: zero false positives on valid code.
    assert!(
        false_positives.is_empty(),
        "PRECISION FAILURE: {} valid snippet(s) produced hallucination warnings (false positives):\n{}",
        false_positives.len(),
        false_positives.join("\n")
    );
}

#[test]
fn hallucinated_snippets_produce_warnings() {
    let _cache = setup_isolated_cache("hallucinated_snippets");
    let mut caught = 0;
    let mut missed = Vec::new();

    for snippet in HALLUCINATED_SNIPPETS {
        let result = symbols::check_symbols(snippet, "unknown");
        let lower = result.markdown.to_lowercase();
        if lower.contains("hallucinat") || lower.contains("does not exist") {
            caught += 1;
        } else {
            missed.push(*snippet);
        }
    }

    // RECALL GATE: catch >=20/25 (80% recall on this corpus).
    let threshold = 20;
    assert!(
        caught >= threshold,
        "RECALL FAILURE: caught {}/{} hallucinated snippets (threshold {})\nMISSED:\n{}",
        caught,
        HALLUCINATED_SNIPPETS.len(),
        threshold,
        missed.join("\n")
    );
}

#[test]
fn unknown_class_produces_no_warning() {
    let _cache = setup_isolated_cache("unknown_class");

            let result = symbols::check_symbols("MyCustomNode.do_something(Vector2(1, 1))", "gdscript");
    let lower = result.markdown.to_lowercase();
    assert!(
        !lower.contains("hallucinat") && !lower.contains("does not exist"),
        "Unknown custom class should NOT produce hallucination warning (false positive risk)\nResult: {:?}",
        result
    );
}

#[test]
fn tool_call_embedded_code_is_scanned() {
    let _cache = setup_isolated_cache("tool_call_embedded");

    let tool_call_args = r#"{"file_path":"player.gd","content":"extends Node2D\nfunc _ready():\n    Node2D.rotate_around(get_parent())\n"}"#;

    let result = symbols::check_symbols(tool_call_args, "unknown");
    let lower = result.markdown.to_lowercase();

    assert!(
        lower.contains("hallucinat") || lower.contains("does not exist"),
        "Hallucinated API in tool_call args should be detected\nResult: {:?}",
        result
    );
}

#[test]
fn mixed_valid_and_hallucinated_flags_only_bad() {
    let _cache = setup_isolated_cache("mixed");

    let mixed_code = "Node2D.apply_scale(Vector2(2,2))\nNode2D.warp_to(Vector2(0,0))";
    let result = symbols::check_symbols(mixed_code, "unknown");
    let lower = result.markdown.to_lowercase();

    assert!(
        lower.contains("warp_to") && (lower.contains("hallucinat") || lower.contains("does not exist")),
        "Should flag hallucinated method warp_to in mixed code\nResult: {:?}",
        result
    );
}

#[test]
fn cross_class_hallucination_detected() {
    // Node2D.distance_to does NOT exist — distance_to is on Vector2.
    // With path-precise lookup, scanner should flag this as hallucination.
    let _cache = setup_isolated_cache("cross_class");

            let result = symbols::check_symbols("Node2D.distance_to(target)", "gdscript");
    let lower = result.markdown.to_lowercase();

    assert!(
        lower.contains("hallucinat") || lower.contains("does not exist"),
        "Node2D.distance_to is cross-class hallucination (distance_to exists on Vector2, not Node2D)\nResult: {:?}",
        result
    );
}

#[test]
fn multiple_hallucinations_in_one_snippet() {
    let _cache = setup_isolated_cache("multi_halluc");

    let code = "Node2D.rotate_around(target)\nVector2.flatten()\nSprite2D.play_animation(\"idle\")";
    let result = symbols::check_symbols(code, "unknown");
    let lower = result.markdown.to_lowercase();

    // Should catch at least 2 of the 3 hallucinations
    let mut caught_count = 0;
    for fake in &["rotate_around", "flatten", "play_animation"] {
        if lower.contains(fake) {
            caught_count += 1;
        }
    }

    assert!(
        caught_count >= 2,
        "Should catch >=2/3 hallucinations in multi-line snippet, caught {}\nResult: {:?}",
        caught_count,
        result
    );
}

#[test]
fn real_code_block_with_mixed_calls() {
    // Simulate a realistic GDScript function with valid + hallucinated calls.
    let _cache = setup_isolated_cache("real_code_block");

    let code = r#"
extends Node2D

func _process(delta):
    var enemy = get_node("Enemy")
    var dist = Vector2.ZERO.distance_to(enemy.get_position())
    
    if dist < 100:
        Node2D.look_at(enemy.get_position())
        Node2D.warp_to(enemy.get_position())  # HALLUCINATED
        Vector2.normalized()                   # valid
        Node2D.snap_to_grid(32)                # HALLUCINATED
"#;

    let result = symbols::check_symbols(code, "unknown");
    let lower = result.markdown.to_lowercase();

    // Should flag at least one hallucination
    assert!(
        lower.contains("hallucinat") || lower.contains("does not exist"),
        "Should detect hallucinations in realistic code block\nResult: {:?}",
        result
    );
}
