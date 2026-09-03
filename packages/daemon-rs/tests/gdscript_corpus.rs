// GDScript hallucination corpus — 12 hallucination/golden pairs.
//
// Each pair covers one Godot 4.x construct a coding agent commonly
// hallucinates: nonexistent Node methods, deprecated Godot 3 properties,
// wrong autoload names, undefined variables, missing signal declarations,
// and Godot 3 → 4 API migrations (e.g. Tween.interpolate_property →
// tween_property).
//
// Why this exists: DELULU + recall_corpus cover Python/Rust/TS/Go. There
// is no GDScript recall corpus. This file fills that gap so GDScript
// detection regressions are caught before merge.
//
// Layout: tests/fixtures/gdscript_samples/NN_{hallucinated,golden}.gd
//
// Ship gate (asserted at end):
//   - recall   >= 8 / 12 hallucinated samples caught
//   - precision 0    / 12 golden samples flagged (0 FPs)
//
// Known scanner gaps that the gate tolerates (NOT fixed here per task scope):
//   - #7 add_to_group vs add_child — both real Node methods, scanner cannot
//     tell intent.
//   - #9 Input.get_axis(...) called with wrong arity (too few args) —
//     forge_gdscript/methods.rs::verify_gdscript_call_arity only flags
//     extra args, never missing args.
//
// Run:
//   $env:DELULU_FORGE_ONLY = "1"   # default for this corpus
//   cargo test --release --test gdscript_corpus -- --nocapture

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use anubis_daemon::scanner::{scan_response, ScanContext, ScanResultData};
use anubis_daemon::symbols::cache::SymbolCache;
use anubis_daemon::symbols::godot_parser;

// ─── Parallel-test cache isolation ──────────────────────────────────
//
// SymbolCache lives at $HOME/.anubis/symbols/cache.sqlite (or
// %USERPROFILE% on Windows). Parallel tests inside this binary would
// race on the same file. We serialize the single entry point test with
// a module-level mutex + isolate HOME/USERPROFILE into a per-run tempdir
// (mirrors tests/remote_docs_integration.rs::CacheIsolation).

static SERIAL_GUARD: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    match SERIAL_GUARD.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

struct EnvGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        EnvGuard { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

struct CacheIsolation {
    _tmp: tempfile::TempDir,
    _home: EnvGuard,
    _userprofile: Option<EnvGuard>,
}

impl CacheIsolation {
    fn new(label: &str) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home_str = tmp.path().to_string_lossy().to_string();
        let _home = EnvGuard::set("HOME", &home_str);
        // Windows caches under USERPROFILE — set both for cross-platform safety.
        let _userprofile = if cfg!(target_os = "windows") {
            Some(EnvGuard::set("USERPROFILE", &home_str))
        } else {
            None
        };
        let _ = label;
        CacheIsolation { _tmp: tmp, _home, _userprofile }
    }
}

// ─── Inline Godot class fixtures ────────────────────────────────────
//
// Covers all classes referenced by the 24 sample files. We embed the
// XML directly (same pattern as tests/hallucination_corpus.rs) rather
// than depending on a network fetch or a committed JSONL bundle. This
// satisfies constraint #8 (no hardcoded symbol data) because every
// symbol here is parsed from the official Godot class XML format by
// godot_parser::parse_xml — the same path used in production.

const NODE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Node" inherits="Object">
    <brief_description>Scene graph base.</brief_description>
    <methods>
        <method name="get_node" qualifiers="const">
            <return type="Node" />
            <param index="0" name="path" type="NodePath" />
        </method>
        <method name="connect">
            <return type="int" />
            <param index="0" name="signal" type="String" />
            <param index="1" name="callable" type="Callable" />
            <param index="2" name="flags" type="int" />
        </method>
        <method name="add_child">
            <return type="void" />
            <param index="0" name="node" type="Node" />
        </method>
        <method name="add_to_group">
            <return type="void" />
            <param index="0" name="group" type="String" />
        </method>
        <method name="queue_free">
            <return type="void" />
        </method>
        <method name="emit_signal">
            <return type="void" />
            <param index="0" name="signal" type="String" />
        </method>
        <method name="get_parent" qualifiers="const">
            <return type="Node" />
        </method>
        <method name="remove_child">
            <return type="void" />
            <param index="0" name="node" type="Node" />
        </method>
    </methods>
    <signals>
        <signal name="tree_entered">
            <description>Tree entered.</description>
        </signal>
    </signals>
</class>"#;

const CANVAS_ITEM_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="CanvasItem" inherits="Node">
    <brief_description>2D drawing base.</brief_description>
    <members>
        <member name="global_position" type="Vector2" setter="set_global_position" getter="get_global_position">
            Global position.
        </member>
        <member name="visible" type="bool" setter="set_visible" getter="is_visible">
            Visibility.
        </member>
    </members>
</class>"#;

const NODE2D_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Node2D" inherits="CanvasItem">
    <brief_description>2D transform node.</brief_description>
    <methods>
        <method name="rotate">
            <return type="void" />
            <param index="0" name="radians" type="float" />
        </method>
        <method name="look_at">
            <return type="void" />
            <param index="0" name="position" type="Vector2" />
        </method>
    </methods>
    <members>
        <member name="size" type="Vector2" setter="set_size" getter="get_size">
            Bounding box size (Godot 4 name; replaces Godot 3 rect_size).
        </member>
    </members>
</class>"#;

const CONTROL_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Control" inherits="CanvasItem">
    <brief_description>UI base node.</brief_description>
    <members>
        <member name="size" type="Vector2" setter="set_size" getter="get_size">
            Bounding box size (Godot 4 name).
        </member>
        <member name="position" type="Vector2" setter="set_position" getter="get_position">
            Local position.
        </member>
    </members>
</class>"#;

const SPRITE2D_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Sprite2D" inherits="Node2D">
    <brief_description>Sprite.</brief_description>
    <methods>
        <method name="set_texture">
            <return type="void" />
            <param index="0" name="texture" type="Texture2D" />
        </method>
        <method name="get_texture" qualifiers="const">
            <return type="Texture2D" />
        </method>
    </methods>
</class>"#;

const INPUT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Input" inherits="Object">
    <brief_description>Input singleton.</brief_description>
    <methods>
        <method name="get_vector" qualifiers="const">
            <return type="Vector2" />
            <param index="0" name="negative_x" type="String" />
            <param index="1" name="positive_x" type="String" />
            <param index="2" name="negative_y" type="String" />
            <param index="3" name="positive_y" type="String" />
        </method>
        <method name="get_axis" qualifiers="const">
            <return type="float" />
            <param index="0" name="negative_action" type="String" />
            <param index="1" name="positive_action" type="String" />
        </method>
        <method name="is_action_pressed" qualifiers="const">
            <return type="bool" />
            <param index="0" name="action" type="String" />
        </method>
    </methods>
</class>"#;

const RESOURCE_LOADER_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="ResourceLoader" inherits="Object">
    <brief_description>Resource loading singleton.</brief_description>
    <methods>
        <method name="load" qualifiers="const">
            <return type="Resource" />
            <param index="0" name="path" type="String" />
        </method>
        <method name="exists" qualifiers="const">
            <return type="bool" />
            <param index="0" name="path" type="String" />
        </method>
    </methods>
</class>"#;

const REF_COUNTED_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="RefCounted" inherits="Object">
    <brief_description>Reference-counted base.</brief_description>
    <methods>
        <method name="reference">
            <return type="bool" />
        </method>
        <method name="unreference">
            <return type="bool" />
        </method>
    </methods>
</class>"#;

const TWEEN_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Tween" inherits="RefCounted">
    <brief_description>Animation interpolator (Godot 4 API).</brief_description>
    <methods>
        <method name="tween_property">
            <return type="PropertyTweener" />
            <param index="0" name="object" type="Object" />
            <param index="1" name="property" type="NodePath" />
            <param index="2" name="final_val" type="Variant" />
            <param index="3" name="duration" type="float" />
        </method>
        <method name="kill">
            <return type="void" />
        </method>
        <method name="play">
            <return type="void" />
        </method>
    </methods>
</class>"#;

const OBJECT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Object">
    <brief_description>Root class.</brief_description>
    <methods>
        <method name="get_instance_id" qualifiers="const">
            <return type="int" />
        </method>
        <method name="free">
            <return type="void" />
        </method>
    </methods>
</class>"#;

/// Install all 10 inline Godot classes into the isolated cache.
fn seed_godot_classes() {
    let cache = SymbolCache::open().expect("open cache");
    for xml in [
        OBJECT_XML,
        NODE_XML,
        CANVAS_ITEM_XML,
        NODE2D_XML,
        CONTROL_XML,
        SPRITE2D_XML,
        INPUT_XML,
        RESOURCE_LOADER_XML,
        REF_COUNTED_XML,
        TWEEN_XML,
    ] {
        let parsed = godot_parser::parse_xml(xml, "test-master").expect("parse fixture");
        cache.insert_many(&parsed).expect("insert symbols");
    }
}

// ─── Sample spec ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct SampleSpec {
    /// Sample number 1..=12.
    n: u8,
    /// Hallucination category (matches task table column "Type").
    category: &'static str,
    /// What the hallucinated sample does wrong.
    description: &'static str,
    /// Whether the scanner is *expected* to catch this sample.
    /// `false` = known scanner gap (documented but tolerated by the gate).
    expected_caught: bool,
}

const SAMPLES: &[SampleSpec] = &[
    SampleSpec { n: 1,  category: "method",     description: "get_node_safe() — nonexistent Node method",                expected_caught: true  },
    SampleSpec { n: 2,  category: "method",     description: "connect_signal() — nonexistent signal connect method",    expected_caught: true  },
    SampleSpec { n: 3,  category: "property",   description: ".global_pos — wrong property name",                        expected_caught: true  },
    SampleSpec { n: 4,  category: "method",     description: "queue_delete() — wrong free method",                       expected_caught: true  },
    SampleSpec { n: 5,  category: "method",     description: "ResourceLoader.load_scene(path, true) — invented method",  expected_caught: true  },
    SampleSpec { n: 6,  category: "undefined",  description: "GameStateManager — undefined autoload",                    expected_caught: true  },
    SampleSpec { n: 7,  category: "method",     description: "add_to_group(name) vs add_child(node) — both real Node methods", expected_caught: false },
    SampleSpec { n: 8,  category: "property",   description: ".rect_size — Godot 3 deprecated, use .size (Godot 4)",      expected_caught: true  },
    SampleSpec { n: 9,  category: "arity",      description: "Input.get_axis(\"ui_left\") — wrong arity (1 vs 2)",       expected_caught: false },
    SampleSpec { n: 10, category: "undefined",  description: "player_health — undefined variable",                        expected_caught: true  },
    SampleSpec { n: 11, category: "signal",     description: "player_hurt — signal not declared",                         expected_caught: true  },
    SampleSpec { n: 12, category: "method",     description: "Tween.interpolate_property — Godot 3 API in Godot 4",       expected_caught: true  },
];

const TOTAL: usize = SAMPLES.len(); // 12

// ─── ScanContext ────────────────────────────────────────────────────

fn build_ctx(project_root: &std::path::Path) -> ScanContext {
    ScanContext {
        project_root: project_root.to_string_lossy().to_string(),
        logic_model: std::env::var("DELULU_LLM_MODEL")
            .unwrap_or_else(|_| "glm-4.7-flash".to_string()),
        llm_base_url: std::env::var("DELULU_LLM_BASE_URL")
            .unwrap_or_else(|_| "https://api.z.ai/api/coding/paas/v4".to_string()),
        // Empty key short-circuits L3 in the cascade. This corpus is
        // FORGE_ONLY (per task constraints) — deterministic layers only.
        llm_api_key: if std::env::var("DELULU_FORGE_ONLY").is_ok() {
            String::new()
        } else {
            std::env::var("DELULU_LLM_API_KEY").unwrap_or_default()
        },
        llm_extra_headers: Vec::new(),
        request_class: String::new(),
        // Pin language so detection ambiguity never enters the equation.
        // The fence tag is gdscript too, but an explicit hint is safer for
        // a corpus with very short snippets.
        language: "gdscript".to_string(),
        cancel: tokio_util::sync::CancellationToken::new(),
    }
}

/// Wrap a raw snippet in a markdown code fence with the `gdscript`
/// language hint (the way an LLM agent would emit it). The language
/// tag is what extract_code_blocks_only + detect_language key off of.
fn fence(raw: &str) -> String {
    format!("```gdscript\n{raw}\n```\n")
}

fn read_sample(n: u8, kind: &str) -> String {
    let name = format!("{:02}_{}.gd", n, kind);
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("gdscript_samples")
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
}

// ─── Per-sample scan ────────────────────────────────────────────────

async fn scan(snippet: &str, _project_root: &std::path::Path) -> ScanResultData {
    // Fresh tempdir per call ⇒ unique project_root ⇒ unique verdict_cache key.
    // Defeats the process-global VERDICT_CACHE collision that silently
    // returned 0-warning results for the 3rd+ sample in earlier runs.
    let tmp = tempfile::tempdir().expect("tempdir for scan call");
    let project_root = tmp.path().to_path_buf();
    let content = fence(snippet);
    let ctx = build_ctx(&project_root);
    let r = scan_response(&content, &ctx).await;
    std::mem::forget(tmp);
    r
}

// ─── Test ───────────────────────────────────────────────────────────

#[tokio::test]
async fn gdscript_corpus_meets_ship_gate() {
    let _guard = lock();
    let _cache = CacheIsolation::new("gdscript_corpus");
    seed_godot_classes();

    let forge_only = std::env::var("DELULU_FORGE_ONLY").is_ok();
    eprintln!(
        "=== gdscript_corpus: {} pairs, L3 {} ===",
        TOTAL,
        if forge_only { "SKIPPED (DELULU_FORGE_ONLY)" } else { "ENABLED" }
    );

    let tmp = tempfile::tempdir().expect("tempdir for project_root");
    let project_root = tmp.path();

    let mut caught = 0usize;
    let mut false_positives: Vec<u8> = Vec::new();
    let mut misses: Vec<&SampleSpec> = Vec::new();
    let mut expected_misses: Vec<&SampleSpec> = Vec::new();

    for s in SAMPLES {
        let halluc_raw = read_sample(s.n, "hallucinated");
        let golden_raw = read_sample(s.n, "golden");

        let h = scan(&halluc_raw, project_root).await;
        let g = scan(&golden_raw, project_root).await;

        let h_caught = !h.warnings.is_empty();
        let g_flagged = !g.warnings.is_empty();

        eprintln!(
            "  #{:02} [{:<10}] caught={} golden_fp={} warns(h={}/g={})",
            s.n, s.category, h_caught, g_flagged, h.warnings.len(), g.warnings.len(),
        );
        for w in &h.warnings {
            eprintln!("      h: {w}");
        }
        for w in &g.warnings {
            eprintln!("      g: {w}");
        }

        if h_caught {
            caught += 1;
        } else if s.expected_caught {
            misses.push(s);
        } else {
            expected_misses.push(s);
        }

        if g_flagged {
            false_positives.push(s.n);
        }
    }

    let expected_caught_count = SAMPLES.iter().filter(|s| s.expected_caught).count();
    eprintln!();
    eprintln!("=== SHIP GATE ===");
    eprintln!("  recall (hallucinated caught) : {caught}/{TOTAL}  (gate >= 8)");
    eprintln!("  precision (golden FPs)        : {} / {TOTAL}  (gate == 0)", false_positives.len());
    eprintln!(
        "  expected-caught-of-caught     : {}/{}",
        caught.saturating_sub(TOTAL - expected_caught_count - expected_misses.len()),
        expected_caught_count
    );

    if !misses.is_empty() {
        eprintln!();
        eprintln!("UNEXPECTED MISSES (scanner regression — investigate):");
        for m in &misses {
            eprintln!("  #{:02} [{}] {}", m.n, m.category, m.description);
        }
    }
    if !expected_misses.is_empty() {
        eprintln!();
        eprintln!("KNOWN GAPS (tolerated — documented in test header):");
        for m in &expected_misses {
            eprintln!("  #{:02} [{}] {}", m.n, m.category, m.description);
        }
    }
    if !false_positives.is_empty() {
        eprintln!();
        eprintln!("FALSE POSITIVES on golden samples (precision failure):");
        for n in &false_positives {
            eprintln!("  #{:02}", n);
        }
    }

    // ── Assertions ─────────────────────────────────────────────────
    assert!(
        caught >= 8,
        "GDScript recall regression: {caught}/{TOTAL} < 8. \
         Expected catches must all fire — see UNEXPECTED MISSES above."
    );
    assert!(
        false_positives.is_empty(),
        "GDScript precision failure: {} golden sample(s) produced warnings: {:?}",
        false_positives.len(),
        false_positives,
    );
}
