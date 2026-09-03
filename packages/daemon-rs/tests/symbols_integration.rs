//! Integration test: full Godot symbol pipeline.
//!
//! XML → parser → cache → lookup
//!
//! Minimal smoke test that does NOT hit the network.

use std::sync::Mutex;

use anubis_daemon::symbols::cache::SymbolCache;
use anubis_daemon::symbols::godot_parser;

static SERIAL: Mutex<()> = Mutex::new(());

const FIXTURE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<class name="Node2D" inherits="CanvasItem" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <brief_description>2D game node.</brief_description>
    <description>A 2D game node.</description>
    <methods>
        <method name="apply_scale" qualifiers="const">
            <return type="void" />
            <param index="0" name="ratio" type="Vector2" />
        </method>
    </methods>
</class>"#;

#[test]
fn godot_pipeline_xml_parse_cache_lookup() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    let symbols = godot_parser::parse_xml(FIXTURE_XML, "test-master")
        .expect("XML must parse");
    assert!(!symbols.is_empty(), "parser should emit at least the class");

    let cache = SymbolCache::open_in_memory().expect("in-memory cache opens");
    cache.insert_many(&symbols).expect("insert succeeds");

    let class = cache.lookup("godot", "Node2D").expect("class lookup");
    assert_eq!(class.kind, anubis_daemon::symbols::types::SymbolKind::Class);

    let missing = cache.lookup("godot", "Node2D.totally_fake_method");
    assert!(missing.is_none(), "fake method should not be in cache");
}

#[test]
fn godot_pipeline_empty_xml_returns_empty() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Empty XML should not crash; may return empty symbol list or error — both acceptable
    let _ = godot_parser::parse_xml("", "broken");
}

#[test]
fn godot_pipeline_malformed_xml_does_not_panic() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Must not panic; error or empty result both acceptable
    let _ = godot_parser::parse_xml("<not really xml", "broken");
}
