//! Godot class reference XML parser.
//!
//! Translates Godot's `doc/classes/*.xml` format into `Vec<Symbol>`.
//! See: <https://docs.godotengine.org/en/stable/tutorials/scripting/class_reference.html>
//!
//! Uses `quick_xml::Reader` (streaming pull-parser) rather than the deserialize
//! layer, because Godot's XML uses attributes heavily and member docs are mixed
//! content that does not map cleanly to serde structs.

use std::sync::OnceLock;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use regex::Regex;

use crate::symbols::types::{Param, Symbol, SymbolKind};

/// Library tag stamped on every emitted symbol.
const LIBRARY: &str = "godot";

/// Parse Godot class reference XML.
///
/// Returns symbols for the class itself + all its methods, members, signals,
/// constants, enums, enum members.
///
/// # Arguments
/// * `xml` - Raw XML string (single class file)
/// * `version` - Godot version this XML belongs to (e.g. "4.3", "4.4", "master")
///
/// # Errors
/// Returns `Err(message)` on malformed XML or parser failure.
pub fn parse_xml(xml: &str, version: &str) -> Result<Vec<Symbol>, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut symbols: Vec<Symbol> = Vec::new();
    let mut stack: Vec<String> = Vec::new();

    let mut class_name: Option<String> = None;
    let mut class_inherits: Option<String> = None;
    let mut class_description = String::new();

    let mut current_method: Option<ElementBuild> = None;
    let mut current_member: Option<ElementBuild> = None;
    let mut current_signal: Option<ElementBuild> = None;
    let mut current_constant: Option<ElementBuild> = None;
    let mut current_enum_name: Option<String> = None;

    let mut text_buf = String::new();
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| format!("xml parse error: {e}"))?;
        match event {
            Event::Start(e) => {
                let name = el_name(e.name().as_ref());
                stack.push(name.clone());
                match name.as_str() {
                    "class" => {
                        class_name = Some(attr(&e, "name").ok_or("missing class@name")?);
                        class_inherits = attr(&e, "inherits");
                    }
                    "method" => {
                        current_method = Some(ElementBuild::new(
                            attr(&e, "name").ok_or("missing method@name")?,
                            attr(&e, "qualifiers"),
                        ));
                    }
                    "member" => {
                        let n = attr(&e, "name").ok_or("missing member@name")?;
                        let t = attr(&e, "type").ok_or("missing member@type")?;
                        let default = attr(&e, "default");
                        let mut b = ElementBuild::new(n, None);
                        b.type_name = Some(t);
                        b.default = default.filter(|d| !d.is_empty());
                        current_member = Some(b);
                    }
                    "signal" => {
                        current_signal = Some(ElementBuild::new(
                            attr(&e, "name").ok_or("missing signal@name")?,
                            None,
                        ));
                    }
                    "constant" => {
                        let n = attr(&e, "name").ok_or("missing constant@name")?;
                        let v = attr(&e, "value").unwrap_or_default();
                        let mut b = ElementBuild::new(n, None);
                        b.value = Some(v);
                        current_constant = Some(b);
                    }
                    "enum" => {
                        let n = attr(&e, "name").ok_or("missing enum@name")?;
                        current_enum_name = Some(n.clone());
                        if let Some(class) = &class_name {
                            let path = format!("{class}.{n}");
                            let mut sym = Symbol::new(LIBRARY, version, &path);
                            sym.kind = SymbolKind::Enum;
                            symbols.push(sym);
                        }
                    }
                    "description" => text_buf.clear(),
                    _ => {}
                }
            }
            Event::End(e) => {
                let name = el_name(e.name().as_ref());
                stack.pop();
                match name.as_str() {
                    "class" => {
                        let cn = class_name
                            .take()
                            .ok_or("internal error: class ended without start")?;
                        let mut sym = Symbol::new(LIBRARY, version, &cn);
                        sym.kind = SymbolKind::Class;
                        sym.return_type = class_inherits.take().filter(|p| !p.is_empty());
                        sym.signature = Some(match &sym.return_type {
                            Some(p) => format!("class {cn} : {p}"),
                            None => format!("class {cn}"),
                        });
                        let desc = clean_text(&class_description);
                        if !desc.is_empty() {
                            sym.doc_text = Some(desc);
                        }
                        symbols.push(sym);
                    }
                    "method" => {
                        if let Some(b) = current_method.take() {
                            if let Some(cn) = &class_name {
                                symbols.push(build_method_symbol(version, cn, b));
                            }
                        }
                    }
                    "member" => {
                        if let Some(b) = current_member.take() {
                            if let Some(cn) = &class_name {
                                symbols.push(build_member_symbol(version, cn, b));
                            }
                        }
                    }
                    "signal" => {
                        if let Some(b) = current_signal.take() {
                            if let Some(cn) = &class_name {
                                symbols.push(build_signal_symbol(version, cn, b));
                            }
                        }
                    }
                    "constant" => {
                        if let Some(b) = current_constant.take() {
                            if let Some(cn) = &class_name {
                                symbols.push(build_constant_symbol(
                                    version,
                                    cn,
                                    current_enum_name.as_deref(),
                                    b,
                                ));
                            }
                        }
                    }
                    "enum" => current_enum_name = None,
                    "description" => {
                        let text = std::mem::take(&mut text_buf);
                        match stack.last().map(String::as_str) {
                            Some("method") => {
                                if let Some(m) = current_method.as_mut() {
                                    m.description.push_str(&text);
                                }
                            }
                            Some("signal") => {
                                if let Some(s) = current_signal.as_mut() {
                                    s.description.push_str(&text);
                                }
                            }
                            Some("class") => class_description.push_str(&text),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            Event::Empty(e) => {
                let name = el_name(e.name().as_ref());
                match name.as_str() {
                    "return" => {
                        if let Some(m) = current_method.as_mut() {
                            m.type_name = Some(attr(&e, "type").unwrap_or_else(|| "void".into()));
                        }
                    }
                    "param" => {
                        if let Some(m) = current_method.as_mut() {
                            m.params.push(Param {
                                name: attr(&e, "name").unwrap_or_default(),
                                type_name: attr(&e, "type").unwrap_or_else(|| "Variant".into()),
                                default_value: attr(&e, "default").filter(|d| !d.is_empty()),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(t) => {
                let text = t.unescape().map_err(|e| format!("xml unescape error: {e}"))?;
                route_text(
                    &text,
                    &stack,
                    &mut text_buf,
                    current_member.as_mut(),
                    current_constant.as_mut(),
                );
            }
            Event::CData(c) => {
                let text = String::from_utf8_lossy(c.as_ref());
                route_text(
                    &text,
                    &stack,
                    &mut text_buf,
                    current_member.as_mut(),
                    current_constant.as_mut(),
                );
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if class_name.is_some() {
        return Err("unexpected EOF: <class> not closed".into());
    }
    Ok(symbols)
}

/// Accumulator for one method/member/signal/constant while its children stream in.
struct ElementBuild {
    name: String,
    qualifiers: Option<String>,
    type_name: Option<String>,
    value: Option<String>,
    default: Option<String>,
    params: Vec<Param>,
    description: String,
    text: String,
}

impl ElementBuild {
    fn new(name: String, qualifiers: Option<String>) -> Self {
        Self {
            name,
            qualifiers,
            type_name: None,
            value: None,
            default: None,
            params: Vec::new(),
            description: String::new(),
            text: String::new(),
        }
    }
}

fn route_text(
    text: &str,
    stack: &[String],
    text_buf: &mut String,
    current_member: Option<&mut ElementBuild>,
    current_constant: Option<&mut ElementBuild>,
) {
    let Some(top) = stack.last().map(String::as_str) else {
        return;
    };
    match top {
        "description" => text_buf.push_str(text),
        "member" => {
            if let Some(m) = current_member {
                m.text.push_str(text);
            }
        }
        "constant" => {
            if let Some(c) = current_constant {
                c.text.push_str(text);
            }
        }
        _ => {}
    }
}

fn build_method_symbol(version: &str, class_name: &str, m: ElementBuild) -> Symbol {
    let path = format!("{class_name}.{}", m.name);
    let mut sym = Symbol::new(LIBRARY, version, &path);
    sym.kind = pick_method_kind(&m);
    sym.return_type = m.type_name.clone();
    let desc = clean_text(&m.description);
    if !desc.is_empty() {
        sym.doc_text = Some(desc);
    }
    // Build signature before moving `params` out of `m`.
    sym.signature = Some(method_signature(&m));
    sym.params = m.params;
    sym
}

fn build_member_symbol(version: &str, class_name: &str, m: ElementBuild) -> Symbol {
    let path = format!("{class_name}.{}", m.name);
    let mut sym = Symbol::new(LIBRARY, version, &path);
    sym.kind = SymbolKind::Property;
    sym.return_type = m.type_name.clone();
    let text = clean_text(&m.text);
    if !text.is_empty() {
        sym.doc_text = Some(text);
    }
    let type_name = m.type_name.as_deref().unwrap_or("Variant");
    sym.signature = Some(match &m.default {
        Some(d) => format!("{}: {type_name} = {d}", m.name),
        None => format!("{}: {type_name}", m.name),
    });
    sym
}

fn build_signal_symbol(version: &str, class_name: &str, s: ElementBuild) -> Symbol {
    let path = format!("{class_name}.{}", s.name);
    let mut sym = Symbol::new(LIBRARY, version, &path);
    sym.kind = SymbolKind::Signal;
    let desc = clean_text(&s.description);
    if !desc.is_empty() {
        sym.doc_text = Some(desc);
    }
    sym
}

fn build_constant_symbol(
    version: &str,
    class_name: &str,
    current_enum: Option<&str>,
    c: ElementBuild,
) -> Symbol {
    let value = c.value.clone().unwrap_or_default();
    let (path, kind) = match current_enum {
        Some(enum_name) => (
            format!("{class_name}.{enum_name}.{}", c.name),
            SymbolKind::EnumMember,
        ),
        None => (format!("{class_name}.{}", c.name), SymbolKind::Constant),
    };
    let mut sym = Symbol::new(LIBRARY, version, &path);
    sym.kind = kind;
    sym.signature = Some(format!("{} = {}", c.name, value));
    let text = clean_text(&c.text);
    if !text.is_empty() {
        sym.doc_text = Some(text);
    }
    sym
}

/// Per spec: virtual `_init`/`init` is a constructor; everything else is a method.
fn pick_method_kind(m: &ElementBuild) -> SymbolKind {
    let is_virtual = m
        .qualifiers
        .as_deref()
        .is_some_and(|q| q.split_whitespace().any(|t| t == "virtual"));
    let is_init = m.name == "init" || m.name == "_init";
    if is_virtual && is_init {
        SymbolKind::Constructor
    } else {
        SymbolKind::Method
    }
}

fn method_signature(m: &ElementBuild) -> String {
    let params = m
        .params
        .iter()
        .map(|p| match &p.default_value {
            Some(d) => format!("{}: {} = {}", p.name, p.type_name, d),
            None => format!("{}: {}", p.name, p.type_name),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let ret = m.type_name.as_deref().unwrap_or("void");
    format!("{}({params}) -> {ret}", m.name)
}

/// Trim + collapse whitespace + strip Godot BBCode tags.
fn clean_text(s: &str) -> String {
    strip_bbcode(s)
        .trim()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Convert Godot's BBCode-ish doc tags to plain text.
/// `[param ratio]` -> `ratio`, `[Node2D]` -> `Node2D`, `[code]x[/code]` -> `x`.
fn strip_bbcode(input: &str) -> String {
    static RE_PARAM: OnceLock<Regex> = OnceLock::new();
    static RE_URL: OnceLock<Regex> = OnceLock::new();
    static RE_LOWER_TAG: OnceLock<Regex> = OnceLock::new();
    static RE_CLASS_TAG: OnceLock<Regex> = OnceLock::new();
    let re_param = RE_PARAM.get_or_init(|| {
        Regex::new(
            r"\[(?:param|method|member|constant|signal|enum|theme_item|constructor|annotation|bred)\s+([^\]]+)\]",
        )
        .expect("static regex")
    });
    let re_url = RE_URL.get_or_init(|| Regex::new(r"\[/?url[^\]]*\]").expect("static regex"));
    let re_lower = RE_LOWER_TAG
        .get_or_init(|| Regex::new(r"\[/?[a-z_][a-z_0-9]*\]").expect("static regex"));
    let re_class = RE_CLASS_TAG
        .get_or_init(|| Regex::new(r"\[/?([A-Z][A-Za-z_0-9.]*)\]").expect("static regex"));
    let s = re_param.replace_all(input, "$1");
    let s = re_url.replace_all(&s, "");
    let s = re_lower.replace_all(&s, "");
    let s = re_class.replace_all(&s, "$1");
    s.into_owned()
}

fn el_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn attr(e: &BytesStart<'_>, name: &str) -> Option<String> {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == name.as_bytes() {
            return a
                .unescape_value()
                .ok()
                .map(|cow| cow.into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::types::Visibility;

    fn find<'a>(symbols: &'a [Symbol], path: &str) -> Option<&'a Symbol> {
        symbols.iter().find(|s| s.path == path)
    }

    #[test]
    fn minimal_class_emits_one_class_symbol() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<class name="Object" inherits="RefCounted">
    <brief_description></brief_description>
    <description>Just an Object.</description>
    <tutorials></tutorials>
</class>"#;
        let symbols = parse_xml(xml, "4.3").expect("parse ok");
        assert_eq!(symbols.len(), 1);
        let c = &symbols[0];
        assert_eq!(c.path, "Object");
        assert_eq!(c.kind, SymbolKind::Class);
        assert_eq!(c.return_type.as_deref(), Some("RefCounted"));
        assert_eq!(c.signature.as_deref(), Some("class Object : RefCounted"));
        assert_eq!(c.doc_text.as_deref(), Some("Just an Object."));
        assert_eq!(c.library, "godot");
        assert_eq!(c.version, "4.3");
        assert_eq!(c.visibility, Visibility::Public);
        assert!(!c.is_deprecated);
    }

    #[test]
    fn class_with_one_method_emits_class_and_method() {
        let xml = r#"<class name="Foo" inherits="Bar">
    <description>Foo desc.</description>
    <methods>
        <method name="do_thing" qualifiers="const">
            <return type="void" />
            <param index="0" name="x" type="int" />
            <description>Does the thing with [param x].</description>
        </method>
    </methods>
</class>"#;
        let symbols = parse_xml(xml, "4.3").expect("parse ok");
        assert_eq!(symbols.len(), 2);
        let m = find(&symbols, "Foo.do_thing").expect("method emitted");
        assert_eq!(m.kind, SymbolKind::Method);
        assert_eq!(m.params.len(), 1);
        assert_eq!(m.params[0].name, "x");
        assert_eq!(m.params[0].type_name, "int");
        assert_eq!(m.return_type.as_deref(), Some("void"));
        assert_eq!(m.signature.as_deref(), Some("do_thing(x: int) -> void"));
        assert_eq!(m.doc_text.as_deref(), Some("Does the thing with x."));
    }

    #[test]
    fn node2d_kitchen_sink_produces_eleven_symbols() {
        let xml = r#"<class name="Node2D" inherits="CanvasItem">
    <brief_description>A 2D game object.</brief_description>
    <description>A 2D game object, with a transform.</description>
    <tutorials>
        <link title="Math">$2027</link>
    </tutorials>
    <methods>
        <method name="apply_scale" qualifiers="const">
            <return type="void" />
            <param index="0" name="ratio" type="Vector2" />
            <description>Multiplies the current scale by the [param ratio] vector.</description>
        </method>
        <method name="get_angle_to" qualifiers="const">
            <return type="float" />
            <param index="0" name="to" type="Node2D" />
            <description>Returns the angle from this Node2D to [param to], in radians.</description>
        </method>
        <method name="rotate" qualifiers="const">
            <return type="void" />
            <param index="0" name="radians" type="float" />
            <description>Applies a rotation to the node, in radians.</description>
        </method>
    </methods>
    <members>
        <member name="global_position" type="Vector2" setter="" getter="get_global_position">Global position of this Node2D.</member>
        <member name="global_rotation" type="float" setter="" getter="get_global_rotation" default="0.0">Global rotation of this Node2D in radians.</member>
    </members>
    <signals>
        <signal name="position_changed">
            <description>Emitted when the global position changes.</description>
        </signal>
    </signals>
    <constants>
        <constant name="SIGNAL_POSITION_CHANGED" value="position_changed">Name of the position_changed signal.</constant>
    </constants>
    <enums>
        <enum name="TextureFilter">
            <constant name="TEXTURE_FILTER_PARENT_NODE" value="0" enum="TextureFilter">Inherits filter mode from parent.</constant>
            <constant name="TEXTURE_FILTER_NEAREST" value="1" enum="TextureFilter">Nearest-neighbor filter.</constant>
        </enum>
    </enums>
</class>"#;
        let symbols = parse_xml(xml, "4.4").expect("parse ok");
        assert_eq!(symbols.len(), 11);

        // Every required kind must show up at least once.
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::Class));
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::Method));
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::Property));
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::Signal));
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::Constant));
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::Enum));
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::EnumMember));

        // Class signature + doc.
        let cls = find(&symbols, "Node2D").unwrap();
        assert_eq!(cls.signature.as_deref(), Some("class Node2D : CanvasItem"));
        assert_eq!(cls.doc_text.as_deref(), Some("A 2D game object, with a transform."));

        // Member with default.
        let mr = find(&symbols, "Node2D.global_rotation").unwrap();
        assert_eq!(mr.kind, SymbolKind::Property);
        assert_eq!(mr.return_type.as_deref(), Some("float"));
        assert_eq!(
            mr.signature.as_deref(),
            Some("global_rotation: float = 0.0")
        );

        // Enum declaration + enum member path.
        assert!(find(&symbols, "Node2D.TextureFilter").is_some());
        let em = find(&symbols, "Node2D.TextureFilter.TEXTURE_FILTER_NEAREST").unwrap();
        assert_eq!(em.kind, SymbolKind::EnumMember);
        assert_eq!(
            em.signature.as_deref(),
            Some("TEXTURE_FILTER_NEAREST = 1")
        );

        // All symbols share library/version.
        assert!(symbols.iter().all(|s| s.library == "godot" && s.version == "4.4"));
    }

    #[test]
    fn class_with_no_methods_still_emits_class() {
        let xml = r#"<class name="Empty" inherits="Object">
            <description>Nothing here.</description>
        </class>"#;
        let symbols = parse_xml(xml, "master").expect("parse ok");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].path, "Empty");
        assert_eq!(symbols[0].kind, SymbolKind::Class);
    }

    #[test]
    fn class_without_inherits_has_bare_signature() {
        let xml = r#"<class name="Variant">
            <description>Root type.</description>
        </class>"#;
        let symbols = parse_xml(xml, "4.3").expect("parse ok");
        let c = find(&symbols, "Variant").unwrap();
        assert!(c.return_type.is_none());
        assert_eq!(c.signature.as_deref(), Some("class Variant"));
    }

    #[test]
    fn malformed_xml_returns_err() {
        let xml = r#"<class name="Foo"><description>oops no close"#;
        let result = parse_xml(xml, "4.3");
        assert!(result.is_err(), "expected Err on truncated XML");
        let err = result.unwrap_err();
        assert!(
            err.contains("xml") || err.contains("EOF"),
            "error message should mention the cause, got: {err}"
        );
    }

    #[test]
    fn bbcode_tags_stripped_from_doc_text() {
        let xml = r#"<class name="X" inherits="Y">
            <methods>
                <method name="m">
                    <return type="void" />
                    <description>Sets [param speed] on [Node2D]. See [method get_speed]. Use [code]flags[/code].</description>
                </method>
            </methods>
        </class>"#;
        let symbols = parse_xml(xml, "4.3").expect("parse ok");
        let m = find(&symbols, "X.m").unwrap();
        assert_eq!(
            m.doc_text.as_deref(),
            Some("Sets speed on Node2D. See get_speed. Use flags.")
        );
    }

    #[test]
    fn method_default_param_in_signature() {
        let xml = r#"<class name="C" inherits="P">
            <methods>
                <method name="m">
                    <return type="C" />
                    <param index="0" name="depth" type="int" default="1" />
                </method>
            </methods>
        </class>"#;
        let symbols = parse_xml(xml, "4.3").expect("parse ok");
        let m = find(&symbols, "C.m").unwrap();
        assert_eq!(
            m.signature.as_deref(),
            Some("m(depth: int = 1) -> C")
        );
        assert_eq!(m.params[0].default_value.as_deref(), Some("1"));
    }
}
