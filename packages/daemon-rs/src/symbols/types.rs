//! Generic Symbol type — works across Godot / TypeScript / Python / Rust / Go.
//!
//! Designed to be the unified representation of "an exported thing with a
//! signature". Per-language parsers (godot_parser, ts_parser, etc.) fill
//! this struct; scanner + cache layer treat them identically.

use serde::{Deserialize, Serialize};

/// A single exported symbol (class, method, property, signal, etc.)
///
/// Identified by `(library, version, path)` triple — globally unique.
/// Example paths:
///   - Godot:  "Node2D.apply_scale"          (class.method)
///   - Godot:  "Node2D.position_changed"      (class.signal)
///   - TS:     "react.useState"               (package.function)
///   - TS:     "react.Component.render"       (package.class.method)
///   - Python: "requests.get"                  (module.function)
///   - Rust:   "serde::Serialize"             (crate::trait)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Symbol {
    /// Library identifier: "godot", "react", "axios", "serde"
    pub library: String,
    /// Library version: "4.3", "18.2.0", "1.0.0"
    pub version: String,
    /// Fully-qualified symbol path within the library.
    /// Dot-separated, type-name-first per language convention.
    pub path: String,
    /// Last segment of `path` — e.g. "apply_scale" for "Node2D.apply_scale"
    pub name: String,
    /// What kind of symbol this is.
    pub kind: SymbolKind,
    /// Human-readable signature, e.g. "apply_scale(ratio: Vector2) -> void"
    pub signature: Option<String>,
    /// Formal parameters (when parseable).
    pub params: Vec<Param>,
    /// Return type as string (when parseable).
    pub return_type: Option<String>,
    /// Doc comment / description extracted from upstream source.
    pub doc_text: Option<String>,
    /// Original file the symbol was extracted from (for debugging).
    pub source_file: Option<String>,
    /// Visibility / access modifier.
    pub visibility: Visibility,
    /// Whether upstream marks this deprecated.
    pub is_deprecated: bool,
    /// Deprecation message if any.
    pub deprecated_message: Option<String>,
    /// Unix timestamp (seconds) when this row was written.
    pub extracted_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// Godot class, TS class, Python class, Rust struct
    Class,
    /// Method on a class or instance
    Method,
    /// Free function (not bound to a class)
    Function,
    /// Member field / property
    Property,
    /// Event (Godot signal, C# event, JS event emitter)
    Signal,
    /// Compile-time constant
    Constant,
    /// Enum declaration
    Enum,
    /// Variant within an enum
    EnumMember,
    /// Decorator / attribute / annotation
    Annotation,
    /// TS interface, Go interface, Rust trait
    Interface,
    /// Type alias (TS type, Rust type alias, Python type alias)
    TypeAlias,
    /// Namespace / module
    Module,
    /// Constructor
    Constructor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Param {
    pub name: String,
    /// Type as string (e.g. "Vector2", "string", "T")
    pub type_name: String,
    /// Default value if optional, e.g. "null", "0", "Vector2.ZERO"
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Protected,
    Private,
    Internal,
}

impl Symbol {
    /// Construct a new Symbol with library/version/path; auto-extracts `name`
    /// from the last path segment. Other fields default to None/empty.
    pub fn new(library: impl Into<String>, version: impl Into<String>, path: impl Into<String>) -> Self {
        let path = path.into();
        let name = path.rsplit('.').next().unwrap_or(&path).to_string();
        Self {
            library: library.into(),
            version: version.into(),
            path,
            name,
            kind: SymbolKind::Method,
            signature: None,
            params: Vec::new(),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    /// Generate a human-readable signature string from kind + name + params
    /// + return type. Used when `signature` field is None (parser didn't
    /// emit one).
    pub fn synthetic_signature(&self) -> String {
        let params_str = self
            .params
            .iter()
            .map(|p| match p.default_value.as_ref() {
                Some(default) => format!("{}: {} = {}", p.name, p.type_name, default),
                None => format!("{}: {}", p.name, p.type_name),
            })
            .collect::<Vec<_>>()
            .join(", ");

        let ret = self
            .return_type
            .as_deref()
            .unwrap_or("void");

        match self.kind {
            SymbolKind::Method | SymbolKind::Function | SymbolKind::Constructor => {
                format!("{}({}) -> {}", self.name, params_str, ret)
            }
            SymbolKind::Property => format!("{}: {}", self.name, ret),
            SymbolKind::Signal => format!("signal {}", self.name),
            SymbolKind::Constant => format!("const {}", self.name),
            SymbolKind::Enum => format!("enum {}", self.name),
            SymbolKind::EnumMember => format!("{} = ?", self.name),
            SymbolKind::Annotation => format!("@{}", self.name),
            SymbolKind::Class => format!("class {}", self.name),
            SymbolKind::Interface => format!("interface {}", self.name),
            SymbolKind::TypeAlias => format!("type {}", self.name),
            SymbolKind::Module => format!("module {}", self.name),
        }
    }

    /// Signature to display — prefers explicit `signature` field, falls
    /// back to `synthetic_signature()`.
    pub fn display_signature(&self) -> &str {
        self.signature.as_deref().unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_extracts_name_from_path() {
        let s = Symbol::new("godot", "4.3", "Node2D.apply_scale");
        assert_eq!(s.name, "apply_scale");
        assert_eq!(s.library, "godot");
        assert_eq!(s.version, "4.3");
    }

    #[test]
    fn new_handles_single_segment_path() {
        let s = Symbol::new("react", "18.2.0", "useState");
        assert_eq!(s.name, "useState");
    }

    #[test]
    fn synthetic_signature_for_method() {
        let mut s = Symbol::new("godot", "4.3", "Node2D.apply_scale");
        s.kind = SymbolKind::Method;
        s.params.push(Param {
            name: "ratio".into(),
            type_name: "Vector2".into(),
            default_value: None,
        });
        s.return_type = Some("void".into());
        assert_eq!(
            s.synthetic_signature(),
            "apply_scale(ratio: Vector2) -> void"
        );
    }

    #[test]
    fn synthetic_signature_for_property() {
        let mut s = Symbol::new("godot", "4.3", "Node2D.global_position");
        s.kind = SymbolKind::Property;
        s.return_type = Some("Vector2".into());
        assert_eq!(s.synthetic_signature(), "global_position: Vector2");
    }

    #[test]
    fn synthetic_signature_with_default_value() {
        let mut s = Symbol::new("godot", "4.3", "Node.foo");
        s.kind = SymbolKind::Method;
        s.params.push(Param {
            name: "depth".into(),
            type_name: "int".into(),
            default_value: Some("1".into()),
        });
        s.return_type = Some("Node".into());
        assert_eq!(s.synthetic_signature(), "foo(depth: int = 1) -> Node");
    }

    #[test]
    fn serde_roundtrip() {
        let mut s = Symbol::new("godot", "4.3", "Node2D.apply_scale");
        s.kind = SymbolKind::Method;
        s.return_type = Some("void".into());
        s.doc_text = Some("Multiplies the current scale by the ratio vector.".into());

        let json = serde_json::to_string(&s).unwrap();
        let back: Symbol = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn enum_kind_serializes_snake_case() {
        let json = serde_json::to_string(&SymbolKind::EnumMember).unwrap();
        assert_eq!(json, "\"enum_member\"");
        let back: SymbolKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SymbolKind::EnumMember);
    }
}
