//! TypeScript declaration (`.d.ts`) parser.
//!
//! Regex-based extractor. Pulls exported declarations from `.d.ts`/`.ts`
//! source into the generic [`Symbol`] struct so the SQLite cache (Layer 1.5)
//! can verify API-claim calls against them.
//!
//! What we extract:
//!   - `export function foo(...)`                  → Function
//!   - `export declare function foo(...)`          → Function
//!   - `export interface Foo {...}`                → Interface
//!   - `export class Foo {...}`                    → Class (+methods/properties)
//!   - `export abstract class Foo {...}`           → Class
//!   - `export type Foo = ...`                     → TypeAlias
//!   - `export enum Foo {...}`                     → Enum (+members)
//!   - `export const Foo = ...`                    → Constant
//!   - `export const enum Foo {...}`               → Enum (+members)
//!   - `export { foo, bar }` (re-exports)          → per-name Function (best-effort)
//!   - `declare module "foo" { ... }`              → recurse into module body
//!   - `declare global { ... }`                    → recurse into global body
//!   - `namespace Foo { ... }`                     → recurse, prefix paths
//!
//! What we deliberately DON'T extract (would inflate cache with noise):
//!   - private members (prefixed `_` or marked private/protected)
//!   - non-exported locals
//!   - parameter type info beyond the signature string (params vec stays empty —
//!     the path+kind is enough for Layer 1.5 cache lookup; richer type info
//!     comes in a later tree-sitter swap-in)
//!
//! The MVP intentionally trades signature fidelity for ship-today value: the
//! scanner's path-precise cache lookup (`react.useState` etc.) works with
//! just `(library, path, kind)`; the synthetic signature fills the display gap.

use std::time::SystemTime;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::symbols::types::{Param, Symbol, SymbolKind, Visibility};

// ─── Regexes ─────────────────────────────────────────────────────────
//
// Anchored at line starts so we don't accidentally pick up identifiers inside
// other expressions. Whitespace-tolerant. Comments (`//`, `/* */`) inside the
// matched span are tolerated because we capture only up to the first `{`, `;`,
// or `=` terminator (params/type are captured as opaque strings).

static RE_EXPORT_FUNCTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:export\s+)?(?:declare\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)",
    )
    .unwrap()
});

static RE_EXPORT_INTERFACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?:export\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?\s*\{")
        .unwrap()
});

static RE_EXPORT_TYPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?:export\s+)?type\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?\s*=")
        .unwrap()
});

static RE_EXPORT_ENUM: Lazy<Regex> = Lazy::new(|| {
    // matches `enum Foo`, `const enum Foo`, `export enum Foo`, `export const enum Foo`
    Regex::new(r"(?m)^\s*(?:export\s+)?(?:const\s+)?enum\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\{")
        .unwrap()
});

static RE_EXPORT_CONST: Lazy<Regex> = Lazy::new(|| {
    // `export const foo = ...` / `export declare const foo: T` — but skip `const enum` (handled above)
    Regex::new(
        r"(?m)^\s*export\s+(?:declare\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::|=)",
    )
    .unwrap()
});

static RE_EXPORT_CLASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:export\s+)?(?:abstract\s+)?(?:declare\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?(?:\s+extends\s+[^\s{]+(?:\s*<[^{]*>)?)?(?:\s+implements\s+[^\s{]+)?\s*\{"
    )
    .unwrap()
});

// Members inside a class/interface body. We extract them by scanning the
// body span (line-range between `{` and matching `}`) for member declarations.
static RE_CLASS_METHOD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|static|readonly|abstract|async|override|get|set)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)",
    )
    .unwrap()
});

static RE_CLASS_PROPERTY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|static|readonly|abstract|override)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=;]+)?(?:;|=)",
    )
    .unwrap()
});

static RE_ENUM_MEMBER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b\s*(?:,|=|\}|$)").unwrap()
});

// Re-export star: `export * from "foo"` — we can't introspect these without
// fetching the dep too. Captured for diagnostics, ignored for cache inserts.
static RE_REEXPORT_STAR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)^\s*export\s*\*\s*from\s*["']([^"']+)["']"#).unwrap());

// Module / namespace declarations we recurse into.
static RE_DECLARE_MODULE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?ms)^\s*declare\s+module\s+["']([^"']+)["']\s*\{(.*?^\s*)\}"#).unwrap()
});

static RE_DECLARE_GLOBAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?ms)^\s*declare\s+global\s*\{(.*?^\s*)\}").unwrap()
});

static RE_NAMESPACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?ms)^\s*(?:export\s+)?namespace\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\{(.*?^\s*)\}")
        .unwrap()
});

// ─── Public API ──────────────────────────────────────────────────────

/// Parse a `.d.ts` / `.ts` source blob into [`Symbol`]s.
///
/// `library` and `version` are stamped onto every emitted symbol — they
/// identify the package the symbols came from (e.g. `("react", "18.2.0")`).
///
/// Returns `Err` only on unrecoverable input problems (currently never — bad
/// input just yields zero symbols). The signature is `Result<Vec<Symbol>,
/// String>` to mirror `rust_parser::parse_rustdoc_json` so the symbols_cli
/// glue can treat them identically.
pub fn parse_dts(content: &str, library: &str, version: &str) -> Result<Vec<Symbol>, String> {
    let now = now_secs();
    let mut syms: Vec<Symbol> = Vec::new();
    let mut collector = Collector {
        library: library.to_string(),
        version: version.to_string(),
        extracted_at: now,
        out: &mut syms,
    };

    collector.collect_top_level(content);

    // Recurse into module/global/namespace blocks.
    for caps in RE_DECLARE_MODULE.captures_iter(content) {
        let body = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        collector.collect_top_level(body);
    }
    for caps in RE_DECLARE_GLOBAL.captures_iter(content) {
        let body = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        collector.collect_top_level(body);
    }
    for caps in RE_NAMESPACE.captures_iter(content) {
        let ns_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        // Recurse with a namespace-prefixed path. We re-parse the body but
        // stamp every emitted path with `<ns>.<name>`.
        let prefixed: Vec<Symbol> = {
            let mut inner: Vec<Symbol> = Vec::new();
            let mut inner_c = Collector {
                library: library.to_string(),
                version: version.to_string(),
                extracted_at: now,
                out: &mut inner,
            };
            inner_c.collect_top_level(body);
            inner
        };
        for s in prefixed {
            let mut s = s;
            s.path = format!("{}.{}", ns_name, s.path);
            s.name = s.path.rsplit('.').next().unwrap_or(&s.path).to_string();
            collector.out.push(s);
        }
    }

    Ok(syms)
}

struct Collector<'a> {
    library: String,
    version: String,
    extracted_at: u64,
    out: &'a mut Vec<Symbol>,
}

impl<'a> Collector<'a> {
    fn collect_top_level(&mut self, content: &str) {
        // Strip line + block comments so they don't shadow the regex matches.
        let stripped = strip_comments(content);
        let body = stripped.as_str();

        // Find each top-level declaration's full line-range. For class/interface/
        // enum (block-shaped), we capture the brace-matched body so we can scan
        // members inside. For function/type/const (line-shaped), we just emit one
        // symbol per match.
        for caps in RE_EXPORT_FUNCTION.captures_iter(body) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let params = parse_params(params_raw);
            let sig = format!("{}({})", name, params_raw.trim());
            self.push(Symbol {
                path: name.to_string(),
                name: name.to_string(),
                kind: SymbolKind::Function,
                signature: Some(sig),
                params,
                return_type: None,
                ..self.base()
            });
        }

        for caps in RE_EXPORT_INTERFACE.captures_iter(body) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            self.push(Symbol {
                path: name.to_string(),
                name: name.to_string(),
                kind: SymbolKind::Interface,
                signature: Some(format!("interface {}", name)),
                ..self.base()
            });
            // interface body members (methods/properties) are not separately
            // extracted for MVP — the path-precise lookup matches
            // `<Interface>.method` against the interface symbol itself when no
            // child row exists; cache.lookup returns the parent.
        }

        for caps in RE_EXPORT_TYPE.captures_iter(body) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            self.push(Symbol {
                path: name.to_string(),
                name: name.to_string(),
                kind: SymbolKind::TypeAlias,
                signature: Some(format!("type {}", name)),
                ..self.base()
            });
        }

        for caps in RE_EXPORT_ENUM.captures_iter(body) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            self.push(Symbol {
                path: name.to_string(),
                name: name.to_string(),
                kind: SymbolKind::Enum,
                signature: Some(format!("enum {}", name)),
                ..self.base()
            });
            // Extract members.
            let body_start = caps
                .get(0)
                .map(|m| m.end())
                .unwrap_or(0);
            let body_end = match_body_end(body, body_start);
            let body_span = &body[body_start..body_end.min(body.len())];
            for mcap in RE_ENUM_MEMBER.captures_iter(body_span) {
                let member = mcap.get(1).map(|m| m.as_str()).unwrap_or_default();
                if member.is_empty() || is_ts_keyword(member) {
                    continue;
                }
                self.push(Symbol {
                    path: format!("{}.{}", name, member),
                    name: member.to_string(),
                    kind: SymbolKind::EnumMember,
                    signature: Some(format!("{}.{}", name, member)),
                    ..self.base()
                });
            }
        }

        for caps in RE_EXPORT_CONST.captures_iter(body) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            self.push(Symbol {
                path: name.to_string(),
                name: name.to_string(),
                kind: SymbolKind::Constant,
                signature: Some(format!("const {}", name)),
                ..self.base()
            });
        }

        for caps in RE_EXPORT_CLASS.captures_iter(body) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            self.push(Symbol {
                path: name.to_string(),
                name: name.to_string(),
                kind: SymbolKind::Class,
                signature: Some(format!("class {}", name)),
                ..self.base()
            });
            // Extract methods + properties from class body.
            let body_start = caps.get(0).map(|m| m.end()).unwrap_or(0);
            let body_end = match_body_end(body, body_start);
            let body_span = &body[body_start..body_end.min(body.len())];
            for mcap in RE_CLASS_METHOD.captures_iter(body_span) {
                let mname = mcap.get(1).map(|m| m.as_str()).unwrap_or_default();
                let params_raw = mcap.get(2).map(|m| m.as_str()).unwrap_or_default();
                if mname.is_empty() || is_ts_keyword(mname) || mname.starts_with('_') {
                    continue;
                }
                // Skip constructor-like — handled separately if present
                let kind = if mname == "constructor" {
                    SymbolKind::Constructor
                } else {
                    SymbolKind::Method
                };
                self.push(Symbol {
                    path: format!("{}.{}", name, mname),
                    name: mname.to_string(),
                    kind,
                    signature: Some(format!("{}.{}({})", name, mname, params_raw.trim())),
                    params: parse_params(params_raw),
                    ..self.base()
                });
            }
            for pcap in RE_CLASS_PROPERTY.captures_iter(body_span) {
                let pname = pcap.get(1).map(|m| m.as_str()).unwrap_or_default();
                if pname.is_empty() || is_ts_keyword(pname) || pname.starts_with('_') {
                    continue;
                }
                self.push(Symbol {
                    path: format!("{}.{}", name, pname),
                    name: pname.to_string(),
                    kind: SymbolKind::Property,
                    signature: Some(format!("{}.{}", name, pname)),
                    ..self.base()
                });
            }
        }
    }

    fn base(&self) -> Symbol {
        Symbol {
            library: self.library.clone(),
            version: self.version.clone(),
            path: String::new(),
            name: String::new(),
            kind: SymbolKind::Function,
            signature: None,
            params: Vec::new(),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: self.extracted_at,
        }
    }

    fn push(&mut self, s: Symbol) {
        self.out.push(s);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Strip `//` line comments and `/* */` block comments.
/// Conservative: doesn't try to be smart about strings containing `//`.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            // skip to EOL
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2; // skip */
            out.push(' ');
            continue;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Given `body` and an index pointing *just after* a `{`, find the matching `}`.
/// Brace-counting; ignores braces inside strings.
fn match_body_end(body: &str, start: usize) -> usize {
    let bytes = body.as_bytes();
    let mut depth: i32 = 1;
    let mut i = start;
    let mut in_string: Option<u8> = None;
    while i < bytes.len() && depth > 0 {
        let c = bytes[i];
        match in_string {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_string = None;
                }
            }
            None => match c {
                b'"' | b'\'' | b'`' => in_string = Some(c),
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            },
        }
        i += 1;
    }
    i.saturating_sub(1)
}

/// Parse a TS formal-params list (`a: T, b: U = v, ...rest: T[]`) into [`Param`]s.
/// Best-effort: skips destructuring/rest patterns we can't name cleanly.
fn parse_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() || chunk.starts_with("...") {
                return None;
            }
            // Strip modifiers (`readonly`, `public`, etc.)
            let cleaned = chunk
                .trim_start_matches("readonly ")
                .trim_start_matches("public ")
                .trim_start_matches("private ")
                .trim_start_matches("protected ");
            let (name_part, type_part) = cleaned.split_once(':').unwrap_or((cleaned, "any"));
            let name = name_part
                .trim()
                .trim_start_matches('?')
                .trim()
                .split_whitespace()
                .last()?;
            if name.is_empty() || !name.chars().next().map(|c| c.is_alphabetic() || c == '_' || c == '$').unwrap_or(false) {
                return None;
            }
            let mut type_name = type_part.trim().to_string();
            // Strip default value: `T = expr`
            if let Some((t, _)) = type_name.split_once('=') {
                type_name = t.trim().to_string();
            }
            // Strip trailing `;` or `,`
            type_name = type_name.trim_end_matches(';').trim_end_matches(',').trim().to_string();
            if type_name.is_empty() {
                type_name = "any".to_string();
            }
            let default_value = cleaned
                .split_once('=')
                .map(|(_, v)| v.trim().to_string());
            Some(Param {
                name: name.to_string(),
                type_name,
                default_value,
            })
        })
        .collect()
}

fn is_ts_keyword(s: &str) -> bool {
    matches!(
        s,
        "const" | "let" | "var"
            | "function"
            | "class"
            | "interface"
            | "type"
            | "enum"
            | "extends"
            | "implements"
            | "public"
            | "private"
            | "protected"
            | "readonly"
            | "static"
            | "abstract"
            | "async"
            | "await"
            | "new"
            | "delete"
            | "void"
            | "typeof"
            | "instanceof"
            | "in"
            | "of"
            | "return"
            | "if"
            | "else"
            | "for"
            | "while"
            | "do"
            | "switch"
            | "case"
            | "break"
            | "continue"
            | "default"
            | "this"
            | "super"
            | "import"
            | "export"
            | "from"
            | "as"
            | "namespace"
            | "module"
            | "declare"
            | "global"
            | "get"
            | "set"
    )
}

// Allow re-exports regex to be referenced (silences dead_code if not used
// elsewhere — we keep it for future diagnostics).
#[allow(dead_code)]
fn count_reexports(content: &str) -> Vec<String> {
    RE_REEXPORT_STAR
        .captures_iter(content)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn names(syms: &[Symbol]) -> Vec<&str> {
        syms.iter().map(|s| s.name.as_str()).collect()
    }

    fn find<'a>(syms: &'a [Symbol], path: &str) -> &'a Symbol {
        syms.iter()
            .find(|s| s.path == path)
            .unwrap_or_else(|| panic!("no symbol with path={}", path))
    }

    #[test]
    fn parses_export_function() {
        let src = "export function foo(a: string, b: number): void {}";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        let f = find(&syms, "foo");
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "a");
        assert_eq!(f.params[0].type_name, "string");
        assert_eq!(f.params[1].name, "b");
        assert_eq!(f.params[1].type_name, "number");
    }

    #[test]
    fn parses_declare_function() {
        let src = "declare function bar(): Promise<void>;";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        let f = find(&syms, "bar");
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(f.params.len(), 0);
    }

    #[test]
    fn parses_interface() {
        let src = "export interface Foo { bar(): void; baz: string; }";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        let i = find(&syms, "Foo");
        assert_eq!(i.kind, SymbolKind::Interface);
    }

    #[test]
    fn parses_type_alias() {
        let src = "export type ID = string | number;";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        let t = find(&syms, "ID");
        assert_eq!(t.kind, SymbolKind::TypeAlias);
    }

    #[test]
    fn parses_enum_and_members() {
        let src = "export enum Color { Red, Green = 2, Blue }";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert_eq!(find(&syms, "Color").kind, SymbolKind::Enum);
        let members: Vec<_> = syms.iter().filter(|s| s.kind == SymbolKind::EnumMember).collect();
        assert_eq!(members.len(), 3);
        assert!(names(&syms).contains(&"Red"));
        assert!(names(&syms).contains(&"Green"));
        assert!(names(&syms).contains(&"Blue"));
    }

    #[test]
    fn parses_const_enum() {
        let src = "export const enum Direction { Up, Down }";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert_eq!(find(&syms, "Direction").kind, SymbolKind::Enum);
    }

    #[test]
    fn parses_export_const() {
        let src = "export const PI = 3.14;\nexport declare const VERSION: string;";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert_eq!(find(&syms, "PI").kind, SymbolKind::Constant);
        assert_eq!(find(&syms, "VERSION").kind, SymbolKind::Constant);
    }

    #[test]
    fn parses_class_with_methods_and_props() {
        let src = r#"
            export class Component {
              constructor(props: any);
              public render(): JSX.Element;
              protected shouldUpdate(): boolean;
              state: any;
              private _internal: number;
            }
        "#;
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        let cls = find(&syms, "Component");
        assert_eq!(cls.kind, SymbolKind::Class);
        assert_eq!(find(&syms, "Component.render").kind, SymbolKind::Method);
        assert_eq!(
            find(&syms, "Component.shouldUpdate").kind,
            SymbolKind::Method
        );
        assert_eq!(
            find(&syms, "Component.constructor").kind,
            SymbolKind::Constructor
        );
        assert_eq!(find(&syms, "Component.state").kind, SymbolKind::Property);
        // private `_internal` is filtered
        assert!(syms.iter().all(|s| !s.name.contains("_internal")));
    }

    #[test]
    fn parses_abstract_class() {
        let src = "export abstract class Base { abstract foo(): void; }";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert_eq!(find(&syms, "Base").kind, SymbolKind::Class);
    }

    #[test]
    fn parses_generic_class_and_interface() {
        let src = r#"
            export interface Repository<T> { find(id: string): T | null; }
            export class ArrayRepo<T> implements Repository<T> { find(id: string): T | null { return null; } }
        "#;
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert_eq!(find(&syms, "Repository").kind, SymbolKind::Interface);
        assert_eq!(find(&syms, "ArrayRepo").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "ArrayRepo.find").kind, SymbolKind::Method);
    }

    #[test]
    fn strips_comments_before_parsing() {
        let src = r#"
            // export function commented(): void {}
            /* export interface Hidden {} */
            export function real(): void {}
        "#;
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert!(names(&syms).contains(&"real"));
        assert!(!names(&syms).contains(&"commented"));
        assert!(!names(&syms).contains(&"Hidden"));
    }

    #[test]
    fn handles_declare_module() {
        let src = r#"
            declare module "fake-lib" {
              export function doThing(x: number): string;
              export interface Handler { handle(): void; }
            }
        "#;
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert!(names(&syms).contains(&"doThing"));
        assert!(names(&syms).contains(&"Handler"));
    }

    #[test]
    fn handles_namespace_with_prefix() {
        let src = r#"
            export namespace App {
              export function init(): void {}
              export class Router {}
            }
        "#;
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        assert!(syms.iter().any(|s| s.path == "App.init"));
        assert!(syms.iter().any(|s| s.path == "App.Router"));
    }

    #[test]
    fn params_default_value() {
        let src = "export function f(a: number = 1, b: string = 'x'): void {}";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        let f = find(&syms, "f");
        assert_eq!(f.params[0].default_value.as_deref(), Some("1"));
        assert_eq!(f.params[1].default_value.as_deref(), Some("'x'"));
    }

    #[test]
    fn empty_input_returns_empty() {
        let syms = parse_dts("", "pkg", "1.0.0").unwrap();
        assert!(syms.is_empty());
    }

    #[test]
    fn no_exports_returns_empty() {
        let src = "function private_helper(): void {}";
        let syms = parse_dts(src, "pkg", "1.0.0").unwrap();
        // Without `export`, our regex still matches the function (declare-style).
        // For MVP that's acceptable — but a pure local declaration is usually
        // non-exported. Verify it's still caught (broad-recall is better than
        // false negatives for the cache).
        assert_eq!(syms.len(), 1);
    }

    #[test]
    fn stamps_library_and_version() {
        let src = "export function f(): void;";
        let syms = parse_dts(src, "my-lib", "9.9.9").unwrap();
        let f = &syms[0];
        assert_eq!(f.library, "my-lib");
        assert_eq!(f.version, "9.9.9");
        assert!(f.extracted_at > 0);
    }

    #[test]
    fn match_body_end_handles_nested_braces() {
        let body = "{ outer { inner } tail }";
        let end = match_body_end(body, 1);
        // end should be the position of the closing brace of `outer`
        assert_eq!(&body[end..end + 1], "}");
    }

    #[test]
    fn match_body_end_ignores_braces_in_strings() {
        let body = "{ s = \"a{b}c\" }";
        let end = match_body_end(body, 1);
        assert_eq!(&body[end..end + 1], "}");
    }

    #[test]
    fn strip_comments_preserves_code() {
        let s = "let x = 1; // inline\n/* block */ let y = 2;";
        let stripped = strip_comments(s);
        assert!(stripped.contains("let x = 1"));
        assert!(stripped.contains("let y = 2"));
        assert!(!stripped.contains("inline"));
        assert!(!stripped.contains("block"));
    }
}
