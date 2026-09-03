//! Tree-sitter based TypeScript/TSX scope analysis.
//!
//! Same architecture as rust_ast_extractor.rs — proper AST parsing replaces
//! regex word-boundary matching (FORGE 2026 pattern). Eliminates English
//! prose contamination that produced 8 FORGE FPs per TS benchmark run.
//!
//! Uses the TSX grammar which handles both .ts and .tsx files.

use std::collections::HashSet;
use tree_sitter::{Node, Parser};

// ─── Keyword / builtin sets ─────────────────────────────────────────────

const TS_KEYWORDS: &[&str] = &[
    "const", "let", "var", "function", "class", "interface", "type", "enum",
    "import", "export", "default", "extends", "implements", "new", "delete",
    "typeof", "instanceof", "void", "this", "super", "return", "if", "else",
    "for", "while", "do", "switch", "case", "break", "continue", "throw",
    "try", "catch", "finally", "async", "await", "yield", "static", "get",
    "set", "public", "private", "protected", "readonly", "abstract", "as",
    "is", "in", "of", "namespace", "module", "declare", "from", "satisfies",
    "true", "false", "null", "undefined", "NaN", "Infinity",
];

const TS_BUILTIN_GLOBALS: &[&str] = &[
    "console", "window", "document", "globalThis", "process", "Buffer",
    "Math", "JSON", "Object", "Array", "String", "Number", "Boolean",
    "RegExp", "Date", "Promise", "Map", "Set", "WeakMap", "WeakSet",
    "Symbol", "Proxy", "Reflect", "Error", "TypeError", "RangeError",
    "SyntaxError", "Intl", "BigInt", "isNaN", "isFinite", "parseInt",
    "parseFloat", "encodeURIComponent", "decodeURIComponent",
    "encodeURI", "decodeURI", "setTimeout", "setInterval",
    "clearTimeout", "clearInterval", "queueMicrotask",
    "AbortController", "AbortSignal", "Event", "EventTarget",
    "CustomEvent", "URL", "URLSearchParams", "Headers",
    "Request", "Response", "fetch", "structuredClone",
    // Node.js built-in modules (always available via require/import)
    "path", "fs", "http", "https", "url", "crypto", "os", "util",
    "stream", "events", "net", "dns", "tls", "zlib", "querystring",
    "child_process", "cluster", "dgram", "readline", "repl", "vm",
    "worker_threads", "assert", "timers", "inspector", "perf_hooks",
    "async_hooks", "trace_events", "v8", "node",
    // Common Express/HTTP globals
    "app", "req", "res", "next",
];

const TS_UTILITY_TYPES: &[&str] = &[
    "Partial", "Required", "Readonly", "Record", "Pick", "Omit",
    "Exclude", "Extract", "NonNullable", "Parameters", "ReturnType",
    "InstanceType", "Awaited", "ConstructorParameters", "ThisType",
    "Uppercase", "Lowercase", "Capitalize", "Uncapitalize",
];

const REACT_GLOBALS: &[&str] = &[
    "React", "useState", "useEffect", "useRef", "useMemo", "useCallback",
    "useContext", "useReducer", "useLayoutEffect", "useImperativeHandle",
    "useTransition", "useDeferredValue", "useId", "useSyncExternalStore",
    "Fragment", "createContext", "forwardRef", "memo", "lazy",
    "Suspense", "Component", "PureComponent", "Children",
];

/// Canonical source-of-truth for JS/TS testing framework globals.
/// Referenced by FORGE Step 2b (named-import verification) and
/// `verify_ts_destructured_calls` to keep both paths in sync — do not
/// duplicate these names in `COMMON_TS_EXPORTS` (forge_pipeline.rs).
pub(crate) static TESTING_GLOBALS: once_cell::sync::Lazy<std::collections::HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
    [
    "describe", "it", "test", "expect", "beforeEach", "afterEach",
    "beforeAll", "afterAll", "before", "after", "vi", "vitest", "jest",
    "setup", "teardown",
    ].into_iter().collect()
});

/// Node types that represent a definition site — the identifier child
/// at field "name" is a definition, not a reference.
const DEFINITION_NODE_TYPES: &[&str] = &[
    "variable_declarator",
    "function_declaration",
    "class_declaration",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
    "method_definition",
    "getter", "setter",
    "import_clause",
    "namespace_declaration",
    "module_declaration",
];

/// Node types where children are parameters (always defined in scope).
const PARAM_NODE_TYPES: &[&str] = &[
    "required_parameter",
    "optional_parameter",
    "rest_pattern",
];

/// Node types for catch/loop binding sites.
const BINDING_NODE_TYPES: &[&str] = &[
    "catch_clause",
    "for_in_statement",
    "for_of_statement",
];

/// Node types whose name field is a method or property name (not a
/// Node types to skip entirely — no identifier collection from these.
const SKIP_NODE_TYPES: &[&str] = &[
    "comment",
    "string",
    "template_string",
    "regex",
    "number",
    "jsx_text",
    // Object property keys — always keys, never variable references.
    // Without this, CSS-in-JS properties leak: { padding: '1rem', display: 'flex' }
    "property_identifier",
    "shorthand_property_identifier",
    "property_signature",  // interface property keys handled here too
];

/// Structural node types — their presence indicates real code, not prose.
const STRUCTURAL_NODE_TYPES: &[&str] = &[
    "variable_declaration",
    "variable_declarator",
    "function_declaration",
    "class_declaration",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
    "import_statement",
    "export_statement",
    "expression_statement",
    "return_statement",
    "if_statement",
    "for_statement",
    "while_statement",
    "method_definition",
    "lexical_declaration",
    "assignment_expression",
    "call_expression",
    "new_expression",
    "arrow_function",
    "object",
    "array",
    "binary_expression",
    "jsx_element",
    "jsx_self_closing_element",
    "jsx_fragment",
    "type_annotation",
    "generic_type",
    "property_signature",
    "public_field_definition",
];

// ─── Code-likeness prefixes for per-line filtering ──────────────────────

const CODE_PREFIXES: &[&str] = &[
    "const ", "let ", "var ", "function ", "class ", "interface ",
    "type ", "enum ", "import ", "export ", "default ", "return ",
    "if ", "if(", "for ", "for(", "while ", "while(", "switch ",
    "try ", "try{", "catch ", "catch(", "async ", "await ",
    "new ", "throw ", "break", "continue", "case ",
    // Operators
    "&", "|", "=", "+", "-", "*", "/", "%", "!", "?", ":",
    "::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||",
    "//", "/*", "*/", "/**",
    "#", "@", "$",
    "{", "}", "(", ")", "[", "]",
    ";", ",",
];

// ─── Main entry point ───────────────────────────────────────────────────

/// Extract undefined variable references from TypeScript/TSX code.
///
/// Returns a list of warning strings for identifiers that are used but not
/// defined in scope. Uses tree-sitter AST for precise structural analysis.
pub fn extract_undefined_variables(content: &str) -> Vec<String> {
    // Pre-strip JSDoc comments inside import specifiers. Real-world TS
    // sometimes embeds `/** @deprecated ... */` notes inline:
    //   import { /** @deprecated Use z.lte() */ _lte } from 'zod';
    // Tree-sitter's TS grammar doesn't always handle these — the comment
    // token can swallow or shift the following identifier, so the import
    // name never lands in `defined` and gets flagged as undefined.
    let cleaned = strip_jsdoc_from_imports(content);
    let content: &str = &cleaned;

    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
        .expect("failed to load TSX grammar");

    let tree = parser.parse(content, None);
    let tree = match tree {
        Some(t) => t,
        None => return Vec::new(),
    };

    let root = tree.root_node();

    // Prose detection: reject content with too many errors or too few
    // structural nodes.
    if has_too_many_errors(root, content.as_bytes()) {
        return Vec::new();
    }

    let source_lines: Vec<&str> = content.lines().collect();
    let mut ctx = CollectContext {
        defined: HashSet::new(),
        referenced: HashSet::new(),
        source_lines: &source_lines,
    };

    collect_identifiers(root, &mut ctx);

    // Compute undefined.
    // Returns bare identifier names; the caller (forge_ts.rs) formats warnings.
    let mut undefined = Vec::new();
    for name in &ctx.referenced {
        if !ctx.defined.contains(name)
            && !is_keyword_or_builtin(name)
            && !TESTING_GLOBALS.contains(name.as_str())
            && name.len() >= 3
        {
            undefined.push(name.clone());
        }
    }

    undefined.sort();
    undefined
}

/// Extract all type/interface/class names defined in the content.
/// Used to supplement project-level type awareness.
pub fn extract_type_names(content: &str) -> HashSet<String> {
    let mut parser = Parser::new();
    if parser.set_language(&tree_sitter_typescript::LANGUAGE_TSX.into()).is_err() {
        return HashSet::new();
    }

    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return HashSet::new(),
    };
    let root = tree.root_node();

    let mut types = HashSet::new();
    collect_type_names(root, &mut types, content.as_bytes());
    types
}

// ─── Internal types ─────────────────────────────────────────────────────

struct CollectContext<'a> {
    defined: HashSet<String>,
    referenced: HashSet<String>,
    source_lines: &'a [&'a str],
}

// ─── Prose detection ────────────────────────────────────────────────────

fn has_too_many_errors(root: Node, source: &[u8]) -> bool {
    let mut errors = 0u32;
    let mut total = 0u32;
    let mut structural = 0u32;
    count_errors_and_nodes(root, &mut errors, &mut total, &mut structural);

    // No structural nodes at all → pure prose
    if structural == 0 {
        return true;
    }

    // Has errors AND very few structural nodes → likely prose
    if root.has_error() && structural < 3 {
        return true;
    }

    // Error ratio too high
    if total > 5 && (errors as f64 / total as f64) > 0.30 {
        return true;
    }

    let _ = source; // suppress unused warning
    false
}

fn count_errors_and_nodes(
    node: Node,
    errors: &mut u32,
    total: &mut u32,
    structural: &mut u32,
) {
    if node.is_error() || node.is_missing() {
        *errors += 1;
    }
    if node.is_named() {
        *total += 1;
        if STRUCTURAL_NODE_TYPES.contains(&node.kind()) {
            *structural += 1;
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            count_errors_and_nodes(child, errors, total, structural);
        }
    }
}

// ─── Identifier collection ──────────────────────────────────────────────

fn collect_identifiers<'a>(node: Node, ctx: &mut CollectContext<'a>) {
    let kind = node.kind();

    // Skip non-code content
    if SKIP_NODE_TYPES.contains(&kind) {
        return;
    }

    // Skip JSX text content (but not JSX expressions)
    if kind == "jsx_expression" {
        // Recurse into jsx_expression to get identifiers
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_identifiers(child, ctx);
            }
        }
        return;
    }

    // Definition sites — collect the name as defined
    if DEFINITION_NODE_TYPES.contains(&kind) {
        // Special handling for import clauses — they don't have a "name"
        // field. Need to extract all imported identifiers from import_specifier,
        // namespace_import, and default_import children.
        // NOTE: import_statement is not in DEFINITION_NODE_TYPES; we recurse
        // into its import_clause child, which is, and dispatch here.
        if kind == "import_clause" {
            collect_import_names(node, ctx);
            // Don't recurse further — import contents already collected
            return;
        }

        if let Some(name_node) = node.child_by_field_name("name") {
            let nkind = name_node.kind();
            if nkind == "identifier" {
                let text = node_text(name_node, ctx);
                if !text.is_empty() {
                    ctx.defined.insert(text);
                }
            } else if nkind == "array_pattern" || nkind == "object_pattern" {
                // Destructuring: const [a, b] = ... or const { x, y } = ...
                collect_pattern_names(name_node, ctx, true);
            }
        }
        // Also recurse to collect nested references
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_identifiers(child, ctx);
            }
        }
        return;
    }

    // Parameter nodes — their pattern children are defined
    if PARAM_NODE_TYPES.contains(&kind) {
        collect_pattern_names(node, ctx, true);
        return;
    }

    // Catch/loop bindings
    if BINDING_NODE_TYPES.contains(&kind) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let ckind = child.kind();
                if ckind == "identifier" || ckind == "array_pattern"
                    || ckind == "object_pattern" || ckind == "assignment_pattern"
                {
                    collect_pattern_names(child, ctx, true);
                } else {
                    collect_identifiers(child, ctx);
                }
            }
        }
        return;
    }

    // Arrow function — parameters are defined
    if kind == "arrow_function" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let ckind = child.kind();
                if ckind == "identifier" || ckind.contains("parameter")
                    || ckind == "formal_parameters"
                {
                    collect_pattern_names(child, ctx, true);
                } else {
                    collect_identifiers(child, ctx);
                }
            }
        }
        return;
    }

    // Identifier node — determine if it's a reference or definition
    if kind == "identifier" {
        let text = node_text(node, ctx);

        // Check if this is a method/field name (not a variable reference)
        if is_method_or_field_name(node) {
            return;
        }

        // Check if this is a property name in object literal
        if is_property_name(node) {
            return;
        }

        // Check if it's in a type annotation context
        if is_type_context(node) {
            return;
        }

        // Check if the source line looks like code
        let row = node.start_position().row;
        if row < ctx.source_lines.len() {
            let line = ctx.source_lines[row];
            if !line_looks_like_code(line) {
                return; // Prose line — skip identifier
            }
        }

        // Skip hex color fragments (ca3af, b7280, f2937) leaking from CSS
        if text.len() >= 4 && text.len() <= 8
            && text.chars().all(|c| c.is_ascii_hexdigit())
            && text.chars().filter(|c| c.is_ascii_alphabetic()).count() >= 2
        {
            return;
        }

        // Skip jQuery/PHP-style $-prefixed identifiers ($content, $el)
        if text.starts_with('$') {
            return;
        }

        // It's a reference (will be checked against defined set later)
        if !text.is_empty() {
            ctx.referenced.insert(text);
        }
        return;
    }

    // Recurse into all children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_identifiers(child, ctx);
        }
    }
}

/// Extract all imported names from an import statement.
/// Handles: import { X, Y } from 'mod', import X from 'mod', import * as X from 'mod'
fn collect_import_names<'a>(node: Node, ctx: &mut CollectContext<'a>) {
    fn walk_import<'a>(n: Node, ctx: &mut CollectContext<'a>) {
        let k = n.kind();
        if k == "import_specifier" {
            // { X } or { X as Y } — collect the local name (Y if aliased, else X)
            let mut found_alias = false;
            for i in 0..n.child_count() {
                if let Some(child) = n.child(i) {
                    if child.kind() == "identifier" {
                        let text = node_text(child, ctx);
                        if !text.is_empty() {
                            ctx.defined.insert(text);
                            found_alias = true;
                        }
                    }
                }
            }
            if found_alias { return; }
        }
        if k == "identifier" && n.parent().map_or(false, |p| {
            let pk = p.kind();
            pk == "import_clause" || pk == "namespace_import" || pk == "default_import"
        }) {
            let text = node_text(n, ctx);
            if !text.is_empty() {
                ctx.defined.insert(text);
            }
            return;
        }
        for i in 0..n.child_count() {
            if let Some(child) = n.child(i) {
                walk_import(child, ctx);
            }
        }
    }
    walk_import(node, ctx);
}

fn collect_pattern_names<'a>(node: Node, ctx: &mut CollectContext<'a>, _is_def: bool) {
    let kind = node.kind();

    if kind == "identifier" {
        let text = node_text(node, ctx);
        if !text.is_empty() {
            ctx.defined.insert(text);
        }
        return;
    }

    if kind == "assignment_pattern" {
        // default parameter: name = value
        if let Some(left) = node.child(0) {
            collect_pattern_names(left, ctx, true);
        }
        return;
    }

    if kind == "array_pattern" || kind == "object_pattern" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_pattern_names(child, ctx, true);
            }
        }
        return;
    }

    // Shorthand property in destructuring: `const { input } = opts`.
    //
    // NOTE: tree-sitter TSX grammar distinguishes the destructuring form
    // (`shorthand_property_identifier_pattern`, a leaf named node whose
    // source text IS the binding name) from the object-literal form
    // (`shorthand_property_identifier`, which is in SKIP_NODE_TYPES and
    // represents `{ foo }` inside `{ foo, bar }` literals). The pattern
    // variant has no identifier child — we extract its text directly.
    //
    // Regression: E2E benchmark task-03-ts-trpc emitted 6 FPs because the
    // previous code recursed into (non-existent) children of this node.
    if kind == "shorthand_property_identifier_pattern" {
        let text = node_text(node, ctx);
        if !text.is_empty() {
            ctx.defined.insert(text);
        }
        return;
    }

    // Long-form destructuring pair: `{ key: value }` or `{ key: value = default }`.
    // Recurse into children — the value (and default) side carries the
    // identifier being defined. Key is a property_identifier (skipped).
    if kind == "pair_pattern" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_pattern_names(child, ctx, true);
            }
        }
        return;
    }

    // formal_parameters — recurse
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_pattern_names(child, ctx, true);
        }
    }
}

fn collect_type_names(node: Node, types: &mut HashSet<String>, source: &[u8]) {
    let kind = node.kind();

    if matches!(
        kind,
        "class_declaration" | "interface_declaration" | "type_alias_declaration"
        | "enum_declaration"
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.kind() == "identifier" || name_node.kind() == "type_identifier" {
                if let Ok(text) = name_node.utf8_text(source) {
                    types.insert(text.to_string());
                }
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_type_names(child, types, source);
        }
    }
}

// ─── Helper functions ───────────────────────────────────────────────────

/// Strip JSDoc block comments (`/** ... */`) from inside the brace
/// portion of `import { ... }` statements.
///
/// Scope is intentionally narrow: only the inside of an import's braces is
/// touched. Comments elsewhere in the file are preserved. Lines outside
/// the matched region are unchanged. Used as a pre-processing step before
/// tree-sitter parsing to work around the TS grammar's handling of inline
/// comments in import specifiers.
fn strip_jsdoc_from_imports(content: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static JSDOC_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"/\*\*[^*]*\*+(?:[^/*][^*]*\*+)*/").unwrap()
    });
    static BRACED_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        // `import { ... }`, `import type { ... }`, `import D, { ... }`.
        // `[^;{}]*` between `import` and `{` covers default + namespace
        // bindings without crossing a statement boundary. Inside-brace
        // group uses `[^{}]*` so it spans newlines without nesting.
        Regex::new(r"(import\b[^;{}]*\{)([^{}]*)(\})").unwrap()
    });
    BRACED_IMPORT_RE
        .replace_all(content, |caps: &regex::Captures| {
            let cleaned = JSDOC_RE.replace_all(&caps[2], "");
            format!("{}{}{}", &caps[1], &cleaned, &caps[3])
        })
        .to_string()
}

fn node_text<'a>(node: Node, ctx: &CollectContext<'a>) -> String {
    let row = node.start_position().row;
    let col = node.start_position().column;
    let end_col = node.end_position().column;

    if row < ctx.source_lines.len() {
        let line = ctx.source_lines[row];
        if col < line.len() && end_col <= line.len() {
            return line[col..end_col].to_string();
        }
    }
    String::new()
}

fn is_method_or_field_name(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };

    let pkind = parent.kind();

    // member_expression: obj.prop → prop is field name
    if pkind == "member_expression" || pkind == "property_access_expression" {
        if let Some(property_token) = parent.child_by_field_name("property") {
            if property_token.id() == node.id() {
                return true;
            }
        }
        let last_named = parent.named_child(parent.named_child_count().saturating_sub(1));
        if let Some(last) = last_named {
            if last.id() == node.id() {
                return true;
            }
        }
    }

    // property in object literal: { key: value }
    if pkind == "pair" {
        if let Some(key) = parent.child_by_field_name("key") {
            if key.id() == node.id() {
                return true;
            }
        }
    }

    // shorthand property: { foo }
    if pkind == "shorthand_property_identifier" {
        return true;
    }

    // JSX attribute: <Comp attr={...}>
    if pkind == "jsx_attribute" {
        return true;
    }

    // JSX element name: <TodoList /> or <TodoList></TodoList>
    if pkind == "jsx_opening_element" || pkind == "jsx_closing_element"
        || pkind == "jsx_self_closing_element"
    {
        if let Some(name) = parent.child_by_field_name("name") {
            if name.id() == node.id() {
                return true;
            }
        }
        // Also skip if this is the first named child (the tag name)
        if let Some(first) = parent.named_child(0) {
            if first.id() == node.id() {
                return true;
            }
        }
    }

    // Named import: { foo } or { foo as bar }
    if pkind == "import_specifier" {
        return true;
    }

    // Labeled statement
    if pkind == "labeled_statement" {
        if let Some(label) = parent.child_by_field_name("label") {
            if label.id() == node.id() {
                return true;
            }
        }
    }

    false
}

fn is_property_name(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };

    // property_signature: interface { foo: Type }
    if parent.kind() == "property_signature" {
        if let Some(key) = parent.child_by_field_name("name") {
            if key.id() == node.id() {
                return true;
            }
        }
    }

    // public_field_definition: class { foo = value }
    if parent.kind() == "public_field_definition" {
        if let Some(prop) = parent.child_by_field_name("name") {
            if prop.id() == node.id() {
                return true;
            }
        }
    }

    // property_identifier in class body
    if parent.kind() == "method_definition" {
        if let Some(child_0) = parent.child(0) {
            if child_0.id() == node.id() {
                return true;
            }
        }
    }

    false
}

fn is_type_context(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };

    matches!(
        parent.kind(),
        "type_annotation" | "type_arguments" | "generic_type"
        | "type_alias_declaration" | "interface_declaration"
        | "type_parameter" | "constraint" | "default_type"
        | "object_type" | "union_type" | "intersection_type"
        | "conditional_type" | "indexed_access_type" | "mapped_type"
    )
}

fn is_keyword_or_builtin(name: &str) -> bool {
    if TS_KEYWORDS.contains(&name) {
        return true;
    }
    if TS_BUILTIN_GLOBALS.contains(&name) {
        return true;
    }
    if TS_UTILITY_TYPES.contains(&name) {
        return true;
    }
    if REACT_GLOBALS.contains(&name) {
        return true;
    }
    if TESTING_GLOBALS.contains(name) {
        return true;
    }
    // Underscore-prefixed (unused convention)
    if name.starts_with('_') {
        return true;
    }
    false
}

fn line_looks_like_code(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    // Code keyword prefix
    for prefix in CODE_PREFIXES {
        if trimmed.starts_with(prefix) {
            return true;
        }
    }

    // Check word count — prose has many words
    let word_count = trimmed.split_whitespace().count();
    if word_count > 6 {
        return false;
    }

    // Punctuation density — code has >= 2 punctuation chars
    let punct_count = trimmed
        .chars()
        .filter(|c| matches!(c, ';' | ',' | '.' | '=' | '(' | ')' | '{' | '}' | '[' | ']' | '<' | '>' | ':' | '|' | '&' | '?' | '!' | '+' | '-' | '*' | '/' | '%'))
        .count();
    if punct_count >= 2 {
        return true;
    }

    false
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undefined_variable_detected() {
        let code = r#"
            function foo() {
                const x = 1;
                return x + undefinedVar;
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.iter().any(|w| w.contains("undefinedVar")));
    }

    #[test]
    fn defined_variables_not_flagged() {
        let code = r#"
            function foo() {
                const x = 1;
                const y = 2;
                return x + y;
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.is_empty(), "Expected no warnings, got: {:?}", warnings);
    }

    #[test]
    fn function_params_not_flagged() {
        let code = r#"
            function add(a: number, b: number): number {
                return a + b;
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.is_empty(), "Expected no warnings, got: {:?}", warnings);
    }

    #[test]
    fn arrow_function_params_not_flagged() {
        let code = r#"
            const items = [1, 2, 3];
            items.map((item) => item * 2);
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.iter().all(|w| !w.contains("item")), "item should not be flagged: {:?}", warnings);
    }

    #[test]
    fn object_destructuring_shorthand_not_flagged() {
        // Regression: E2E benchmark task-03-ts-trpc emitted 6 FPs, all on
        // the binding name `input` destructured from `opts`:
        //   const { input } = opts;
        //   return { where: { id: input.id }, data: input };
        // Root cause: `shorthand_property_identifier` is in SKIP_NODE_TYPES
        // (correctly, for object literals) AND was being recursed-into by
        // collect_pattern_names looking for identifier children that don't
        // exist — the node itself IS the identifier. Fix extracts its text
        // directly when encountered inside a destructuring pattern.
        let code = r#"
            export const userRouter = trpc.router({
              create: publicProcedure
                .input(z.object({ name: z.string() }))
                .mutation(async (opts) => {
                  const { input } = opts;
                  return prisma.user.create({ data: input });
                }),
              update: publicProcedure
                .input(z.object({ id: z.number(), name: z.string() }))
                .mutation(async (opts) => {
                  const { input } = opts;
                  return prisma.user.update({
                    where: { id: input.id },
                    data: { name: input.name },
                  });
                }),
            });
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(
            warnings.iter().all(|w| !w.contains("input")),
            "destructured `input` binding must not be flagged, got: {:?}",
            warnings
        );
    }

    #[test]
    fn object_destructuring_longform_not_flagged() {
        // Companion to the shorthand test: long-form `{ key: value }`
        // destructuring must also collect the value-side binding.
        let code = r#"
            function handler() {
              const { data: payload, status: code } = response;
              return { payload, code };
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(
            warnings.iter().all(|w| !w.contains("payload") && !w.contains("code")),
            "long-form destructuring bindings must not be flagged, got: {:?}",
            warnings
        );
    }

    #[test]
    fn object_destructuring_default_value_not_flagged() {
        // `const { count = 0 } = opts` — assignment_pattern inside pair_pattern.
        let code = r#"
            function render(opts) {
              const { count = 0, label = "default" } = opts;
              return [count, label];
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(
            warnings.iter().all(|w| !w.contains("count") && !w.contains("label")),
            "destructuring with defaults must not be flagged, got: {:?}",
            warnings
        );
    }

    #[test]
    fn import_names_not_flagged() {
        let code = r#"
            import { useState, useEffect } from 'react';
            function Component() {
                const [state, setState] = useState(0);
                useEffect(() => {}, [state]);
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.iter().all(|w| !w.contains("useState") && !w.contains("useEffect")), "{:?}", warnings);
    }

    #[test]
    fn object_properties_not_flagged() {
        let code = r#"
            const obj = { name: "test", value: 42 };
            return obj.name + obj.value;
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.iter().all(|w| !w.contains("name") && !w.contains("value")), "{:?}", warnings);
    }

    #[test]
    fn jsx_component_not_flagged() {
        let code = r#"
            function App() {
                return <TodoList items={items} />;
            }
        "#;
        let warnings = extract_undefined_variables(code);
        // TodoList is a JSX component, items is a prop — shouldn't be "name" flagged
        assert!(warnings.iter().all(|w| !w.contains("TodoList")), "{:?}", warnings);
    }

    #[test]
    fn prose_returns_empty() {
        let prose = r#"
            This is a paragraph of English text that talks about code.
            It mentions variables like foo and bar but they're not real code.
            The function does something interesting with the data.
        "#;
        let warnings = extract_undefined_variables(prose);
        assert!(warnings.is_empty(), "Expected no warnings for prose, got: {:?}", warnings);
    }

    #[test]
    fn interface_properties_not_flagged() {
        let code = r#"
            interface Todo {
                id: number;
                title: string;
                completed: boolean;
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.is_empty(), "Expected no warnings, got: {:?}", warnings);
    }

    #[test]
    fn class_methods_not_flagged() {
        let code = r#"
            class Store {
                items: Item[] = [];
                
                addItem(item: Item) {
                    this.items.push(item);
                }
                
                getCount() {
                    return this.items.length;
                }
            }
        "#;
        let warnings = extract_undefined_variables(code);
        // 'item' is a parameter, 'Item' is a type — neither should be flagged
        assert!(warnings.iter().all(|w| !w.contains("item") && !w.contains("Item")), "{:?}", warnings);
    }

    #[test]
    fn catch_variable_not_flagged() {
        let code = r#"
            try {
                doSomething();
            } catch (error) {
                console.error(error.message);
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.iter().all(|w| !w.contains("error")), "{:?}", warnings);
    }

    #[test]
    fn react_hooks_not_flagged() {
        let code = r#"
            function Component() {
                const [count, setCount] = useState(0);
                const ref = useRef(null);
                const memo = useMemo(() => count * 2, [count]);
                useEffect(() => {
                    console.log(count);
                }, [count]);
            }
        "#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.is_empty(), "Expected no warnings, got: {:?}", warnings);
    }

    #[test]
    fn extract_type_names_works() {
        let code = r#"
            interface Todo { id: number; }
            type Status = "active" | "done";
            class Store { }
            enum Priority { Low, High }
        "#;
        let types = extract_type_names(code);
        assert!(types.contains("Todo"));
        assert!(types.contains("Status"));
        assert!(types.contains("Store"));
        assert!(types.contains("Priority"));
    }

    #[test]
    fn import_clause_collects_non_builtin_names() {
        // Regression: previously `import_statement` was checked in
        // collect_identifiers but it is not in DEFINITION_NODE_TYPES, so
        // the import_clause dispatch never fired. Names that weren't in the
        // builtin skip-list (e.g. Zod's `promiseType`) leaked through and
        // were flagged as undefined.
        let code = "// Using zod\nimport { promiseType } from 'zod';\n\npromiseType()\n";
        let warnings = extract_undefined_variables(code);
        assert!(
            warnings.iter().all(|w| !w.contains("promiseType")),
            "expected promiseType to be collected from import_clause, got: {:?}",
            warnings
        );
    }

    #[test]
    fn spread_in_array_with_call_arg_flagged() {
        // Regression: DELULU typescript-undefinedvariable-f6121e231e99
        // projectListRoute is undefined but wasn't being flagged.
        // Context: spread + call + array literal with undefined identifier.
        let code = r#"import { index, route } from "@react-router/dev/routes";

export default [
  route("/shells", "routes/shells.tsx"),
  ...prefix("projects", [
    index(projectListRoute)
  ]),
];
"#;
        let warnings = extract_undefined_variables(code);
        assert!(
            warnings.iter().any(|w| w.contains("projectListRoute")),
            "projectListRoute should be flagged as undefined, got: {:?}",
            warnings
        );
    }

    #[test]
    fn f6121e231e99_full_fim_concatenation_flagged() {
        // Regression: DELULU f6121e231e99.
        // Reproduces exact prompt+hallucinated+suffix concatenation that
        // scan_response receives via warning_set in delulu_compare.
        // Reproduction of pipeline miss reported in DELULU debug output.
        let prompt = r#"import { index, layout, prefix, type RouteConfig, route } from "@react-router/dev/routes";

export default [
  layout("root", [
    route("/home", "routes/home.tsx"),
    route("/about", "routes/about.tsx"),
    route("/admin", [
      index("routes/admin/dashboard.tsx"),
    ]),
    ...prefix('projects', ["#;
        let hallucinated = "    index(projectListRoute)";
        let suffix = r#",
      route("/create", "routes/project/create-project.tsx"),
    ]),
  ]),
] satisfies RouteConfig;
"#;
        let full = format!("{}{}{}", prompt, hallucinated, suffix);
        let warnings = extract_undefined_variables(&full);
        assert!(
            warnings.iter().any(|w| w.contains("projectListRoute")),
            "projectListRoute should be flagged in full FIM concatenation, got: {:?}",
            warnings
        );
    }
}
