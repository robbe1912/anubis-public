//! Go tree-sitter AST-based scope analysis.
//!
//! Replaces regex-based extract_go_undefined_variables with proper AST
//! parsing. Follows the same proven architecture as rust_ast_extractor
//! and ts_ast_extractor:
//!   1. Parse content with tree-sitter Go grammar
//!   2. Prose detection (structural node count + error ratio)
//!   3. Per-line code-likeness filter
//!   4. Collect defined identifiers (func/type/var/const/param/import)
//!   5. Collect referenced identifiers (not in skip contexts)
//!   6. Return referenced - defined - builtins as "hallucinated"

use std::collections::HashSet;
use tree_sitter::{Node, Parser};

// ─── Language-specific sets ─────────────────────────────────────────────

/// Go reserved keywords — never flagged as undefined.
const GO_KEYWORDS: &[&str] = &[
    "break", "case", "chan", "const", "continue", "default", "defer",
    "else", "fallthrough", "for", "func", "go", "goto", "if", "import",
    "interface", "map", "package", "range", "return", "select", "struct",
    "switch", "type", "var",
];

/// Go builtin functions — always available, never hallucinated.
const GO_BUILTINS: &[&str] = &[
    "append", "cap", "close", "complex", "copy", "delete", "imag",
    "len", "make", "new", "panic", "print", "println", "real", "recover",
    "error", "bool", "byte", "rune", "uintptr",
    "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64",
    "float32", "float64", "complex64", "complex128",
    "string", "any", "comparable",
    "true", "false", "nil", "iota",
    // Common Go variable names — ubiquitous, never hallucinated.
    "err", "ok", "ctx", "req", "resp", "res", "buf", "key", "val", "value",
    "lis", "ln", "srv", "s", "n", "w", "r", "p", "v", "k", "i", "j",
    "task", "job", "msg", "item", "obj", "data", "result", "out",
    "log", "logger", "db", "conn", "tx", "query", "stmt",
    "config", "cfg", "opts", "args", "params",
    "server", "client", "handler", "middleware", "router",
    "service", "repo", "store", "cache", "pool",
];

/// Common Go stdlib package names — used in selector expressions.
const GO_STDLIB: &[&str] = &[
    "fmt", "os", "io", "strings", "strconv", "errors", "time",
    "context", "sync", "sort", "path", "filepath", "bytes", "bufio",
    "encoding", "json", "xml", "binary", "net", "http", "url", "rpc",
    "crypto", "hash", "math", "rand", "regexp", "unicode", "utf8",
    "reflect", "unsafe", "runtime", "testing", "log", "flag",
    "database", "sql", "exec", "signal", "syscall", "atomic",
    "mutex", "pool", "waitgroup", "once", "map", "array", "slice",
    "slices", "maps", "cmp", "iter",
    // Common third-party packages
    "gin", "gorm", "echo", "fiber", "chi", "mux",
    "zap", "slog", "viper", "cobra", "pflag",
    "yaml", "toml", "ini", "env",
    "uuid", "jwt", "bcrypt", "sha256", "md5",
    "pb", "proto", "grpc", "protobuf",
    "redis", "mongo", "pgx", "pgtype",
    "validator", "openapi", "swagger",
    "dagger", "ent", "sqlc", "squirrel",
    "testify", "assert", "require", "mock", "gomock",
    "httptest", "iotest", "bytes", "strings",
];

/// Common method names that are never hallucinated (from builtin types/interfaces).
const GO_COMMON_METHODS: &[&str] = &[
    "String", "Format", "Error", "Read", "Write", "Close", "Open",
    "Flush", "Seek", "Len", "Cap", "Get", "Set", "Add", "Delete",
    "Has", "Contains", "Find", "Index", "Last", "First", "Push", "Pop",
    "Insert", "Remove", "Sort", "Reverse", "Copy", "Clone", "Append",
    "Slice", "Keys", "Values", "Range", "Next", "Prev", "Count",
    "Error", "Unwrap", "Is", "As", "Unwrap",
    "ServeHTTP", "Handle", "HandleFunc", "Listen", "ListenAndServe",
    "Do", "Get", "Post", "Put", "Patch", "Delete", "Head",
    "Walk", "WalkDir", "Glob", "ReadFile", "WriteFile",
    "Print", "Printf", "Println", "Sprint", "Sprintf", "Fprint", "Fprintf",
    "Scan", "Scanf", "Scanln", "Sscan", "Sscanf",
    "Parse", "ParseInt", "ParseFloat", "ParseBool", "ParseUint",
    "Format", "FormatInt", "FormatFloat", "FormatBool",
    "Atoi", "Itoa",
    "New", "Must", "Try",
];

/// Tree-sitter node types to skip entirely (strings, comments, etc.).
const SKIP_NODE_TYPES: &[&str] = &[
    "comment",
    "line_comment",
    "block_comment",
    "raw_string_literal",
    "interpreted_string_literal",
    "rune_literal",
    "int_literal",
    "float_literal",
    "imaginary_literal",
];

/// Node types whose "name" field is a definition site.
const DEFINITION_NODE_TYPES: &[&str] = &[
    "function_declaration",
    "method_declaration",
    "type_spec",
];

/// Structural node types — presence indicates real code.
const STRUCTURAL_NODE_TYPES: &[&str] = &[
    "function_declaration",
    "method_declaration",
    "type_declaration",
    "type_spec",
    "var_declaration",
    "const_declaration",
    "import_declaration",
    "assignment_statement",
    "return_statement",
    "if_statement",
    "for_statement",
    "switch_statement",
    "expression_statement",
    "call_expression",
    "composite_literal",
    "func_literal",
    "short_var_declaration",
    "block",
    "source_file",
    "package_clause",
];

/// Code line prefix keywords — lines starting with these look like code.
const CODE_PREFIXES: &[&str] = &[
    "func ", "var ", "const ", "type ", "import ", "package ",
    "if ", "for ", "switch ", "case ", "default:", "return ",
    "go ", "defer ", "select ", "break", "continue", "fallthrough",
    "//", "/*", "*/", "} else", "case ",
];

/// Operator starts — lines starting with these are code.
const OPERATOR_STARTS: &[&str] = &["&", "|", "=", "+", "-", "*", "/", "%", "<", ">", "!", "^", ":="];

// ─── Main entry point ───────────────────────────────────────────────────

/// Extract undefined variables from Go code content.
/// Returns formatted warning strings for identifiers not defined in scope.
pub fn extract_undefined_variables(content: &str) -> Vec<String> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("failed to set Go grammar");

    let tree = parser.parse(content, None);
    let tree = match tree {
        Some(t) => t,
        None => return Vec::new(),
    };

    let root = tree.root_node();

    // Prose detection: if content isn't real Go code, return empty.
    if !is_real_go_code(root) {
        return Vec::new();
    }

    let source = content.as_bytes();
    let source_lines: Vec<&str> = content.lines().collect();

    let mut ctx = CollectContext {
        defined: HashSet::new(),
        referenced: HashSet::new(),
        source,
        source_lines: &source_lines,
    };

    collect_identifiers(root, &mut ctx);

    // Compute undefined = referenced - defined - builtins.
    // Returns bare identifier names; the caller (forge_go.rs) formats the warning.
    let mut undefined = Vec::new();
    for name in &ctx.referenced {
        if ctx.defined.contains(name) {
            continue;
        }
        if is_keyword_or_builtin(name) {
            continue;
        }
        if name.starts_with('_') || name.len() < 3 {
            continue;
        }
        undefined.push(name.clone());
    }
    undefined.sort();
    undefined
}

/// Extract type names defined in the content (struct, interface, type aliases).
pub fn extract_type_names(content: &str) -> HashSet<String> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("failed to set Go grammar");

    let tree = parser.parse(content, None);
    let tree = match tree {
        Some(t) => t,
        None => return HashSet::new(),
    };

    let mut types = HashSet::new();
    let source = content.as_bytes();
    extract_type_names_subtree(tree.root_node(), &mut types, source);
    types
}

// ─── Collection context ────────────────────────────────────────────────

struct CollectContext<'a> {
    defined: HashSet<String>,
    referenced: HashSet<String>,
    source: &'a [u8],
    source_lines: &'a [&'a str],
}

// ─── Prose detection ────────────────────────────────────────────────────

fn is_real_go_code(root: Node) -> bool {
    let mut errors = 0u32;
    let mut total = 0u32;
    let mut structural = 0u32;
    count_errors_and_nodes(root, &mut errors, &mut total, &mut structural);

    // Reject if: no structural nodes (pure prose)
    if structural == 0 {
        return false;
    }
    // Reject if: high error rate AND few structural nodes
    if root.has_error() && structural < 3 {
        return false;
    }
    // Reject if: error ratio > 0.30
    if total > 5 && errors as f64 / total as f64 > 0.30 {
        return false;
    }
    true
}

fn count_errors_and_nodes(node: Node, errors: &mut u32, total: &mut u32, structural: &mut u32) {
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

    // Definition sites — collect the name as defined
    if DEFINITION_NODE_TYPES.contains(&kind) {
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.kind() == "identifier" {
                let text = node_text(name_node, ctx);
                if !text.is_empty() {
                    ctx.defined.insert(text);
                }
            }
        }
        // Recurse for body
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_identifiers(child, ctx);
            }
        }
        return;
    }

    // Import declaration — collect imported package names
    if kind == "import_declaration" {
        collect_go_imports(node, ctx);
        return;
    }

    // Var/const declarations — collect names
    if kind == "var_spec" || kind == "const_spec" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    let text = node_text(child, ctx);
                    if !text.is_empty() && text != "_" {
                        ctx.defined.insert(text);
                    }
                }
                // Stop at = (assignment)
                if child.kind() == "=" {
                    break;
                }
            }
        }
        // Recurse for value expressions
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_identifiers(child, ctx);
            }
        }
        return;
    }

    // Short var declaration: x := value
    if kind == "short_var_declaration" || kind == "assignment_statement" {
        // Left side identifiers are defined
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let ckind = child.kind();
                if ckind == "identifier" {
                    let text = node_text(child, ctx);
                    if !text.is_empty() && text != "_" {
                        // For := it's always a definition. For = it might be reassignment.
                        if kind == "short_var_declaration" {
                            ctx.defined.insert(text);
                        }
                    }
                } else if ckind == "identifier_list" {
                    // Multiple targets: x, y := ...
                    for j in 0..child.named_child_count() {
                        if let Some(id) = child.named_child(j) {
                            if id.kind() == "identifier" {
                                let text = node_text(id, ctx);
                                if !text.is_empty() && text != "_" {
                                    ctx.defined.insert(text);
                                }
                            }
                        }
                    }
                }
                collect_identifiers(child, ctx);
            }
        }
        return;
    }

    // Parameter declarations — names are defined
    if kind == "parameter_declaration" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.kind() == "identifier" {
                let text = node_text(name_node, ctx);
                if !text.is_empty() {
                    ctx.defined.insert(text);
                }
            }
        }
        return;
    }

    // Range clause: for k, v := range items — k and v are defined
    if kind == "range_clause" {
        // Collect left-side identifiers before the 'range' keyword
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let ckind = child.kind();
                if ckind == "identifier" {
                    let text = node_text(child, ctx);
                    if !text.is_empty() && text != "_" {
                        ctx.defined.insert(text);
                    }
                } else if ckind == "identifier_list" {
                    for j in 0..child.named_child_count() {
                        if let Some(id) = child.named_child(j) {
                            if id.kind() == "identifier" {
                                let text = node_text(id, ctx);
                                if !text.is_empty() && text != "_" {
                                    ctx.defined.insert(text);
                                }
                            }
                        }
                    }
                }
                // Recurse for the range expression (right side)
                collect_identifiers(child, ctx);
            }
        }
        return;
    }

    // For statement — recurse into children (range_clause handled above)
    if kind == "for_statement" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let ckind = child.kind();
                if ckind == "range_clause" || ckind == "short_var_declaration" {
                    // Extract the loop variables
                    collect_identifiers(child, ctx);
                } else {
                    collect_identifiers(child, ctx);
                }
            }
        }
        return;
    }

    // Identifier node — determine if reference or skip
    if kind == "identifier" {
        let text = node_text(node, ctx);

        // Skip if this is a method/field name in a selector expression
        if is_method_or_field_name(node) {
            return;
        }

        // Skip if in a type context
        if is_type_context(node) {
            return;
        }

        // Per-line code filter
        let row = node.start_position().row;
        if row < ctx.source_lines.len() {
            if !line_looks_like_code(ctx.source_lines[row]) {
                return;
            }
        }

        if !text.is_empty() && text != "_" {
            ctx.referenced.insert(text);
        }
        return;
    }

    // Field identifier in struct literal — skip (it's a field name, not a variable)
    if kind == "field_identifier" || kind == "field_declaration" {
        return;
    }

    // Recurse into all children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_identifiers(child, ctx);
        }
    }
}

// ─── Import collection ──────────────────────────────────────────────────

fn collect_go_imports<'a>(node: Node, ctx: &mut CollectContext<'a>) {
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            if child.kind() == "import_spec" {
                // import_spec has a path (string literal) and optional name
                // The package name is derived from the import path
                if let Some(path_node) = child.child_by_field_name("path") {
                    let path_text = node_text(path_node, ctx);
                    // Extract package name from path: "fmt" → fmt, "net/http" → http
                    let pkg_name = path_text
                        .trim_matches('"')
                        .rsplit('/')
                        .next()
                        .unwrap_or("");
                    if !pkg_name.is_empty() {
                        ctx.defined.insert(pkg_name.to_string());
                    }
                }
                // Check for aliased import: import f "fmt"
                if let Some(name_node) = child.child_by_field_name("name") {
                    let alias = node_text(name_node, ctx);
                    if !alias.is_empty() && alias != "." && alias != "_" {
                        ctx.defined.insert(alias);
                    }
                }
            }
        }
    }
}

// ─── Helper functions ───────────────────────────────────────────────────

fn node_text<'a>(node: Node, ctx: &CollectContext<'a>) -> String {
    node.utf8_text(ctx.source).unwrap_or("").to_string()
}

fn is_method_or_field_name(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };

    // selector_expression: pkg.Func or obj.Field — the field is the method/field name
    if parent.kind() == "selector_expression" {
        if let Some(field) = parent.child_by_field_name("field") {
            if field.id() == node.id() {
                return true;
            }
        }
    }

    // keyed_element: struct literal { Field: value } — Field is a field name.
    // tree-sitter-go nests the key inside a literal_element wrapper, so check both.
    if parent.kind() == "keyed_element" || parent.kind() == "literal_element" {
        if let Some(key) = parent.child_by_field_name("key") {
            if key.id() == node.id() {
                return true;
            }
        }
        // Fallback: first child is the key in both keyed_element and literal_element.
        if let Some(child_0) = parent.child(0) {
            if child_0.id() == node.id() {
                return true;
            }
        }
    }

    // field_declaration in struct — the name
    if parent.kind() == "field_declaration" {
        if let Some(name) = parent.child_by_field_name("name") {
            if name.id() == node.id() {
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
        "type_identifier" | "qualified_type" | "pointer_type"
        | "array_type" | "slice_type" | "map_type" | "channel_type"
        | "function_type" | "interface_type" | "struct_type"
        | "type_assertion" | "type_conversion"
    )
}

fn is_keyword_or_builtin(name: &str) -> bool {
    if GO_KEYWORDS.contains(&name) {
        return true;
    }
    if GO_BUILTINS.contains(&name) {
        return true;
    }
    if GO_STDLIB.contains(&name) {
        return true;
    }
    if GO_COMMON_METHODS.contains(&name) {
        return true;
    }
    false
}

fn line_looks_like_code(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return false;
    }

    // Keyword prefix check
    for prefix in CODE_PREFIXES {
        if trimmed.starts_with(prefix) {
            return true;
        }
    }

    // Operator start check
    for op in OPERATOR_STARTS {
        if trimmed.starts_with(op) {
            return true;
        }
    }

    // Word count: prose has > 6 words
    let word_count = trimmed.split_whitespace().count();
    if word_count > 6 {
        return false;
    }

    // Punctuation check: code has ≥ 2 structural punctuation
    let punct_count = trimmed.chars().filter(|c| {
        matches!(c, ';' | '{' | '}' | '(' | ')' | '<' | '>' | '=' | ':' | '.' | ',' | '[' | ']')
    }).count();
    punct_count >= 2
}

fn extract_type_names_subtree(node: Node, types: &mut HashSet<String>, source: &[u8]) {
    if node.kind() == "type_spec" {
        if let Some(name) = node.child_by_field_name("name") {
            if let Ok(text) = name.utf8_text(source) {
                types.insert(text.to_string());
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_type_names_subtree(child, types, source);
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undefined_variable_detected() {
        let code = r#"package main

func main() {
    undefined_var.Foo()
}
"#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.iter().any(|w| w.contains("undefined_var")), "got: {:?}", warnings);
    }

    #[test]
    fn prose_returns_empty() {
        let prose = r#"This is a description of how to use the Go programming language.
We will create a REST API with gin framework and gorm ORM.
The API should have CRUD endpoints for managing users.
"#;
        let warnings = extract_undefined_variables(prose);
        assert!(warnings.is_empty(), "prose should return empty, got: {:?}", warnings);
    }

    #[test]
    fn imports_not_flagged() {
        let code = r#"package main

import (
    "fmt"
    "net/http"
    "encoding/json"
)

func main() {
    fmt.Println("hello")
}
"#;
        let warnings = extract_undefined_variables(code);
        assert!(!warnings.iter().any(|w| w.contains("fmt")), "fmt should be defined");
        assert!(!warnings.iter().any(|w| w.contains("http")), "http should be defined");
        assert!(!warnings.iter().any(|w| w.contains("json")), "json should be defined");
    }

    #[test]
    fn function_definitions_not_flagged() {
        let code = r#"package main

func handler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
}

func main() {
    handler(nil, nil)
}
"#;
        let warnings = extract_undefined_variables(code);
        assert!(!warnings.iter().any(|w| w.contains("handler")), "handler should be defined");
        assert!(!warnings.iter().any(|w| w.contains("ResponseWriter")), "ResponseWriter should be skipped");
    }

    #[test]
    fn short_var_decl_not_flagged() {
        let code = r#"package main

func main() {
    x := 42
    y := x + 1
    _ = y
}
"#;
        let warnings = extract_undefined_variables(code);
        assert!(!warnings.iter().any(|w| w.contains("x")), "x should be defined");
        assert!(!warnings.iter().any(|w| w.contains("y")), "y should be defined");
    }

    #[test]
    fn type_definitions_collected() {
        let code = r#"package main

type User struct {
    Name string
    Age  int
}

type UserList []User

func main() {
    u := User{Name: "test"}
    _ = u
}
"#;
        let types = extract_type_names(code);
        assert!(types.contains("User"));
        assert!(types.contains("UserList"));
    }

    #[test]
    fn stdlib_not_flagged() {
        let code = r#"package main

import "fmt"

func main() {
    fmt.Println("hello")
    _ = len("test")
    _ = make([]int, 10)
}
"#;
        let warnings = extract_undefined_variables(code);
        assert!(warnings.is_empty(), "stdlib functions should not be flagged, got: {:?}", warnings);
    }

    #[test]
    fn struct_fields_not_flagged() {
        let code = r#"package main

type Config struct {
    Host string
    Port int
}

func main() {
    c := Config{}
    c.Host = "localhost"
    c.Port = 8080
}
"#;
        let warnings = extract_undefined_variables(code);
        // Host and Port are field names in selector expressions, should be skipped
        assert!(!warnings.iter().any(|w| w.contains("Host")), "Host should be field name");
        assert!(!warnings.iter().any(|w| w.contains("Port")), "Port should be field name");
    }

    #[test]
    fn keyed_element_field_not_flagged() {
        let code = r#"package main

type Foo struct {
    Bar int
    baz string
}

func main() {
    f := Foo{
        Bar: 42,
        baz: "hello",
    }
    _ = f
}
"#;
        let warnings = extract_undefined_variables(code);
        assert!(!warnings.iter().any(|w| w == "Bar"), "Bar should be composite literal key, got: {:?}", warnings);
        assert!(!warnings.iter().any(|w| w == "baz"), "baz should be composite literal key, got: {:?}", warnings);
    }

    #[test]
    fn range_variables_not_flagged() {
        let code = r#"package main

func main() {
    items := []string{"a", "b", "c"}
    for i, v := range items {
        _ = i
        _ = v
    }
}
"#;
        let warnings = extract_undefined_variables(code);
        assert!(!warnings.iter().any(|w| w.contains("i")), "range var i should be defined");
        assert!(!warnings.iter().any(|w| w.contains("v")), "range var v should be defined");
    }
}
