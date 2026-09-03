//! Tree-sitter based Rust scope analysis.
//!
//! Replaces the regex-based extract_rust_undefined_variables with proper AST
//! parsing (FORGE 2026 paper: deterministic AST analysis for 100% precision).
//!
//! Key advantage: tree-sitter only extracts structurally valid Rust identifiers,
//! naturally filtering prose contamination. English prose won't parse as valid
//! Rust → tree has ERROR nodes → we return empty.
//!
//! Additionally, AST traversal properly distinguishes definition sites (let
//! bindings, fn params, use imports, match patterns) from reference sites,
//! eliminating the false positives that regex word-boundary matching produces.

use std::collections::HashSet;
use tree_sitter::{Node, Parser};

// ── User-extendable Rust ecosystem type allow-list (council A7) ────────────
//
// COMMON_RUST_ECOSYSTEM_TYPES (chrono/serde/clap/tokio/uuid/etc.) is a
// static slice baked into the binary. Users with internal crates (custom
// error types, framework traits) cannot extend without recompiling. The
// `extra_rust_ecosystem_types` ScannerConfig field feeds this OnceCell
// at daemon startup; `is_common_rust_ecosystem_type` checks both. Empty
// by default — common crates are already covered by the static slice.

static EXTRA_RUST_ECOSYSTEM_TYPES: once_cell::sync::OnceCell<HashSet<String>> =
    once_cell::sync::OnceCell::new();

/// Populate the user-extendable Rust ecosystem type allow-list from
/// config. Called once at daemon startup. Subsequent calls are no-ops
/// (first-write-wins). Names are matched case-sensitively.
pub fn set_extra_rust_ecosystem_types(names: Vec<String>) {
    let _ = EXTRA_RUST_ECOSYSTEM_TYPES.set(names.into_iter().collect());
}

/// Check whether a Rust identifier should be treated as a known ecosystem
/// type (skipped by the undefined-variable check). True if the name is in
/// the built-in COMMON_RUST_ECOSYSTEM_TYPES OR the user-provided
/// `extra_rust_ecosystem_types` config list.
pub fn is_common_rust_ecosystem_type(name: &str) -> bool {
    COMMON_RUST_ECOSYSTEM_TYPES.contains(&name)
        || EXTRA_RUST_ECOSYSTEM_TYPES
            .get()
            .is_some_and(|set| set.contains(name))
}

// ─── Keyword / builtin sets ─────────────────────────────────────────────

/// Rust reserved words. Identifiers matching these are never flagged.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn",
    "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while",
    // Contextual keywords
    "union", "default", "raw", "macro_rules", "macro", "try", "box",
    // Primitive types
    "bool", "char", "str", "i8", "i16", "i32", "i64", "i128", "isize",
    "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "never",
    // Standard library modules
    "std", "core", "alloc",
];

/// Standard prelude types — always available, never hallucinated.
const RUST_PRELUDE_TYPES: &[&str] = &[
    "Option", "Result", "Some", "None", "Ok", "Err",
    "Vec", "String", "Box", "Arc", "Rc", "Cell", "RefCell",
    "Mutex", "RwLock", "HashMap", "HashSet", "BTreeMap", "BTreeSet",
    "VecDeque", "LinkedList", "BinaryHeap", "Cow",
    "Pin", "PhantomData", "MaybeUninit", "ManuallyDrop",
    "Ordering", "Range", "RangeInclusive", "RangeFrom", "RangeTo",
    "RangeFull", "Bound", "NonZeroU8", "NonZeroU16", "NonZeroU32",
    "NonZeroU64", "NonZeroU128", "NonZeroUsize", "NonZeroI8",
    "NonZeroI16", "NonZeroI32", "NonZeroI64", "NonZeroI128", "NonZeroIsize",
    "Default", "Clone", "Copy", "Debug", "Display",
    "PartialEq", "Eq", "PartialOrd", "Ord", "Hash",
    "From", "Into", "FromStr", "ToString", "AsRef", "AsMut",
    "Iterator", "IntoIterator", "ExactSizeIterator", "DoubleEndedIterator",
    "Drop", "Sized", "Send", "Sync", "Unpin",
    "Fn", "FnMut", "FnOnce",
];

/// Standard library types that appear in method call positions.
/// These are commonly used but not in the prelude — still never hallucinated.
const RUST_STDLIB_TYPES: &[&str] = &[
    "PathBuf", "Path", "File", "ExitCode", "Command", "Instant", "Duration",
    "SystemTime", "OsString", "OsStr", "Metadata", "OpenOptions",
    "BufReader", "BufWriter", "Read", "Write", "Seek", "Cursor",
    "Error", "ErrorKind", "IoSlice", "IoSliceMut",
    "JoinHandle", "Builder", "ThreadId", "LocalKey",
    "Once", "OnceLock", "Lazy",
    "Args", "Env", "VarError", "Vars",
    "Spawn", "Receiver", "Sender", "SyncSender",
    "ToSocketAddrs", "SocketAddr", "IpAddr", "Ipv4Addr", "Ipv6Addr",
    "TcpListener", "TcpStream", "UdpSocket",
    "Process", "Child", "Stdio", "ExitStatus",
    "AddrParseError", "ParseBoolError", "TryFromIntError", "TryFromCharError",
    "ParseIntError", "ParseFloatError", "CharTryFromError",
];

/// Standard library macros — always available.
const RUST_MACROS: &[&str] = &[
    "println", "eprintln", "print", "eprint", "dbg", "todo", "unimplemented",
    "unreachable", "panic", "assert", "assert_eq", "assert_ne",
    "debug_assert", "debug_assert_eq", "debug_assert_ne",
    "vec", "format", "write", "writeln",
    "include_str", "include_bytes", "include", "env", "concat",
    "stringify", "file", "line", "column", "module_path",
    "cfg", "matches", "compile_error", "thread_local",
    "asm", "global_asm", "naked_asm",
    "trace_macros", "log_syntax", "option_env",
    "choice", "matches2",
    "select", "spawn", "block_on",
];

/// Common crate names that are always available via use — never flagged.
/// These are commonly imported crates that won't appear in crates.io checks
/// as standalone crates (they're part of the standard distribution or
/// universally available in Rust projects).
const COMMON_CRATE_NAMES: &[&str] = &[
    "std", "core", "alloc", "proc_macro", "test", "proc_macro2",
    "syn", "quote", "serde", "serde_json", "tokio", "clap",
    "anyhow", "thiserror", "tracing", "log", "env_logger",
    "reqwest", "hyper", "axum", "actix",
    "chrono", "time", "uuid",
    "regex", "once_cell", "lazy_static",
    "rand", "base64", "hex", "sha2", "md5",
    "futures", "async_trait", "async_stream",
    "rusqlite", "sqlx", "diesel",
    "rust_decimal", "bigdecimal",
    "itertools", "either",
    "nom", "pest",
    "rayon", "crossbeam",
    "parking_lot",
];

// ─── Public API ──────────────────────────────────────────────────────────

/// Extract undefined Rust variables using tree-sitter AST parsing.
///
/// Returns a sorted, deduplicated list of variable names that are referenced
/// but not defined in scope. Returns empty vec if:
/// - Content fails to parse as valid Rust (prose detection)
/// - All referenced identifiers are defined or are keywords/builtins
pub fn extract_undefined_variables(content: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return vec![];
    }

    let tree = match parser.parse(content.as_bytes(), None) {
        Some(t) => t,
        None => return vec![],
    };

    let root = tree.root_node();

    // Prose detection: high error ratio → not valid Rust code
    if has_too_many_errors(root) {
        return vec![];
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

    // Tier 2.1 supplement: when `use <crate>;` is present, treat all
    // types from that crate (per symbol bundle) as defined. Without this,
    // type-name references like `UnixStream` in `use tokio; UnixStream.x()`
    // get flagged as undefined — but they ARE defined via the crate import.
    // Catches the BOTH-unique FP pattern on DELULU v2 Rust samples where
    // golden (SerializeMap) and halluc (SreializeMap) both got flagged
    // because neither was bound via `let`. After fix: golden's name is
    // in bundle → defined; halluc's typo → undefined → clean TRUE positive.
    add_crate_imported_types(content, &mut ctx.defined);

    let mut undefined: Vec<String> = ctx
        .referenced
        .difference(&ctx.defined)
        .filter(|n| n.len() >= 3)
        .filter(|n| !is_keyword_or_builtin(n))
        .cloned()
        .collect();

    undefined.sort();
    undefined.dedup();
    undefined
}

/// For each `use <crate>;` in content, look up the crate's types in the
/// local SymbolCache (bundle) and add top-level type names to `defined`.
/// Top-level = path has no dot (e.g., "UnixStream", not "UnixStream.connect").
/// Silent on cache miss — caller's existing fallback paths handle missing data.
fn add_crate_imported_types(content: &str, defined: &mut HashSet<String>) {
    use regex::Regex;
    use std::sync::OnceLock;
    static USE_CRATE_RE: OnceLock<Regex> = OnceLock::new();
    let re = USE_CRATE_RE.get_or_init(|| {
        // Match `use <crate>;` only — NOT `use <crate>::<Type>;`.
        // Bare crate import makes the crate name available; types still
        // need explicit handling but bundle lookup covers them.
        Regex::new(r"(?m)^\s*use\s+([a-z_][a-z0-9_]*)\s*;").unwrap()
    });

    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return,
    };

    for caps in re.captures_iter(content) {
        let crate_name = caps.get(1).unwrap().as_str();
        let library = format!("rust.{}", crate_name);
        let entries = cache.lookup_prefix(&library, "");
        for entry in entries {
            // Top-level types have no dot in path (e.g., "UnixStream",
            // not "UnixStream.connect"). Add only those to the defined set.
            if !entry.path.contains('.') {
                defined.insert(entry.path.clone());
            }
        }
    }
}

/// Extract all struct/enum/trait/union/type names from the content.
/// Used by rust_introspect to skip local types in method verification.
pub fn extract_type_names(content: &str) -> HashSet<String> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return HashSet::new();
    }

    let tree = match parser.parse(content.as_bytes(), None) {
        Some(t) => t,
        None => return HashSet::new(),
    };

    let root = tree.root_node();
    if has_too_many_errors(root) {
        return HashSet::new();
    }

    let source = content.as_bytes();
    let mut types = HashSet::new();
    collect_type_declarations(root, source, &mut types);
    types
}

// ─── Internal types ──────────────────────────────────────────────────────

struct CollectContext<'a> {
    defined: HashSet<String>,
    referenced: HashSet<String>,
    source: &'a [u8],
    source_lines: &'a [&'a str],
}

// ─── AST traversal ───────────────────────────────────────────────────────

/// Walk the AST collecting defined and referenced identifiers.
fn collect_identifiers(node: Node, ctx: &mut CollectContext) {
    let kind = node.kind();

    match kind {
        // Use declarations: all names inside are definitions (imports)
        "use_declaration" => {
            collect_all_identifiers_subtree(node, ctx.source, &mut ctx.defined);
            return; // Don't recurse further — fully handled
        }

        // Identifier in expression or pattern position
        "identifier" => {
            if let Ok(text) = node.utf8_text(ctx.source) {
                if is_definition_context(node) {
                    ctx.defined.insert(text.to_string());
                } else if !is_method_or_field_name(node) {
                    // Per-line prose filter: if the identifier is on a line that
                    // doesn't look like code, skip it. This catches prose words
                    // that tree-sitter's error recovery parses as identifiers
                    // when mixed with valid Rust code.
                    let row = node.start_position().row as usize;
                    let line_ok = row < ctx.source_lines.len()
                        && line_looks_like_code(ctx.source_lines[row]);
                    if line_ok {
                        ctx.referenced.insert(text.to_string());
                    }
                }
            }
        }

        // Type identifier (PascalCase types)
        "type_identifier" => {
            if let Ok(text) = node.utf8_text(ctx.source) {
                if is_type_definition_context(node) {
                    ctx.defined.insert(text.to_string());
                } else if !is_method_or_field_name(node) {
                    ctx.referenced.insert(text.to_string());
                }
            }
        }

        // Generic type parameters: <T, E> → T, E are definitions
        "type_parameters" => {
            collect_all_identifiers_subtree(node, ctx.source, &mut ctx.defined);
            return;
        }

        // Where clause type parameters
        "where_clause" => {
            // Don't collect types from where clause as references — they're constraints
            return;
        }

        // Attribute #[...] — identifiers inside are NOT references
        "attribute_item" | "inner_attribute_item" | "meta_item" => {
            return; // Skip entirely
        }

        // Comments — tree-sitter marks these as extra nodes, skip them
        "line_comment" | "block_comment" => {
            return;
        }

        // String literals — identifiers in strings are NOT references
        "string_literal" | "raw_string_literal" => {
            return;
        }

        // Macro invocation — recurse into children to find variable references
        // in macro args (e.g., println!("{}", undefined_var)). The macro name
        // itself is collected as a reference when visited as an identifier child.
        "macro_invocation" => {
            // Fall through to default recursion — collect identifiers inside
            // token_tree as references (they may be variable references)
        }

        _ => {}
    }

    // Recurse into children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_identifiers(child, ctx);
        }
    }
}

/// Collect all identifiers in a subtree into a target set.
/// Used for use declarations and type parameters.
/// Uses child_count/child (not named_child) to find ALL identifiers including
/// those inside scoped_identifier paths.
fn collect_all_identifiers_subtree<'a>(node: Node<'a>, source: &'a [u8], target: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if kind == "identifier" || kind == "type_identifier" {
            if let Ok(text) = n.utf8_text(source) {
                target.insert(text.to_string());
            }
        }
        for i in 0..n.child_count() {
            if let Some(child) = n.child(i) {
                stack.push(child);
            }
        }
    }
}

/// Collect struct/enum/trait/union/type declaration names.
fn collect_type_declarations(node: Node, source: &[u8], types: &mut HashSet<String>) {
    let kind = node.kind();

    match kind {
        "struct_item" | "enum_item" | "trait_item" | "union_item" | "type_item" => {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(text) = name.utf8_text(source) {
                    types.insert(text.to_string());
                }
            }
            // For enums, also collect variant names so they don't get flagged
            // as undefined when used in match arms (Command::Get => ...).
            if kind == "enum_item" {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "enum_variant" {
                            if let Some(vname) = child.child_by_field_name("name") {
                                if let Ok(text) = vname.utf8_text(source) {
                                    types.insert(text.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_type_declarations(child, source, types);
        }
    }
}

// ─── Context detection ──────────────────────────────────────────────────

/// Check if an identifier is a method/field name in a path expression.
/// These should NOT be treated as variable references.
/// Examples:
///   HashMap::new() → "new" is the name field of scoped_identifier
///   obj.method() → "method" is the field of field_expression
fn is_method_or_field_name(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };

    let field = get_field_name(parent, node);

    match parent.kind() {
        // HashMap::new() → "new" is a method name
        // dotenvy::dotenv() → skip both path (dotenvy) and name (dotenv)
        "scoped_identifier" => field == Some("name") || field == Some("path"),
        // std::fmt::Formatter → "Formatter" is the name of scoped_type_identifier
        // std::fmt::Result → nested scoped_type_identifier, each segment is a name/path
        "scoped_type_identifier" => field == Some("name") || field == Some("path"),
        // obj.method() → "method" is a field/method name
        "field_expression" => field == Some("field"),
        // Foo { field: value } → "field" is a struct field name, not a variable ref
        "field_initializer" => {
            // The identifier in key position is a field name.
            // In tree-sitter-rust, field_initializer has the field name as
            // its first child (field_name for the key).
            parent.child(0).map(|c| c.id() == node.id()).unwrap_or(false)
        }
        _ => false,
    }
}

/// Determine if an identifier node is in a definition context.
///
/// Definition contexts (the identifier is being declared):
/// - let pattern: `let x = ...`
/// - fn parameter: `fn foo(x: Type)`
/// - fn name: `fn foo()`
/// - const/static name
/// - for loop variable: `for x in iter`
/// - closure params: `|x|`
/// - match pattern bindings
/// - destructuring patterns: `let (a, b) = ...`
fn is_definition_context(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };

    let parent_kind = parent.kind();

    // Check direct definition contexts via field name
    let field = get_field_name(parent, node);

    match parent_kind {
        // let x = ... → x is definition
        "let_declaration" => field == Some("pattern"),

        // fn name: fn foo() → foo is definition
        "function_item" | "function_signature_item" => field == Some("name"),

        // const/static name
        "const_item" | "static_item" => field == Some("name"),

        // for x in iter → x is definition
        "for_statement" => field == Some("pattern"),

        // extern crate name
        "extern_crate_declaration" => field == Some("name"),

        // module name: mod foo
        "module_declaration" => field == Some("name"),

        // macro name
        "macro_definition" => field == Some("name"),

        // field name in struct: name: Type
        "field_declaration" => field == Some("name"),

        // Enum variant name: enum AppError { NotFound, BadRequest }
        // Without this, variant identifiers fall through to `referenced`
        // and get flagged as undefined when later used (AppError::BadRequest).
        "enum_variant" => field == Some("name"),

        // Closure parameter
        "closure_parameters" => true,

        // Simple parameter: (x: Type)
        "parameter" | "simple_parameter" => true,

        // Labeled parameter (extern blocks)
        "labeled_parameter" => true,

        // Inside any pattern node → binding (definition)
        _ if is_pattern_node(parent_kind) => true,

        _ => false,
    }
}

/// Check if a node kind is a pattern (destructuring/binding) node.
/// Identifiers inside patterns are definitions (bindings).
fn is_pattern_node(kind: &str) -> bool {
    matches!(
        kind,
        "tuple_pattern"
            | "struct_pattern"
            | "tuple_struct_pattern"
            | "ref_pattern"
            | "identifier_pattern"
            | "mut_pattern"
            | "slice_pattern"
            | "or_pattern"
            | "reference_pattern"
            | "captured_pattern"
            | "remaining_field_pattern"
            | "field_pattern"
            | "match_pattern"
    )
}

/// Determine if a type_identifier node is in a definition context.
fn is_type_definition_context(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };

    let field = get_field_name(parent, node);

    match parent.kind() {
        "struct_item" | "enum_item" | "trait_item" | "union_item" | "type_item" => {
            field == Some("name")
        }
        "module_declaration" => field == Some("name"),
        // impl blocks: impl Trait for Type — both are references not definitions
        // (they reference existing types, they don't define new ones)
        _ => false,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Get the field name of a child node within its parent.
fn get_field_name(parent: Node, child: Node) -> Option<&'static str> {
    for i in 0..parent.child_count() {
        if let Some(c) = parent.child(i) {
            if c.id() == child.id() {
                return parent.field_name_for_child(i as u32);
            }
        }
    }
    None
}

/// Check if the parse tree has too many error nodes (content is prose, not code).
fn has_too_many_errors(root: Node) -> bool {
    // Prose detection strategy:
    // 1. If the tree has errors AND very few structural Rust nodes (< 3),
    //    it's likely prose or mixed content — reject.
    // 2. If error ratio is high (> 30%), reject even for larger trees.
    // 3. Zero structural nodes → definitely not Rust code.
    let structural = count_structural_nodes(root);
    if structural == 0 {
        return true;
    }
    if root.has_error() && structural < 3 {
        return true;
    }
    let (errors, total) = count_errors(root);
    if total > 5 && (errors as f64 / total as f64) > 0.30 {
        return true;
    }
    false
}

/// Count nodes that represent real Rust structural constructs.
fn count_structural_nodes(node: Node) -> usize {
    let mut count = 0;
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if is_structural_node(kind) {
            count += 1;
        }
        for i in 0..n.child_count() {
            if let Some(child) = n.child(i) {
                stack.push(child);
            }
        }
    }
    count
}

fn is_structural_node(kind: &str) -> bool {
    matches!(
        kind,
        "let_declaration"
            | "function_item"
            | "function_signature_item"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "impl_item"
            | "use_declaration"
            | "const_item"
            | "static_item"
            | "module_declaration"
            | "type_item"
            | "call_expression"
            | "assignment_expression"
            | "if_expression"
            | "match_expression"
            | "for_statement"
            | "while_statement"
            | "return_expression"
            | "binary_expression"
            | "field_expression"
            | "method_call_expression"
            | "array_expression"
            | "tuple_expression"
            | "struct_expression"
            | "closure_expression"
            | "reference_expression"
            | "dereference_expression"
            | "index_expression"
            | "break_expression"
            | "continue_expression"
    )
}

fn count_errors(node: Node) -> (usize, usize) {
    let mut errors = 0usize;
    let mut total = 0usize;
    count_errors_recursive(node, &mut errors, &mut total);
    (errors, total)
}

fn count_errors_recursive(node: Node, errors: &mut usize, total: &mut usize) {
    *total += 1;
    if node.is_error() || node.is_missing() {
        *errors += 1;
        // Don't recurse into error nodes — they may contain many sub-errors
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            count_errors_recursive(child, errors, total);
        }
    }
}

/// Strip the contents of string literals (between unescaped `"..."`), keeping
/// the outer structure. Used by `line_looks_like_code` to count code tokens
/// without being thrown off by natural-language text inside format strings.
///
/// Example: `debug!("Starting async task #{}", id);` → `debug!("", id);`
/// Word count drops from 5 to 2 — correctly identified as code, not prose.
fn strip_string_contents_for_count(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut prev = '\0';
    for ch in s.chars() {
        if ch == '"' && prev != '\\' {
            in_str = !in_str;
            out.push('"');
        } else if !in_str {
            out.push(ch);
        }
        prev = ch;
    }
    out
}

/// Check if a source line looks like Rust code (not English prose).
/// Used to filter prose words that tree-sitter's error recovery parses as
/// identifiers when mixed with valid Rust code.
///
/// A line looks like code if it contains structural Rust punctuation or
/// starts with a Rust keyword.
fn line_looks_like_code(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    // Lines starting with Rust keywords are definitely code.
    // NOTE: single-char operator prefixes (`-`, `*`, `+`, `<`, `>`, `!`,
    // `.`, `&`, `|`, `=`, `@`, etc.) are intentionally EXCLUDED — they are
    // rare/invalid as Rust line-starters but extremely common as markdown
    // list/quote markers (`- item`, `* item`, `> quote`). The operator
    // substring check below catches code lines like `&foo` or `.method()`
    // that lack a keyword prefix but contain `::`, `=>`, etc.
    const CODE_PREFIXES: &[&str] = &[
        "fn ", "let ", "use ", "mod ", "pub ", "struct ", "enum ", "trait ",
        "impl ", "const ", "static ", "type ", "extern ", "unsafe ",
        "if ", "else", "match ", "for ", "while ", "loop ", "return",
        "self", "Self", "super", "crate", "async ", "await ", "move ",
        "//", "/*", "*/", "#[", "#!", "break", "continue",
    ];
    if CODE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
        return true;
    }

    // (2) Rust-specific operators almost never appear in prose.
    // Catches `HashMap::new()`, `|x| x * 2`, `Result<T, E>` without a prefix.
    if trimmed.contains("::")
        || trimmed.contains("=>")
        || trimmed.contains("->")
        || trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.contains("!=")
    {
        return true;
    }

    // (3) Prose rejection gates.
    // Trailing single `.` (sentence terminator). Rust paths use `.` between
    // identifiers but never trail with a single `.` (`..` range is fine).
    if trimmed.ends_with('.') && !trimmed.ends_with("..") {
        return false;
    }
    // Markdown list / quote markers — common in agent prose summaries.
    if trimmed.starts_with("- ")
        || trimmed.starts_with("* ")
        || trimmed.starts_with("> ")
    {
        return false;
    }
    // Backtick anywhere → markdown inline code (`Status`, `cargo test`).
    // Legitimate Rust source never contains a backtick character.
    if trimmed.contains('`') {
        return false;
    }
    // Wordy lines (>4 whitespace-separated tokens OUTSIDE string literals)
    // are prose. Stripping string contents first prevents macro calls like
    // `debug!("Starting async task #{}", task_sequence_id);` (5 raw tokens
    // but only 2 code tokens) from being misclassified as prose.
    let code_only = strip_string_contents_for_count(trimmed);
    let word_count = code_only.split_whitespace().count();
    if word_count > 4 {
        return false;
    }

    // (4) Code terminator suffix → short line ending in structural punctuation.
    if trimmed.ends_with(';')
        || trimmed.ends_with('{')
        || trimmed.ends_with('}')
        || trimmed.ends_with("()")
        || trimmed.ends_with(");")
        || trimmed.ends_with("),")
        || trimmed.ends_with("}]")
    {
        return true;
    }

    // (5) Fallback for very short non-keyword code: ≤2 tokens with multiple
    // code-punct chars (e.g., `arr[0]`, `x.y`, `*ptr`). Too short for prose.
    if word_count <= 2 {
        let punct_count = trimmed
            .chars()
            .filter(|&c| matches!(c, ';' | '{' | '}' | '(' | ')' | '[' | ']' | '=' | ':'))
            .count();
        if punct_count >= 2 {
            return true;
        }
    }

    false
}

/// Common method names that should never be flagged as undefined variables.
/// These are available on most types via std traits (Display, Clone, etc.)
/// or are extremely common container methods.
const RUST_COMMON_METHODS: &[&str] = &[
    "to_string", "to_owned", "to_lowercase", "to_uppercase", "to_ascii_lowercase",
    "to_ascii_uppercase", "as_str", "as_bytes", "as_path", "as_ref", "as_mut",
    "len", "is_empty", "is_none", "is_some", "is_ok", "is_err",
    "contains", "starts_with", "ends_with", "find", "rfind",
    "clone", "copy", "partial_cmp", "cmp",
    "iter", "iter_mut", "into_iter", "into_string",
    "push", "pop", "insert", "remove", "retain", "clear",
    "get", "get_mut", "entry", "or_insert", "or_default",
    "map", "filter", "for_each", "collect", "fold",
    "unwrap", "unwrap_or", "unwrap_or_default", "unwrap_or_else",
    "expect", "expect_err",
    "ok", "err", "ok_or", "ok_or_else",
    "and_then", "or_else", "map_err",
    "take", "replace", "borrow", "borrow_mut",
    "fmt", "debug", "display",
    "eq", "ne", "lt", "le", "gt", "ge",
    "hash", "default", "into", "try_into", "from", "try_from",
    "spawn", "block_on", "lock", "read", "write",
    "new", "with_capacity", "from_iter", "from_vec",
    "parse", "trim", "trim_start", "trim_end",
    "split", "split_whitespace", "lines", "chars", "bytes",
    "format", "join",
];

/// Common enum variant names used in CLI apps (clap subcommands etc.)
const COMMON_ENUM_VARIANTS: &[&str] = &[
    "Add", "Delete", "List", "Done", "Pending", "Completed", "Todo",
    "Init", "Build", "Run", "Test", "Clean", "Check", "Update",
    "Create", "Read", "Write", "Move", "Copy", "Rename",
    "Start", "Stop", "Pause", "Resume", "Cancel", "Reset",
];

fn is_keyword_or_builtin(name: &str) -> bool {
    // SCREAMING_SNAKE_CASE — constants and macros, not undefined variables.
    // Matches: ESCALATE, JSON, MAX_RETRIES, etc. (len>=2, all uppercase/_,
    // at least 2 uppercase chars).
    if name.len() >= 2
        && name.chars().all(|c| c.is_uppercase() || c == '_')
        && name.chars().filter(|c| c.is_uppercase()).count() >= 2
    {
        return true;
    }
    // Hex hash IDs — DELULU sample IDs (`cb4c2dfd1574236`), tool-call IDs
    // (`f5ad26cf2914400e`), request IDs. Never valid Rust identifiers.
    // Generalizes the single-entry `"f5ad26cf2914400e"` in COMMON_PROSE_WORDS.
    // 12+ chars, all ASCII hex digits. Shorter hex (e.g. `0xff`) doesn't
    // reach this path — the AST sees it as a numeric literal, not identifier.
    if name.len() >= 12 && name.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    RUST_KEYWORDS.contains(&name)
        || RUST_PRELUDE_TYPES.contains(&name)
        || RUST_STDLIB_TYPES.contains(&name)
        || RUST_MACROS.contains(&name)
        || COMMON_CRATE_NAMES.contains(&name)
        || RUST_COMMON_METHODS.contains(&name)
        || COMMON_ENUM_VARIANTS.contains(&name)
        || is_common_rust_ecosystem_type(name)
        || COMMON_PROSE_WORDS.contains(&name)
        || name.starts_with('_')
}

/// Common Rust ecosystem types imported from external crates — not defined
/// locally in every snippet but universally real. Prevents FPs when the
/// import statement is in a prior response not visible to the current scan.
const COMMON_RUST_ECOSYSTEM_TYPES: &[&str] = &[
    // chrono
    "DateTime", "Utc", "Local", "FixedOffset", "NaiveDateTime", "NaiveDate",
    "NaiveTime", "Duration", "TimeZone", "Datelike", "Timelike",
    // serde
    "Serialize", "Deserialize", "Serializer", "Deserializer",
    // clap
    "Parser", "Subcommand", "ArgAction", "ArgMatches", "Command",
    "Args", "ValueEnum", "ValueParser", "ArgGroup",
    // anyhow/thiserror
    "Result", "Error", "Context", "bail", "ensure",
    // tokio
    "Runtime", "Handle", "spawn", "block_on", "JoinHandle",
    // uuid
    "Uuid",
    // log/tracing
    "info", "warn", "error", "debug", "trace", "instrument",
    // reqwest
    "Client", "Response", "StatusCode",
    // serde_json
    "Value", "json",
    // regex
    "Regex", "RegexBuilder",
    // std::collections
    "HashMap", "HashSet", "BTreeMap", "BTreeSet", "VecDeque",
    "LinkedList",
    // std::sync
    "Arc", "Mutex", "RwLock", "Barrier", "Once", "Condvar",
    "OnceLock", "Lazy", "LazyLock",
    // std::io
    "Read", "Write", "BufRead", "Cursor", "BufReader", "BufWriter",
    "Stdin", "Stdout", "Stderr",
    // std::fs
    "File", "DirEntry", "OpenOptions", "Metadata",
    "Permissions", "FileType",
    // std::process
    "Command", "Stdio", "Child", "ExitStatus", "Output",
    "ChildStdin", "ChildStdout", "ChildStderr",
    // std::path
    "Path", "PathBuf",
    // std::net
    "TcpListener", "TcpStream", "UdpSocket", "IpAddr", "Ipv4Addr",
    "Ipv6Addr", "SocketAddr", "SocketAddrV4", "SocketAddrV6",
    // std::ffi
    "OsStr", "OsString", "CString", "CStr",
    // Common types
    "Error", "Errors", "Result", "Option", "Some", "None",
    "Ok", "Err", "Box", "Rc", "RefCell", "Cell",
    "Cow",
];

/// Common English/prose words that leak from LLM response metadata into
/// the scope checker. These are NOT Rust identifiers — they come from API
/// response descriptions, usage statistics, and chat metadata.
/// Root cause: extract_code_blocks_only strategy 3 passes prose through
/// filter_prose_lines. This is a band-aid; the real fix is cross-response
/// context tracking + better prose filtering.
const COMMON_PROSE_WORDS: &[&str] = &[
    "glm", "confidence", "completion", "completion_tokens_details",
    "positional", "assistant", "sound", "storage", "strings",
    "commands", "cli", "content", "choices", "message", "messages",
    "prompt_tokens", "completion_tokens", "total_tokens", "model",
    "created", "usage", "object", "role", "index",
    "reasoning_content", "tool_calls", "function", "name",
    "id", "seed", "system_fingerprint", "finish_reason",
    // API metadata field names that leak through streaming JSON
    "reasoning_tokens", "prompt_tokens_details", "cached_tokens",
    "request_id", "dependencies", "package",
    // clap derive macros — not in clap crate source, only generated
    "Parser", "Subcommand", "Args", "ValueEnum", "FromArgs",
    // anyhow macro — not in anyhow crate source as a function
    "bail",
    // English stop words that leak through prose contamination.
    // These are NEVER valid Rust identifiers.
    "the", "all", "but", "are", "can", "that", "this", "per", "used",
    "fix", "keep", "keeps", "let", "not", "and", "for", "with", "from",
    "into", "will", "was", "has", "had", "been", "were", "our", "their",
    "Manual", "chat", "produced", "rewrite", "render", "lib", "minimal",
    "operations", "newString", "spec", "user", "value", "toml", "surfaced",
    "Implementations", "Cargo", "friendly", "impls", "filePath", "deps",
    "dep", "failures", "derive",
    // Common file/build terms
    "json", "Json", "NotFound", "next_id",
];

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_content_returns_empty() {
        assert!(extract_undefined_variables("").is_empty());
    }

    #[test]
    fn prose_returns_empty() {
        let prose = "The quick brown fox jumps over the lazy dog. \
                     This is English text that should not parse as Rust.";
        assert!(extract_undefined_variables(prose).is_empty());
    }

    #[test]
    fn undefined_variable_detected() {
        let code = r#"
            fn main() {
                let x = 5;
                println!("{}", undefined_var);
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(result.contains(&"undefined_var".to_string()));
    }

    #[test]
    fn defined_variables_not_flagged() {
        let code = r#"
            fn main() {
                let x = 5;
                let y = x + 1;
                println!("{}", y);
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(!result.contains(&"x".to_string()));
        assert!(!result.contains(&"y".to_string()));
    }

    #[test]
    fn function_params_not_flagged() {
        let code = r#"
            fn process(data: String, count: i32) -> i32 {
                count + data.len() as i32
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(!result.contains(&"data".to_string()));
        assert!(!result.contains(&"count".to_string()));
    }

    #[test]
    fn use_imports_not_flagged() {
        let code = r#"
            use std::collections::HashMap;
            use std::io::Read;
            fn main() {
                let map: HashMap<String, i32> = HashMap::new();
            }
        "#;
        let result = extract_undefined_variables(code);
        // HashMap, Read, String, i32 are all defined/keywords
        assert!(result.is_empty() || result.iter().all(|n| n.len() < 3));
    }

    #[test]
    fn grouped_imports_not_flagged() {
        let code = r#"
            use std::io::{Read, Write, BufRead};
            fn main() {
                let _ = Read;
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(!result.contains(&"Read".to_string()));
        assert!(!result.contains(&"Write".to_string()));
        assert!(!result.contains(&"BufRead".to_string()));
    }

    #[test]
    fn match_arm_bindings_not_flagged() {
        let code = r#"
            fn process(result: Result<i32, String>) -> i32 {
                match result {
                    Ok(value) => value,
                    Err(msg) => {
                        eprintln!("{}", msg);
                        0
                    }
                }
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(!result.contains(&"value".to_string()));
        assert!(!result.contains(&"msg".to_string()));
    }

    #[test]
    fn closure_params_not_flagged() {
        let code = r#"
            fn main() {
                let nums = vec![1, 2, 3];
                let doubled: Vec<i32> = nums.iter().map(|x| x * 2).collect();
            }
        "#;
        let result = extract_undefined_variables(code);
        // x is closure param, should not be flagged
        assert!(!result.contains(&"x".to_string()));
    }

    #[test]
    fn stdlib_types_not_flagged() {
        let code = r#"
            use std::fs::File;
            use std::path::PathBuf;
            fn open(path: PathBuf) -> File {
                File::create(path).unwrap()
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(result.is_empty() || result.iter().all(|n| n.len() < 3));
    }

    #[test]
    fn extract_type_names_finds_structs_enums() {
        let code = r#"
            struct Todo {
                title: String,
            }
            enum Status {
                Pending,
                Done,
            }
            trait Storage {}
        "#;
        let types = extract_type_names(code);
        assert!(types.contains("Todo"));
        assert!(types.contains("Status"));
        assert!(types.contains("Storage"));
    }

    #[test]
    fn string_contents_not_flagged() {
        let code = r#"
            fn main() {
                let msg = "hello world foo bar";
                println!("{}", msg);
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(!result.contains(&"hello".to_string()));
        assert!(!result.contains(&"world".to_string()));
    }

    #[test]
    fn attribute_args_not_flagged() {
        let code = r#"
            #[derive(Debug, Clone)]
            struct Config {
                name: String,
            }
        "#;
        let result = extract_undefined_variables(code);
        // Debug and Clone are in attribute — should not be flagged
        assert!(!result.contains(&"Debug".to_string()));
        assert!(!result.contains(&"Clone".to_string()));
    }

    // ─── Prose contamination regression tests (task-001 benchmark) ───────
    // Agent summary prose with backticked code mentions previously leaked
    // Status/TodoList/Cargo/Actually/etc. into the undefined-variable set.

    #[test]
    fn agent_summary_prose_does_not_flag_backticked_words() {
        // Verbatim from task-001-rust-todo-cli benchmark — agent's final
        // summary, pure markdown prose with inline code mentions.
        let prose = r#"Done. Task 001 complete.

**Deliverables**
- `Cargo.toml` - clap v4 (derive+env), serde, serde_json, chrono, dirs, anyhow
- `src/models.rs` - `Status` enum (serde lowercase), `Todo` struct, `TodoList` with add/complete/delete/filter + 4 tests
- `src/commands.rs` - `add`/`complete`/`delete`/`list` handlers, `CommandOutcome` enum, 5 tests
- `src/main.rs` - clap CLI, `--data-file` override (also env `TODO_RS_DATA_FILE`)

**Verification**
- `cargo build --release` - clean
- `cargo test` - **14/14 pass**
"#;
        let result = extract_undefined_variables(prose);
        assert!(
            !result.contains(&"Status".to_string()),
            "Status must not be flagged from prose; got {:?}",
            result
        );
        assert!(
            !result.contains(&"TodoList".to_string()),
            "TodoList must not be flagged from prose; got {:?}",
            result
        );
        assert!(
            !result.contains(&"Cargo".to_string()),
            "Cargo must not be flagged from prose; got {:?}",
            result
        );
        assert!(
            !result.contains(&"CommandOutcome".to_string()),
            "CommandOutcome must not be flagged from prose; got {:?}",
            result
        );
    }

    #[test]
    fn short_prose_lines_rejected() {
        // Common LLM "thinking aloud" prose patterns that previously passed
        // the weak punct_count >= 2 check.
        let prose = r#"
Actually, this works.
Wait, let me think.
Two: define Status.
Specification ends here.
Carefully documented.
Can and are concerns.
"#;
        let result = extract_undefined_variables(prose);
        for word in
            &["Actually", "Wait", "Two", "Specification", "Carefully", "concerns", "documented"]
        {
            assert!(
                !result.contains(&word.to_string()),
                "prose word `{}` must not be flagged; got {:?}",
                word,
                result
            );
        }
    }

    #[test]
    fn hex_hash_ids_not_flagged() {
        // DELULU sample IDs and tool-call request IDs leaked from API
        // response metadata. Generalized hex check replaces the single
        // entry in COMMON_PROSE_WORDS.
        let code = r#"
            fn main() {
                let id = cb4c2dfd1574236;
                let req = dc0060b55bb4883;
                process(f5ad26cf2914400e);
            }
        "#;
        let result = extract_undefined_variables(code);
        assert!(
            !result.iter().any(|n| n.contains("cb4c2dfd1574236")),
            "14-char hex ID must not be flagged; got {:?}",
            result
        );
        assert!(
            !result.iter().any(|n| n.contains("dc0060b55bb4883")),
            "14-char hex ID must not be flagged; got {:?}",
            result
        );
        assert!(
            !result.iter().any(|n| n.contains("f5ad26cf2914400e")),
            "16-char hex ID must not be flagged; got {:?}",
            result
        );
    }

    #[test]
    fn short_code_lines_still_accepted() {
        // Regression guard: tightening prose filter must not reject short
        // valid Rust lines that lack a keyword prefix.
        let code = r#"
            fn main() {
                foo();
                bar.x();
                arr[0];
                HashMap::new();
            }
        "#;
        let result = extract_undefined_variables(code);
        // foo, bar, arr are undefined → must be flagged. The fix must not
        // over-filter and kill recall on real code.
        assert!(
            result.contains(&"foo".to_string()),
            "foo() must still be flagged; got {:?}",
            result
        );
        assert!(
            result.contains(&"bar".to_string()),
            "bar.x() must still be flagged; got {:?}",
            result
        );
        assert!(
            result.contains(&"arr".to_string()),
            "arr[0] must still be flagged; got {:?}",
            result
        );
    }

    #[test]
    fn line_looks_like_code_prose_gates() {
        // Direct unit test for the per-line filter to lock in the gates.
        assert!(!line_looks_like_code("Actually, this works."));
        assert!(!line_looks_like_code("Wait, let me think."));
        assert!(!line_looks_like_code("Two: define Status."));
        assert!(!line_looks_like_code("- `Cargo.toml` - clap v4"));
        assert!(!line_looks_like_code("`Status` enum (serde lowercase)"));
        assert!(!line_looks_like_code("Done. Task 001 complete."));
        // Code-shape lines still pass:
        assert!(line_looks_like_code("foo();"));
        assert!(line_looks_like_code("bar.x();"));
        assert!(line_looks_like_code("HashMap::new();"));
        assert!(line_looks_like_code("let x = 5;"));
        assert!(line_looks_like_code("return result;"));
        assert!(line_looks_like_code("arr[0]"));
    }

    #[test]
    fn macro_call_with_format_string_still_flagged() {
        // Regression guard: `debug!("...long format string...", id)` must
        // still be recognized as code despite having many whitespace tokens
        // inside the string literal. Without strip_string_contents_for_count,
        // the word-count gate rejected this line and `task_sequence_id` was
        // no longer flagged (DELULU rust-undefinedvariable-84886328e06f
        // regression).
        let code = r#"fn main() {
    debug!("Starting async task #{}", task_sequence_id);
}"#;
        let result = extract_undefined_variables(code);
        assert!(
            result.contains(&"task_sequence_id".to_string()),
            "task_sequence_id inside debug!() must be flagged; got {:?}",
            result
        );
        // Direct line-check guard:
        assert!(line_looks_like_code(
            r#"debug!("Starting async task #{}", task_sequence_id);"#
        ));
    }

    #[test]
    fn is_common_rust_ecosystem_type_recognises_builtins() {
        // Sanity: built-in static slice still resolves after introducing
        // the helper + EXTRA_RUST_ECOSYSTEM_TYPES OnceCell.
        assert!(is_common_rust_ecosystem_type("DateTime"));
        assert!(is_common_rust_ecosystem_type("Serialize"));
        assert!(is_common_rust_ecosystem_type("HashMap"));
        assert!(is_common_rust_ecosystem_type("JoinHandle"));
        assert!(is_common_rust_ecosystem_type("PathBuf"));
    }

    #[test]
    fn is_common_rust_ecosystem_type_rejects_unrelated() {
        assert!(!is_common_rust_ecosystem_type("totally_unknown_type"));
        assert!(!is_common_rust_ecosystem_type(""));
    }

    #[test]
    fn set_extra_rust_ecosystem_types_extends_list_first_write_wins() {
        // OnceCell semantics: first call wins. Use unique marker to avoid
        // colliding with other tests that might call set_.
        let marker = "anubis_a7_rust_marker_xyz";
        super::set_extra_rust_ecosystem_types(vec![marker.to_string()]);
        assert!(
            is_common_rust_ecosystem_type(marker),
            "user-provided extra_rust_ecosystem_types should be honored"
        );
        // Second call should NOT overwrite (OnceCell first-write-wins).
        super::set_extra_rust_ecosystem_types(vec!["anubis_a7_rust_second_qwerty".to_string()]);
        assert!(
            is_common_rust_ecosystem_type(marker),
            "OnceCell first-write-wins: original marker should still be present"
        );
    }
}
