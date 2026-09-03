//! C# scope analysis via tree-sitter AST.
//!
//! Replaces regex-based `extract_undefined` (driven by `scope_extractor.rs`)
//! for C#. Falls back to the regex extractor on parse failure or prose input.
//!
//! Designed to eliminate false positives the regex extractor produces on:
//!   - anonymous object property labels (`new { Foo = 1 }`)
//!   - pattern-matching keywords (`not`, `and`, `or`, `when`)
//!   - lambda parameters (`(x, y) => ...`)
//!   - record primary constructors (`record R(string Name)`)
//!   - qualified namespace segments (`System.Uri`)

use std::collections::HashSet;
use std::sync::OnceLock;
use tree_sitter::{Node, Parser};
use tree_sitter_c_sharp::LANGUAGE;

// ---- Keyword / builtin sets ------------------------------------------------

static CSHARP_RESERVED_KEYWORDS: &[&str] = &[
    "abstract", "as", "async", "await", "base", "bool", "break", "byte",
    "case", "catch", "char", "checked", "class", "const", "continue",
    "decimal", "default", "delegate", "do", "double", "else", "enum",
    "event", "explicit", "extern", "false", "finally", "fixed", "float",
    "for", "foreach", "goto", "if", "implicit", "in", "int", "interface",
    "internal", "is", "lock", "long", "namespace", "new", "not", "null",
    "object", "operator", "or", "out", "override", "params", "partial",
    "private", "protected", "public", "readonly", "ref", "return", "sbyte",
    "sealed", "short", "sizeof", "stackalloc", "static", "string",
    "struct", "switch", "this", "throw", "true", "try", "typeof", "uint",
    "ulong", "unchecked", "unsafe", "ushort", "using", "var", "virtual",
    "void", "volatile", "while", "yield", "when", "and", "get", "set",
    "init", "value", "nameof", "global", "args", "let", "where", "select",
    "from", "orderby", "group", "by", "join", "into", "ascending",
    "descending", "equals", "remove", "add", "dynamic", "nint", "nuint",
    "alias", "managed", "unmanaged",
];

static CSHARP_PREDEFINED_TYPES: &[&str] = &[
    "bool", "byte", "sbyte", "char", "decimal", "double", "float", "int",
    "uint", "long", "ulong", "short", "ushort", "object", "string", "void",
    "var", "dynamic", "nint", "nuint",
];

static CSHARP_BCL_TYPE_ALIASES: &[&str] = &[
    "Boolean", "Byte", "SByte", "Char", "Decimal", "Double", "Single",
    "Int32", "UInt32", "Int64", "UInt64", "Int16", "UInt16", "String",
    "Object", "Void", "IntPtr", "UIntPtr", "DateTime", "DateTimeOffset",
    "TimeSpan", "Guid", "Task", "ValueTask", "CancellationToken",
    "IEnumerable", "IEnumerator", "IDictionary", "IList", "ICollection",
    "IReadOnlyList", "IReadOnlyCollection", "IReadOnlyDictionary",
    "IDisposable", "IComparable", "IEquatable", "IFormattable",
    "IConvertible", "ICloneable", "AsyncCallback", "IAsyncResult",
    "Dictionary", "List", "HashSet", "SortedSet", "SortedDictionary",
    "SortedList", "Queue", "Stack", "LinkedList", "ReadOnlyCollection",
    "Action", "Func", "Predicate", "Comparison", "Converter",
    "Tuple", "ValueTuple", "KeyValuePair", "Nullable", "Lazy",
    "Exception", "ArgumentException", "ArgumentNullException",
    "ArgumentOutOfRangeException", "InvalidOperationException",
    "NotImplementedException", "NotSupportedException", "NullReferenceException",
    "IndexOutOfRangeException", "OverflowException", "FormatException",
    "TimeoutException", "IOException", "ApplicationException",
    "SystemException", "AggregateException", "OperationCanceledException",
    "Type", "Math", "Console", "Convert", "Environment", "GC",
    "Activator", "AppDomain", "Attribute", "FlagsAttribute",
    "StringBuilder", "Regex", "Match", "Group", "Capture",
    "Uri", "HttpClient", "HttpResponseMessage", "HttpRequestMessage",
    "MediaTypeHeaderValue", "HttpContent", "Stream", "MemoryStream",
    "FileStream", "BufferedStream", "StreamReader", "StreamWriter",
    "BinaryReader", "BinaryWriter", "TextReader", "TextWriter",
    "Encoding", "Thread", "Mutex", "SemaphoreSlim",
    "ManualResetEvent", "AutoResetEvent", "Monitor", "Interlocked",
    "IServiceProvider", "IServiceCollection", "IServiceScope",
    // Common framework / library types frequently seen as type references
    // without explicit `using` aliases. Filtering these as built-in prevents
    // the AST extractor from flagging every reference to a widely-known
    // interface or base class as a hallucinated variable.
    "ILogger", "ILoggerFactory", "ILoggerProvider", "ILogEventEnricher",
    "IConfiguration", "IOptions", "IOptionsMonitor", "IOptionsSnapshot",
    "IHostBuilder", "IWebHostBuilder", "IHostApplicationLifetime",
    "IHostedService", "IWebHostEnvironment", "IApplicationLifetime",
    "DbContext", "DbSet", "DbContextOptions", "ModelBuilder", "EntityTypeBuilder",
    "ControllerBase", "Controller", "ActionResult", "IActionResult",
    "NotFound", "Ok", "BadRequest", "NoContent", "CreatedAtAction",
    "CreatedAtRoute", "BadRequestObjectResult", "NotFoundObjectResult",
    "OkObjectResult", "JsonResult", "ContentResult", "FileResult",
    "RedirectResult", "RedirectToActionResult", "RedirectToRouteResult",
    "AbstractValidator", "IValidator", "ValidationContext", "ValidationResult",
    "IRuleBuilder", "IRuleBuilderOptions", "RuleBuilder",
    "IPipelineBehavior", "IRequest", "IRequestHandler", "INotification",
    "INotificationHandler", "IMediator", "ISender", "IPublisher",
    "Mediator", "RequestHandlerDelegate", "RequestExceptionHandler",
    "IRequestExceptionAction", "IRequestExceptionHandler",
    "AsyncRetryPolicy", "RetryPolicy", "Policy", "PolicyResult",
    "ISyncPolicy", "IAsyncPolicy",
    "LogContext", "LogEventLevel", "LoggerConfiguration",
    "ActivitySource", "Activity", "ActivityStatusCode", "ActivityKind",
    "Stopwatch", "StringComparison", "StringSplitOptions",
    "BackgroundService", "Host", "HostBuilder",
    "IAsyncEnumerable", "IQueryable",
];

static CSHARP_COMMON_METHODS: &[&str] = &[
    "ToString", "GetHashCode", "GetType", "Equals", "CompareTo",
    "GetEnumerator", "Dispose", "Length", "Count", "Add", "Remove",
    "Contains", "Clear", "CopyTo", "IndexOf", "Insert", "FirstOrDefault",
    "Where", "Select", "OrderBy", "ToList", "ToArray", "First", "Last",
    "Any", "All", "Sum", "Min", "Max", "Average", "GroupBy", "Join",
    "Distinct", "Skip", "Take", "Reverse", "Concat", "Aggregate",
    "ElementAt", "Except", "Intersect", "Union", "SequenceEqual",
    "ToDictionary", "ToLookup", "ToHashSet", "AsEnumerable", "AsQueryable",
    "Cast", "OfType", "Zip", "Append", "Prepend", "DefaultIfEmpty",
    "Range", "Repeat", "Empty", "WriteLine", "Write", "ReadLine", "Read",
    "ReadKey", "Format", "Parse", "TryParse", "IsNullOrEmpty",
    "IsNullOrWhiteSpace", "Trim", "TrimStart", "TrimEnd", "Split",
    "Substring", "Replace", "LastIndexOf", "StartsWith", "EndsWith",
    "ToUpper", "ToLower", "PadLeft", "PadRight", "Compare",
    "CompareOrdinal", "Copy", "Intern", "Get", "Set", "Value", "Key",
    "Keys", "Values", "Print", "Log", "Info", "Warn", "Error", "Debug",
    "Trace", "Fatal", "Verbose", "Configure", "Build", "Run", "Start",
    "Stop", "Wait", "Result", "ContinueWith", "Delay", "WhenAll",
    "WhenAny", "FromResult", "CompletedTask", "RunSynchronously",
    "ConfigureAwait", "BeginInvoke", "EndInvoke", "Invoke", "DynamicInvoke",
    "Send", "Post", "Break", "Continue", "Map", "Bind", "To", "From",
    "With", "Use", "Apply", "SendAsync", "ReceiveAsync", "ConnectAsync",
    "DisconnectAsync", "ReadAsync", "WriteAsync", "FlushAsync",
    "CopyToAsync", "Name", "Id", "Date", "Time", "Item", "Items",
    "Errors", "IsValid", "Validate", "Next", "Current", "MoveNext",
    "Reset", "Throw", "ThrowIfNull", "EnumerateFiles", "EnumerateDirectories",
    "ReadAllText", "WriteAllText", "ReadAllLines", "WriteAllLines",
    "ReadAllBytes", "WriteAllBytes", "Exists", "Delete", "Create",
    "Open", "OpenRead", "OpenWrite", "AppendAllText", "AppendText",
    "AppendLine", "AppendFormat", "Append",
];

static CSHARP_PROSE_WORDS: &[&str] = &[
    "the", "and", "but", "for", "with", "from", "into", "onto", "this",
    "that", "these", "those", "have", "has", "had", "was", "were", "are",
    "been", "being", "would", "could", "should", "might", "must", "shall",
    "can", "may", "will", "their", "there", "they", "them", "then", "than",
    "what", "when", "where", "which", "while", "during", "before", "after",
    "above", "below", "between", "through", "without", "within", "across",
    "along", "around", "behind", "beside", "near", "over", "under",
    "task", "user", "users", "data", "value", "values", "info",
    "system", "code", "method", "function", "example", "note", "notes",
    "todo", "fixme", "test", "tests", "spec", "specs", "doc", "docs",
    "comment", "comments", "block", "statement", "expression",
    "instance", "type", "field", "property", "properties",
    "feature", "behavior", "implementation", "description", "summary",
    "review", "author", "version", "history", "change", "changes",
    "argument", "arguments", "exception", "exceptions", "error", "errors",
    "warning", "warnings", "build", "release", "deploy", "tag", "branch",
    "commit", "merge", "pull", "push", "checkout", "master", "develop",
    "right", "left", "first", "last", "next", "previous", "current",
    "following", "subsequent", "earlier", "later", "via", "per",
    "Output", "Result", "Command", "Query", "Handler", "Request",
    "Response", "Behavior", "Pipeline", "Notification", "Event",
];

fn reserved_keywords() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| CSHARP_RESERVED_KEYWORDS.iter().copied().collect())
}

fn predefined_types() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| CSHARP_PREDEFINED_TYPES.iter().copied().collect())
}

fn bcl_type_aliases() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| CSHARP_BCL_TYPE_ALIASES.iter().copied().collect())
}

fn common_methods() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| CSHARP_COMMON_METHODS.iter().copied().collect())
}

fn prose_words() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| CSHARP_PROSE_WORDS.iter().copied().collect())
}

const SKIP_NODE_TYPES: &[&str] = &[
    "comment", "line_comment", "block_comment",
    "string_literal", "character_literal", "integer_literal",
    "real_literal", "boolean_literal", "null_literal",
    "interpolated_string_expression", "interpolation", "escape_sequence",
    "string_content", "interpolation_start", "interpolation_quote",
    "interpolation_format_clause",
    "attribute_list", "type_parameter_list", "type_parameter_constraints_clause",
    "preproc_if", "preproc_directive", "preproc_message", "preproc_region",
    "preproc_end_region", "preproc_else", "preproc_endif", "preproc_def",
    "preproc_undef", "preproc_warning", "preproc_error",
    "modifier",
];

const NAMED_DEFINITION_TYPES: &[&str] = &[
    "class_declaration", "interface_declaration", "struct_declaration",
    "record_declaration", "enum_declaration", "delegate_declaration",
    "method_declaration", "constructor_declaration", "destructor_declaration",
    "operator_declaration", "conversion_operator_declaration",
    "property_declaration", "indexer_declaration", "event_declaration",
    "local_function_statement",
    "catch_declaration", "tuple_element",
];

const STRUCTURAL_NODE_TYPES: &[&str] = &[
    "class_declaration", "interface_declaration", "struct_declaration",
    "record_declaration", "enum_declaration", "method_declaration",
    "constructor_declaration", "property_declaration", "field_declaration",
    "namespace_declaration", "file_scoped_namespace_declaration",
    "variable_declaration", "local_declaration_statement",
    "if_statement", "for_statement", "foreach_statement", "while_statement",
    "return_statement", "switch_statement", "try_statement", "using_statement",
    "lock_statement", "expression_statement", "block", "declaration_list",
    "invocation_expression", "member_access_expression",
    "object_creation_expression", "source_file",
];

const CODE_PREFIXES: &[&str] = &[
    "using ", "namespace ", "class ", "interface ", "struct ", "record ",
    "enum ", "delegate ", "public ", "private ", "protected ", "internal ",
    "static ", "readonly ", "abstract ", "sealed ", "virtual ", "override ",
    "async ", "void ", "int ", "string ", "bool ", "var ", "double ",
    "float ", "decimal ", "long ", "char ", "byte ", "object ", "task ",
    "if ", "else ", "for ", "foreach ", "while ", "do ", "switch ", "case ",
    "default:", "return ", "throw ", "try ", "catch ", "finally ",
    "lock ", "yield ", "break", "continue", "goto ",
    "//", "/*", "*/", "} else", "else",
    "[Attribute", "[Test", "[Fact", "[Theory", "[Obsolete",
    "new ", "out ", "ref ", "params ",
    "Task<", "List<", "Dictionary<", "IEnumerable<", "IList<",
    "Func<", "Action<",
];

const OPERATOR_STARTS: &[&str] = &[
    "&", "|", "=", "+", "-", "*", "/", "%", "<", ">", "!", "^", "~", "?",
    ".", ":",
];

struct CollectContext<'a> {
    defined: HashSet<String>,
    referenced: HashSet<String>,
    source: &'a [u8],
    source_lines: &'a [&'a str],
}

// ---- Public API ----

/// Extract identifiers that look referenced-but-undefined in the given C# source.
/// Falls back to the regex extractor on parse failure or prose input.
pub fn extract_undefined_variables(content: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser.set_language(&LANGUAGE.into()).is_err() {
        return crate::scanner::forge_csharp::extract_csharp_undefined_variables_regex(content);
    }
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => {
            return crate::scanner::forge_csharp::extract_csharp_undefined_variables_regex(content);
        }
    };
    let root = tree.root_node();
    if !is_real_csharp_code(root) {
        return crate::scanner::forge_csharp::extract_csharp_undefined_variables_regex(content);
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

    let mut undefined: Vec<String> = Vec::new();
    for name in &ctx.referenced {
        if ctx.defined.contains(name) {
            continue;
        }
        if name.len() < 3 || name.starts_with('_') {
            continue;
        }
        if is_keyword_or_builtin(name) {
            continue;
        }
        undefined.push(name.clone());
    }
    undefined.sort();
    undefined.dedup();
    undefined
}

/// Extract names of declared types (class/interface/struct/enum/record).
pub fn extract_type_names(content: &str) -> HashSet<String> {
    let mut parser = Parser::new();
    if parser.set_language(&LANGUAGE.into()).is_err() {
        return HashSet::new();
    }
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return HashSet::new(),
    };
    let mut types = HashSet::new();
    extract_type_names_subtree(tree.root_node(), &mut types, content.as_bytes());
    types
}

// ---- Prose detection ----

fn is_real_csharp_code(root: Node) -> bool {
    let mut errors = 0usize;
    let mut total = 0usize;
    let mut structural = 0usize;
    count_errors_and_nodes(root, &mut errors, &mut total, &mut structural);
    if structural == 0 {
        return false;
    }
    if root.has_error() && structural < 3 {
        return false;
    }
    if total > 5 && errors as f64 / total as f64 > 0.30 {
        return false;
    }
    true
}

fn count_errors_and_nodes(
    node: Node,
    errors: &mut usize,
    total: &mut usize,
    structural: &mut usize,
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
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            count_errors_and_nodes(cursor.node(), errors, total, structural);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ---- Recursive identifier collection ----

fn collect_identifiers(node: Node, ctx: &mut CollectContext) {
    let kind = node.kind();

    if SKIP_NODE_TYPES.contains(&kind) {
        return;
    }

    // Definition nodes: collect name field, recurse into children.
    if NAMED_DEFINITION_TYPES.contains(&kind) {
        if let Some(name_node) = node.child_by_field_name("name") {
            collect_name_identifier(name_node, ctx);
        }
        recurse_all_children(node, ctx);
        return;
    }

    match kind {
        // using_directive: every identifier in the directive is a namespace
        // or alias name (e.g. `using MediatR;`, `using X = System.Uri;`,
        // `using static System.Math;`). They are imports, not references —
        // treat all identifier children as defined.
        "using_directive" => {
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "identifier" {
                        if let Ok(text) = child.utf8_text(ctx.source) {
                            ctx.defined.insert(text.to_string());
                        }
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            return;
        }

        // variable_declarator: name may be identifier (single) or tuple_pattern
        // (deconstruction). Recurse into RHS, skipping the name field.
        "variable_declarator" => {
            let name_id = handle_designation_name(node.child_by_field_name("name"), ctx);
            recurse_children_skipping(node, ctx, name_id);
            return;
        }

        // parameter: name -> defined, type/default -> references.
        "parameter" => {
            let name_id = handle_designation_name(node.child_by_field_name("name"), ctx);
            recurse_children_skipping(node, ctx, name_id);
            return;
        }

        // implicit_parameter: a single identifier in lambda `(x) => ...`.
        "implicit_parameter" => {
            if let Ok(text) = node.utf8_text(ctx.source) {
                ctx.defined.insert(text.to_string());
            }
            return;
        }

        // foreach_statement: `left` is loop variable, `right` is collection.
        "foreach_statement" => {
            let left_id = handle_designation_name(node.child_by_field_name("left"), ctx);
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    if Some(cursor.node().id()) != left_id {
                        collect_identifiers(cursor.node(), ctx);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            return;
        }

        // declaration_pattern: `Type identifier` in is-pattern.
        "declaration_pattern" => {
            let name_id = handle_designation_name(node.child_by_field_name("name"), ctx);
            recurse_children_skipping(node, ctx, name_id);
            return;
        }

        // recursive_pattern: optional `name` designation + subpatterns.
        "recursive_pattern" => {
            let name_id = handle_designation_name(node.child_by_field_name("name"), ctx);
            recurse_children_skipping(node, ctx, name_id);
            return;
        }

        // parenthesized_variable_designation: `(x, y)` in deconstruction.
        "parenthesized_variable_designation" => {
            collect_designation_identifiers(node, ctx);
            return;
        }

        // Identifier reference: respect line-level filter + skip contexts.
        "identifier" => {
            if is_definition_site(node) || is_member_name(node) {
                return;
            }
            if let Ok(text) = node.utf8_text(ctx.source) {
                let row = node.start_position().row;
                let line = ctx.source_lines.get(row).copied().unwrap_or("");
                if line_looks_like_code(line) {
                    ctx.referenced.insert(text.to_string());
                }
            }
            return;
        }

        // type_identifier — references in type position. Filter predefined.
        "type_identifier" => {
            if let Ok(text) = node.utf8_text(ctx.source) {
                if !is_predefined_type(text) {
                    ctx.referenced.insert(text.to_string());
                }
            }
            return;
        }

        _ => {
            recurse_all_children(node, ctx);
        }
    }
}

/// Insert an identifier or pattern designation into `ctx.defined`.
/// Returns the node id so the caller can skip it during child recursion.
fn handle_designation_name(name_node: Option<Node>, ctx: &mut CollectContext) -> Option<usize> {
    let n = name_node?;
    let id = n.id();
    match n.kind() {
        "identifier" => {
            if let Ok(text) = n.utf8_text(ctx.source) {
                ctx.defined.insert(text.to_string());
            }
        }
        "tuple_pattern" | "parenthesized_pattern" => collect_pattern_identifiers(n, ctx),
        "parenthesized_variable_designation" => collect_designation_identifiers(n, ctx),
        "discard" => {}
        _ => {}
    }
    Some(id)
}

fn recurse_all_children(node: Node, ctx: &mut CollectContext) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_identifiers(cursor.node(), ctx);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn recurse_children_skipping(node: Node, ctx: &mut CollectContext, skip_id: Option<usize>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if Some(cursor.node().id()) != skip_id {
                collect_identifiers(cursor.node(), ctx);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Collect identifiers inside a tuple_pattern / parenthesized_pattern as
/// defined names (deconstruction).
fn collect_pattern_identifiers(node: Node, ctx: &mut CollectContext) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let k = cursor.node().kind();
            if k == "identifier" {
                if let Ok(text) = cursor.node().utf8_text(ctx.source) {
                    ctx.defined.insert(text.to_string());
                }
            } else {
                collect_pattern_identifiers(cursor.node(), ctx);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Collect identifiers inside a parenthesized_variable_designation.
fn collect_designation_identifiers(node: Node, ctx: &mut CollectContext) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let k = cursor.node().kind();
            match k {
                "identifier" => {
                    if let Ok(text) = cursor.node().utf8_text(ctx.source) {
                        ctx.defined.insert(text.to_string());
                    }
                }
                "parenthesized_variable_designation" => {
                    collect_designation_identifiers(cursor.node(), ctx);
                }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn collect_name_identifier(name_node: Node, ctx: &mut CollectContext) {
    if name_node.kind() == "identifier" {
        if let Ok(text) = name_node.utf8_text(ctx.source) {
            ctx.defined.insert(text.to_string());
        }
    } else if matches!(name_node.kind(), "tuple_pattern" | "parenthesized_pattern") {
        collect_pattern_identifiers(name_node, ctx);
    } else if name_node.kind() == "parenthesized_variable_designation" {
        collect_designation_identifiers(name_node, ctx);
    }
}

// ---- Position checks ----

/// True if this identifier sits in a definition-site position (e.g. the
/// `name` field of a declaration).
fn is_definition_site(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let pkind = parent.kind();
    // Direct name fields on definition parents are already handled by the
    // parent walk (definition branch inserts into `defined` and recurses).
    // This check guards against double-insertion when recursion visits the
    // identifier before its parent (it doesn't, normally) and also catches
    // any definition field we forgot to special-case.
    if NAMED_DEFINITION_TYPES.contains(&pkind) {
        if let Some(name_field) = parent.child_by_field_name("name") {
            if name_field.id() == node.id() {
                return true;
            }
        }
    }
    if pkind == "variable_declarator" {
        if let Some(name_field) = parent.child_by_field_name("name") {
            if name_field.id() == node.id() {
                return true;
            }
        }
    }
    if pkind == "parameter" {
        if let Some(name_field) = parent.child_by_field_name("name") {
            if name_field.id() == node.id() {
                return true;
            }
        }
    }
    if pkind == "foreach_statement" {
        if let Some(left) = parent.child_by_field_name("left") {
            if left.id() == node.id() {
                return true;
            }
        }
    }
    if matches!(pkind, "declaration_pattern" | "recursive_pattern") {
        if let Some(name_field) = parent.child_by_field_name("name") {
            if name_field.id() == node.id() {
                return true;
            }
        }
    }
    if pkind == "tuple_element" {
        if let Some(name_field) = parent.child_by_field_name("name") {
            if name_field.id() == node.id() {
                return true;
            }
        }
    }
    false
}

/// True if this identifier is a non-reference site (member access, qualified
/// name segment, anonymous property label, named-argument label, etc.).
fn is_member_name(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        // a.Foo, obj.Bar — trailing identifier is a member access.
        // System.Console.WriteLine — leftmost identifier of a member-access
        // chain (parent is itself a member_access_expression) is a namespace
        // root, not a variable reference.
        "member_access_expression" => {
            if let Some(name_node) = parent.child_by_field_name("name") {
                if name_node.id() == node.id() {
                    return true;
                }
            }
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "member_access_expression" {
                    return true;
                }
            }
            false
        }
        // System.Uri — qualifier and name segments are type-qualified refs,
        // handled elsewhere (qualified names map to type references, not vars).
        "qualified_name" => true,
        "alias_qualified_name" => true,
        // new { Foo = 1 } — anonymous property label.
        "anonymous_object_creation_expression" => true,
        // Method(name: value) — named-argument label.
        "name_colon" => true,
        // using X = System.Uri — name_equals defines the alias.
        "name_equals" => true,
        // Method(name: value) — named-argument label is the `name` field of
        // an `argument` node. Identifying these as non-references avoids
        // flagging every named-argument label as a hallucinated variable.
        "argument" => parent
            .child_by_field_name("name")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // Type { Prop: pattern } — subpattern property label.
        "subpattern" => parent
            .child_by_field_name("name")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        _ => false,
    }
}

// ---- Type-name extraction ----

fn extract_type_names_subtree(node: Node, types: &mut HashSet<String>, source: &[u8]) {
    let kind = node.kind();
    if matches!(
        kind,
        "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "enum_declaration"
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(text) = name_node.utf8_text(source) {
                types.insert(text.to_string());
            }
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            extract_type_names_subtree(cursor.node(), types, source);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ---- Builtins / prose ----

fn is_keyword_or_builtin(name: &str) -> bool {
    if name.len() < 3 {
        return true;
    }
    if reserved_keywords().contains(name) {
        return true;
    }
    if is_predefined_type(name) {
        return true;
    }
    if bcl_type_aliases().contains(name) {
        return true;
    }
    if common_methods().contains(name) {
        return true;
    }
    if prose_words().contains(name) {
        return true;
    }
    // ALL_CAPS constants — screaming snake case.
    if name.len() >= 3 && name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
        return true;
    }
    false
}

fn is_predefined_type(name: &str) -> bool {
    predefined_types().contains(name)
}

// ---- Line filtering ----

fn line_looks_like_code(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return false;
    }
    if CODE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
        return true;
    }
    if OPERATOR_STARTS.iter().any(|p| trimmed.starts_with(p)) {
        return true;
    }
    let stripped = strip_string_contents(line);
    let word_count = stripped.split_whitespace().count();
    if word_count > 6 {
        return false;
    }
    let punct_count = stripped
        .chars()
        .filter(|c| {
            matches!(
                c,
                '{' | '}' | '(' | ')' | '<' | '>' | ':' | '=' | '.' | ',' | '[' | ']' | ';'
            )
        })
        .count();
    punct_count >= 2
}

fn strip_string_contents(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_string = false;
    let mut escape = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
                out.push('"');
            }
        } else if c == '"' {
            in_string = true;
            out.push('"');
        } else if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            break;
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_undefined_local() {
        let code = r#"
public class Foo {
    public void Bar() {
        Console.WriteLine(missing);
    }
}
"#;
        let undefined = extract_undefined_variables(code);
        assert!(undefined.iter().any(|n| n == "missing"));
    }

    #[test]
    fn ignores_anonymous_object_property_labels() {
        // The `Foo` and `Bar` here are property labels, not references.
        let code = r#"
public class C {
    public void M() {
        var x = new { Foo = 1, Bar = 2 };
        Console.WriteLine(x);
    }
}
"#;
        let undefined = extract_undefined_variables(code);
        assert!(!undefined.iter().any(|n| n == "Foo"), "got: {:?}", undefined);
        assert!(!undefined.iter().any(|n| n == "Bar"), "got: {:?}", undefined);
    }

    #[test]
    fn handles_lambda_parameters() {
        let code = r#"
public class C {
    public void M() {
        System.Func<int, int> f = (xyz) => xyz + 1;
        f(42);
    }
}
"#;
        let undefined = extract_undefined_variables(code);
        assert!(!undefined.iter().any(|n| n == "xyz"), "got: {:?}", undefined);
    }

    #[test]
    fn handles_record_primary_constructor() {
        let code = r#"
public record Person(string Name, int Age);

public class C {
    public void M() {
        var p = new Person("Ada", 30);
        System.Console.WriteLine(p);
    }
}
"#;
        let undefined = extract_undefined_variables(code);
        assert!(!undefined.iter().any(|n| n == "Name"), "got: {:?}", undefined);
        assert!(!undefined.iter().any(|n| n == "Age"), "got: {:?}", undefined);
    }

    #[test]
    fn ignores_qualified_namespace_segments() {
        let code = r#"
public class C {
    public void M() {
        System.Uri u = new System.Uri("http://example.com");
        System.Console.WriteLine(u);
    }
}
"#;
        let undefined = extract_undefined_variables(code);
        assert!(!undefined.iter().any(|n| n == "System"), "got: {:?}", undefined);
    }

    #[test]
    fn does_not_flag_pattern_matching_keywords() {
        let code = r#"
public class C {
    public void M(object o) {
        if (o is string s and not null) {
            System.Console.WriteLine(s);
        }
    }
}
"#;
        let undefined = extract_undefined_variables(code);
        assert!(!undefined.iter().any(|n| n == "not"), "got: {:?}", undefined);
        assert!(!undefined.iter().any(|n| n == "and"), "got: {:?}", undefined);
    }

    #[test]
    fn handles_foreach_loop_variable() {
        let code = r#"
public class C {
    public void M() {
        foreach (var item in System.Linq.Enumerable.Range(1, 10)) {
            System.Console.WriteLine(item);
        }
    }
}
"#;
        let undefined = extract_undefined_variables(code);
        assert!(!undefined.iter().any(|n| n == "item"), "got: {:?}", undefined);
    }

    #[test]
    fn extracts_type_names_basic() {
        let code = r#"
public class Foo { }
public interface IBar { }
public struct Baz { }
public record Qux(string Name);
public enum Quux { A, B, C }
"#;
        let types = extract_type_names(code);
        assert!(types.contains("Foo"));
        assert!(types.contains("IBar"));
        assert!(types.contains("Baz"));
        assert!(types.contains("Qux"));
        assert!(types.contains("Quux"));
    }
}
