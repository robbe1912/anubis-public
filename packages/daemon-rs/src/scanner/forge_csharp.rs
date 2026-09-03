//! C# FORGE runner — extracted from forge_pipeline.rs (M1 chunk 5c).
//!
//! Verifies C# source for:
//!   1. NuGet package imports — registry verification
//!   2. Undefined variables — regex scope checker
//!   3. BCL namespace verification — System.* `using` statements
//!   4. Parameter arity — flag 0-arg methods called with extra args
//!   5. Method calls — receiver map + cache verification
//!   6. Static method calls — TypeName.Method() patterns

use crate::scanner::arity::check_call_arity;
use crate::scanner::forge_types::ForgeResult;
use crate::scanner::levenshtein::distance as levenshtein_distance;
use crate::scanner::package_index::ImportStatus;
use crate::scanner::scope_extractor::{extract_undefined, ScopeExtractor};

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

// Static regex pattern for verify_csharp_bcl_namespaces
static USING_RE: Lazy<Regex> = Lazy::new(|| Regex::new(
    r#"using\s+((?:System|Microsoft|net|Windows)\.[A-Za-z_][\w.]*)\s*;"#
).unwrap());

/// C# FORGE pipeline (partial).
/// Verifies imports against NuGet + C# regex scope checker.
pub(crate) async fn run_forge_csharp(content: &str) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();

    // Language-contamination guard (mirror forge_cpp / forge_rust): if the
    // response is mostly another language (Python/JS/Rust prose) or mostly
    // English with little C# structural signal, skip all checks. Eliminates
    // the dominant FP source on agent explanations like
    // "Plan: scaffold LibraryApi + test project...".
    let lower = content.to_lowercase();
    let english_count = [
        "the ", " a ", " an ", " is ", " are ", " was ", " were ", " to ",
        " of ", " in ", " on ", " at ", " by ", " for ", " with ", " from ",
        " this ", " that ", " it ", " its ", " as ", " be ", " have ",
        " has ", " do ", " does ", " will ", " would ", " could ", " should ",
        " can ", " may ", " might ",
    ].iter().map(|w| lower.matches(w).count()).sum::<usize>();
    let cs_kw_count = [
        "using ", "namespace ", "public ", "private ", "protected ",
        "internal ", "static ", "class ", "interface ", "struct ",
        "enum ", "void ", "var ", "new ", "return ", "if ", "else ",
        "foreach ", "for ", "while ", "try ", "catch ", "finally ",
        "[HttpGet", "[HttpPost", "[HttpPut", "[HttpDelete", "[ApiController",
        "Console.", "Math.", "DateTime.", "List<", "Dictionary<",
        "IEnumerable<", "Task<", "get; ", "set; ",
    ].iter().map(|w| lower.matches(w).count()).sum::<usize>();
    let other_lang_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("def ") || t.starts_with("import ") || t.starts_with("from ")
            || t.starts_with("func ") || t.starts_with("package ")
            || t.starts_with("pub fn ") || t.starts_with("fn ")
            || t.starts_with("const ") && t.contains("= require(")
            || t.starts_with("export ") && t.contains("function")
    }).count();
    let cs_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("using ") || t.starts_with("namespace ") || t.starts_with("public ")
            || t.starts_with("private ") || t.starts_with("protected ")
            || t.starts_with("internal ") || t.starts_with("[Http")
            || t.starts_with("[Api") || t.starts_with("var ")
            || t.starts_with("//") || t.contains("} catch")
            || t.contains("Console.WriteLine") || t.contains("Console.Write")
    }).count();
    if other_lang_lines > cs_lines
        || cs_kw_count == 0
        || english_count > cs_kw_count * 3 && cs_kw_count < 20
    {
        result.latency_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    let terms = extract_csharp_imports(content);
    result.claims_extracted = terms.len();
    for pkg in &terms {
        if pkg.starts_with('.') || pkg.starts_with('/') {
            continue;
        }
        let status = crate::scanner::package_index::verify_import_with_language("csharp", pkg).await;
        match status {
            ImportStatus::NotFound => {
                result.warnings.push(format!(
                    "hallucinated-import: `{}` — not found in NuGet", pkg
                ));
                result.claims_hallucinated += 1;
            }
            ImportStatus::Verified => result.claims_verified += 1,
            _ => result.claims_unknown += 1,
        }
    }
    let undefined = crate::scanner::csharp_ast_extractor::extract_undefined_variables(content);

    // Build a set of known type names from the current content.
    // This prevents FPs on user-defined types (UpdateBookDto, Book, etc.)
    // defined elsewhere in the response.
    let known_types = extract_csharp_type_names(content);

    for name in &undefined {
        if name.len() >= 3 && !known_types.contains(name.as_str()) {
            // Skip .NET generic type parameters (TRequest, TResponse, TEntity, etc.)
            // These follow the convention: T + PascalCase name. Not hallucinations.
            let is_generic_param = name.starts_with('T')
                && name.len() > 1
                && name[1..].chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
            if is_generic_param {
                continue;
            }
            // Consult SymbolCache: if this name exists as a type/method in ANY
            // cached library (populated by metadata fetcher from NuGet .nupkg),
            // it's a real symbol — don't flag as hallucinated.
            if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
                if !cache.lookup_global(name).is_empty() {
                    continue;
                }
            }
            result.warnings.push(format!(
                "hallucinated-variable: `{}` — referenced but not defined in scope", name
            ));
            result.claims_hallucinated += 1;
        }
    }
    result.claims_extracted += undefined.len();

    let namespace_warnings = verify_csharp_bcl_namespaces(content);
    if !namespace_warnings.is_empty() {
        result.claims_extracted += namespace_warnings.len();
        result.claims_hallucinated += namespace_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(namespace_warnings);
    }

    let arity_warnings = check_call_arity(content);
    if !arity_warnings.is_empty() {
        result.claims_extracted += arity_warnings.len();
        result.claims_hallucinated += arity_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(arity_warnings);
    }

    let cs_receiver_map = crate::scanner::csharp_introspect::build_csharp_receiver_map(content);
    if !cs_receiver_map.is_empty() {
        let method_warnings = crate::scanner::csharp_introspect::verify_csharp_methods(content, &cs_receiver_map).await;
        if !method_warnings.is_empty() {
            result.claims_extracted += method_warnings.len();
            result.claims_hallucinated += method_warnings.iter().filter(|w| w.contains("hallucinated")).count();
            result.warnings.extend(method_warnings);
        }
    }

    let static_warnings = crate::scanner::csharp_introspect::verify_csharp_static_methods(content).await;
    if !static_warnings.is_empty() {
        result.claims_extracted += static_warnings.len();
        result.claims_hallucinated += static_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(static_warnings);
    }

    // Inline constructor chained method calls: Type(...).Method(...)
    // Catches hallucinations like Guid(id).ToGuidInstance() where the
    // receiver is a constructor call expression, not a variable.
    let ctor_chain_warnings = crate::scanner::csharp_introspect::verify_csharp_inline_ctor_chains(content).await;
    if !ctor_chain_warnings.is_empty() {
        result.claims_extracted += ctor_chain_warnings.len();
        result.claims_hallucinated += ctor_chain_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(ctor_chain_warnings);
    }

    result.latency_ms = start.elapsed().as_millis() as u64;

    result
}

/// Verify C# BCL namespace `using` statements against known namespaces.
fn verify_csharp_bcl_namespaces(content: &str) -> Vec<String> {
    static KNOWN_BCL: Lazy<HashSet<&str>> = Lazy::new(|| {
        let ns = [
            "System", "System.IO", "System.Net", "System.Net.Http",
            "System.Net.Mail", "System.Net.Mime", "System.Net.Sockets",
            "System.Net.NetworkInformation", "System.Net.Security",
            "System.Net.WebSockets", "System.Net.Cache",
            "System.Text", "System.Text.Json", "System.Text.RegularExpressions",
            "System.Collections", "System.Collections.Generic",
            "System.Collections.Concurrent", "System.Collections.ObjectModel",
            "System.Collections.Specialized", "System.Threading",
            "System.Threading.Tasks", "System.Threading.Tasks.Dataflow",
            "System.Threading.Channels", "System.Linq",
            "System.Linq.Expressions", "System.Xml", "System.Xml.Linq",
            "System.Xml.Serialization", "System.Xml.XPath", "System.Xml.Xsl",
            "System.Globalization", "System.Diagnostics",
            "System.Diagnostics.Tracing", "System.Diagnostics.Contracts",
            "System.Reflection", "System.Runtime",
            "System.Runtime.Serialization",
            "System.Runtime.InteropServices",
            "System.Runtime.CompilerServices", "System.Security",
            "System.Security.Cryptography",
            "System.Security.Authentication", "System.Security.Claims",
            "System.Security.Principal", "System.Security.Permissions",
            "System.Configuration", "System.Resources",
            "System.Drawing", "System.Drawing.Drawing2D",
            "System.Drawing.Imaging", "System.Drawing.Text",
            "System.Windows.Forms", "System.Data",
            "System.Data.SqlClient", "System.Data.Common",
            "System.Web", "System.Web.Mvc", "System.Web.Routing",
            "System.ServiceModel", "System.ServiceModel.Channels",
            "System.Transactions", "System.Timers",
            "System.IO.Compression", "System.IO.Pipes",
            "System.IO.FileSystem", "System.IO.FileSystem.Watcher",
            "System.Buffers", "System.Memory", "System.Numerics",
            "System.HashCode", "System.Uri", "System.Guid",
            "System.ComponentModel",
            "System.ComponentModel.DataAnnotations",
            "System.ComponentModel.Design", "System.Media",
            "System.Reflection.Emit", "System.Runtime.Intrinsics",
            "System.Runtime.Loader", "System.Runtime.Versioning",
            "System.Security.AccessControl",
            "System.Security.Cryptography.X509Certificates",
            "System.Text.Encodings.Web",
            "System.Threading.Tasks.Extensions", "System.ValueTuple",
            "System.IO.Enumeration", "System.Diagnostics.Process",
            "System.Diagnostics.StackTrace",
        ];
        ns.iter().copied().collect()
    });

    let mut warnings = Vec::new();
    let using_re = &*USING_RE;
    for caps in using_re.captures_iter(content) {
        let ns = caps.get(1).unwrap().as_str();
        if KNOWN_BCL.contains(ns) {
            continue;
        }
        let mut best_match: Option<(usize, &str)> = None;
        for &known in KNOWN_BCL.iter() {
            let dist = levenshtein_distance(ns, known);
            if dist > 0 && dist <= 6 {
                match best_match {
                    None => best_match = Some((dist, known)),
                    Some((bd, _)) if dist < bd => best_match = Some((dist, known)),
                    _ => {}
                }
            }
        }
        if let Some((dist, suggestion)) = best_match {
            if dist <= ns.len() / 3 + 2 {
                warnings.push(format!(
                    "hallucinated-namespace: `{}` — not a known .NET BCL namespace. Did you mean `{}` (distance {})?",
                    ns, suggestion, dist
                ));
            }
        }
    }

    warnings
}

static CSHARP_KEYWORDS: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch",
        "char", "checked", "class", "const", "continue", "decimal", "default",
        "delegate", "do", "double", "else", "enum", "event", "explicit",
        "extern", "false", "finally", "fixed", "float", "for", "foreach",
        "goto", "if", "implicit", "in", "int", "interface", "internal",
        "is", "lock", "long", "namespace", "new", "null", "object", "operator",
        "out", "override", "params", "private", "protected", "public", "readonly",
        "ref", "return", "sbyte", "sealed", "short", "sizeof", "stackalloc",
        "static", "string", "struct", "switch", "this", "throw", "true",
        "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort",
        "using", "virtual", "void", "volatile", "while", "var", "Console",
        "Math", "String", "Convert", "DateTime", "TimeSpan", "Guid",
        "Task", "Enumerable",
        // C# 9+ contextual keywords.
            "init", "record", "not", "notnull", "and", "or", "when",
        // Contextual keywords — not reserved but have special meaning.
        "get", "set", "async", "await", "value", "partial", "where",
        "yield", "nameof", "when", "global", "args",
        // ASP.NET Core framework types.
        "ControllerBase", "WebApplication", "ActionResult", "IActionResult",
        "IActionResult", "NotFound", "Ok", "BadRequest", "NoContent",
        "CreatedAtAction", "CreatedAtRoute", "BadRequestObjectResult",
        "Builder", "JsonOptions",
        // Common BCL types used in production .NET code.
        "CancellationToken", "CancellationTokenSource",
        "DateOnly", "TimeOnly", "DateTimeOffset",
        "Version", "Environment", "AppDomain", "GC",
        "JsonIgnoreCondition", "JsonSerializerOptions", "JsonSerializer",
        "Description", "DisplayName", "Required", "MaxLength", "Range",
        "RegularExpression", "StringLength", "MinLength",
        // LINQ / Collections interfaces.
        "IQueryable", "IReadOnlyList", "IReadOnlyCollection",
        "IEqualityComparer", "IComparable", "IProgress",
        // Logging / DI / Config.
        "ILogger", "ILoggerFactory", "IServiceCollection",
        "IServiceProvider", "IConfiguration", "IOptions",
        "IHostBuilder", "IWebHostEnvironment",
        // EF Core.
        "DbContext", "DbContextOptions", "DbSet",
        "DbUpdateException", "DbUpdateConcurrencyException",
        "ModelBuilder", "EntityTypeBuilder",
        // ASP.NET Core HTTP pipeline.
        "ModelState", "IActionFilter", "IAsyncActionFilter",
        "ActionExecutedContext", "ActionExecutingContext",
        "HttpContext", "HttpRequest", "HttpResponse",
        "StatusCode", "StatusCodes", "IResult",
        // Misc common framework types.
        "HashSet", "Dictionary", "KeyValuePair",
        "Exception", "InvalidOperationException", "ArgumentException",
        "ArgumentNullException", "NotImplementedException",
        "HttpRequestException", "JsonException",
    ]
    .iter().copied().collect()
});

static VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bvar\s+(\w+)\s*=").unwrap()
});
static PROPERTY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\w+(?:\s*<[^>]+>)?(?:\s*\[\])?\s+(\w+)\s*\{\s*get\s*;").unwrap()
});
/// Scope-extractor variant: captures the first identifier from `using X.Y.Z;`
/// so individual namespace names (Microsoft, System) are treated as defined.
/// Distinct from USING_RE (line 22) which captures the full dotted path.
static USING_SCOPE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\busing\s+(\w+)").unwrap()
});
static IDENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:^|[\s(,;])\b([a-zA-Z_]\w*)\b").unwrap()
});

/// Named arguments in C# method calls: paramName: value
/// These are NOT undefined variables — they're parameter assignments.
/// Pattern matches identifier followed by colon in argument context.
static NAMED_PARAM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+)\s*:\s").unwrap()
});

static CSHARP_DECL_REGEXES: &[&Lazy<Regex>] = &[&VAR_RE, &PROPERTY_RE, &USING_SCOPE_RE, &NAMED_PARAM_RE];

/// Extract C# type names from content + project_index to filter
/// false-positive "undefined variable" warnings on user-defined types.
fn extract_csharp_type_names(content: &str) -> std::collections::HashSet<String> {
    use regex::Regex;
    use std::sync::OnceLock;
    static TYPE_RE: OnceLock<Regex> = OnceLock::new();
    let re = TYPE_RE.get_or_init(|| {
        Regex::new(
            r"(?:class|interface|struct|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)"
        ).unwrap()
    });
    let mut names = std::collections::HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue; // Skip comment lines — prevents stub type names in comments
        }
        for cap in re.captures_iter(trimmed) {
            if let Some(name) = cap.get(1) {
                names.insert(name.as_str().to_string());
            }
        }
    }
    names
}


pub struct CSharpScope;

impl ScopeExtractor for CSharpScope {
    fn keywords(&self) -> &'static Lazy<HashSet<&'static str>> {
        &CSHARP_KEYWORDS
    }

    fn ident_regex(&self) -> &'static Lazy<Regex> {
        &IDENT_RE
    }

    fn decl_regexes(&self) -> &'static [&'static Lazy<Regex>] {
        CSHARP_DECL_REGEXES
    }

    fn strip_strings(&self) -> bool {
        true
    }

    fn skip_match(&self, content: &str, match_start: usize) -> bool {
        if match_start == 0 {
            return false;
        }
        let prev_byte = content
            .as_bytes()
            .get(match_start.wrapping_sub(1))
            .copied()
            .unwrap_or(b' ');
        prev_byte == b'.'
    }

    fn collect_param(&self, parts: &[&str]) -> Option<String> {
        if parts.len() >= 2 {
            Some(parts[parts.len() - 1].to_string())
        } else {
            None
        }
    }
}

/// Extract undefined variables from C# source via the shared scope-extractor
/// driver. Used as a regex-based fallback when the tree-sitter AST extractor
/// is unavailable or fails.
pub(crate) fn extract_csharp_undefined_variables_regex(content: &str) -> Vec<String> {
    let mut undefined = extract_undefined(content, &CSharpScope);

    // Post-filter: extract additional declarations the regex-based scope
    // extractor misses — lambda parameters, record/class/struct primary
    // constructor parameters, and explicit-type local declarations.
    // Without this, lambda params (onRetry, outcome) and record properties
    // (OrderId, CreatedAtUtc) are flagged as hallucinated-variable FPs.
    use std::sync::OnceLock;

    fn extract_param_names(group: &str) -> Vec<String> {
        group
            .split(',')
            .filter_map(|param| {
                let trimmed = param.trim().trim_end_matches(')');
                // Take last word: "Type name" → "name", "name" → "name"
                let name = trimmed.split_whitespace().last()?;
                if !name.is_empty()
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                    && name.len() > 1
                {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    let mut extra_declared = std::collections::HashSet::<String>::new();

    // Lambda parameters: (param1, param2) =>
    static LAMBDA_RE: OnceLock<Regex> = OnceLock::new();
    let lambda_re = LAMBDA_RE.get_or_init(|| Regex::new(r"\(([^)]*)\)\s*=>").unwrap());
    for cap in lambda_re.captures_iter(content) {
        if let Some(params) = cap.get(1) {
            extra_declared.extend(extract_param_names(params.as_str()));
        }
    }

    // Record/class/struct primary constructor: record Name(Type1 param1, Type2 param2)
    static CTOR_RE: OnceLock<Regex> = OnceLock::new();
    let ctor_re = CTOR_RE.get_or_init(|| {
        Regex::new(r"\b(?:record|class|struct)\s+\w+\s*\(([^)]*)\)").unwrap()
    });
    for cap in ctor_re.captures_iter(content) {
        if let Some(params) = cap.get(1) {
            extra_declared.extend(extract_param_names(params.as_str()));
        }
    }

    // Explicit-type local declarations: TimeSpan timespan = ... or int count;
    static EXPLICIT_LOCAL_RE: OnceLock<Regex> = OnceLock::new();
    let explicit_re = EXPLICIT_LOCAL_RE.get_or_init(|| {
        Regex::new(r"\b[A-Z]\w+(?:<[^>]+>)?\s+(\w+)\s*[=;]").unwrap()
    });
    for cap in explicit_re.captures_iter(content) {
        if let Some(name) = cap.get(1) {
            extra_declared.insert(name.as_str().to_string());
        }
    }

    undefined.retain(|name| !extra_declared.contains(name));
    undefined
}

/// Extract C#-specific import terms from `using <namespace>;` directives only.
///
/// Replaces the generic `extract_lookup_terms` call for C#. The generic
/// extractor pulls ClassName.method patterns and JS/Rust/Go/Python patterns
/// — none apply to C#. Result was that class names mentioned in prose
/// (LibraryApi, BookDto, etc.) were routed to NuGet and flagged as
/// hallucinated (24 of 32 FPs on task-009-csharp-api).
///
/// Only true `using Namespace.Sub;` directives count as imports. Top-level
/// segment is used for NuGet lookup (e.g. `Newtonsoft` from
/// `Newtonsoft.Json`). BCL namespaces (System.*, Microsoft.*, Windows.*)
/// are validated separately by `verify_csharp_bcl_namespaces`.
fn extract_csharp_imports(content: &str) -> HashSet<String> {
    let mut terms = HashSet::new();
    // Match `using Namespace.Sub;` and `using static Namespace.Type;`.
    // Reject `using var x = ...;` and `using (...)` statements — those
    // are resource management, not imports.
    let using_re = regex::Regex::new(r"\busing\s+(?:static\s+)?([A-Za-z_][\w.]*)\s*;").unwrap();
    for caps in using_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            // Skip BCL — handled by verify_csharp_bcl_namespaces against KNOWN_BCL.
            if path.starts_with("System.")
                || path.starts_with("Microsoft.")
                || path.starts_with("Windows.")
                || path == "System"
            {
                continue;
            }
            // Top-level namespace segment for NuGet lookup.
            if let Some(top) = path.split('.').next() {
                terms.insert(top.to_lowercase());
            }
        }
    }
    // Filter out project-internal namespaces — if `namespace LibraryApi.Controllers`
    // is declared in the code, `using LibraryApi.Models;` is a same-project
    // reference, not a NuGet package. Prevents hallucinated-import FPs on
    // internal namespace cross-references.
    let ns_re = regex::Regex::new(r"\bnamespace\s+([A-Za-z_][\w.]*)").unwrap();
    let declared_roots: HashSet<String> = ns_re
        .captures_iter(content)
        .filter_map(|c| {
            c.get(1)
                .and_then(|m| m.as_str().split('.').next())
                .map(|s| s.to_lowercase())
        })
        .filter(|s| !s.is_empty())
        .collect();
    terms.retain(|t| !declared_roots.contains(t));
    terms
}

#[cfg(test)]
mod prose_guard_tests {
    use super::*;

    async fn run_and_count(content: &str) -> usize {
        let result = run_forge_csharp(content).await;
        result.warnings.len()
    }

    #[tokio::test]
    async fn pure_english_plan_text_no_warnings() {
        // Was 3 import FPs on task-009: `libraryapi`, `bookdto`, `models`.
        let content = "Plan: scaffold LibraryApi + test project, implement \
                       Book entity/DTOs/context/controller, configure SQLite \
                       + migrations, write xUnit tests. Build, test, fix.";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn short_english_setup_text_no_warnings() {
        let content = "Now create main project. Need EF tool locally.";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn python_code_triggers_language_contamination_guard() {
        let content = "import asyncio\nfrom fastapi import FastAPI\n\n\
                       app = FastAPI()\n\n\
                       @app.get('/')\nasync def root():\n    return {'hello': 'world'}\n";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn real_csharp_with_undefined_var_still_flagged() {
        // C# signal must dominate; `undefinedThing` should still be flagged.
        let content = "using System;\nusing System.Collections.Generic;\n\n\
                       public class Foo {\n\
                       \n    public void Bar() {\n\
                       \n        undefinedThing.Run();\n    }\n}\n";
        let result = run_forge_csharp(content).await;
        assert!(
            result.warnings.iter().any(|w| w.contains("undefinedThing")),
            "expected undefinedThing warning, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn extract_csharp_imports_skips_bcl_namespaces() {
        let content = "using System;\nusing System.Collections.Generic;\n\
                       using System.IO;\nusing Microsoft.AspNetCore.App;\n\
                       using Windows.Forms;\n";
        let terms = extract_csharp_imports(content);
        assert!(
            terms.is_empty(),
            "BCL using directives must not route to NuGet, got: {:?}",
            terms
        );
    }

    #[test]
    fn extract_csharp_imports_skips_using_var_declarations() {
        // `using var x = ...;` is resource management, not import.
        let content = "public void Read() {\n    using var stream = new StreamReader(\"f\");\n}\n";
        let terms = extract_csharp_imports(content);
        assert!(terms.is_empty(), "using-var must not be treated as import");
    }

    #[test]
    fn extract_csharp_imports_skips_using_statements() {
        // `using (...)` block is resource management, not import.
        let content = "public void Read() {\n    using (var s = new StreamReader(\"f\")) {\n        s.Read();\n    }\n}\n";
        let terms = extract_csharp_imports(content);
        assert!(terms.is_empty(), "using-statement must not be treated as import");
    }

    #[test]
    fn extract_csharp_imports_takes_top_segment_of_third_party() {
        // Non-BCL using → top-level segment routed to NuGet lookup.
        let content = "using Newtonsoft.Json;\nusing Amazon.S3;\n";
        let terms = extract_csharp_imports(content);
        assert!(terms.contains("newtonsoft"), "got: {:?}", terms);
        assert!(terms.contains("amazon"), "got: {:?}", terms);
        assert_eq!(terms.len(), 2);
    }

    #[test]
    fn extract_csharp_imports_ignores_class_refs_in_prose() {
        // Crucial fix: previously ClassName.method in prose was extracted as
        // an import term and routed to NuGet. Now only true `using` directives
        // count.
        let content = "Plan: use LibraryApi.Controllers.BooksController and \
                       BookDto for the response model. BookService handles \
                       ISBN validation.";
        let terms = extract_csharp_imports(content);
        assert!(
            terms.is_empty(),
            "class refs in prose must not be import terms, got: {:?}",
            terms
        );
    }
}
