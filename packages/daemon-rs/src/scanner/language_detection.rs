//! Language detection — extracted from forge_pipeline.rs (M1 chunk 11).
//!
//! Heuristic language detection from content + file path. Used by
//! scan_response to route to the correct FORGE pipeline runner.

use regex::Regex;
use std::sync::OnceLock;

pub fn detect_language(content: &str, path: &str) -> &'static str {
    // Strong signals from path.
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".py") || path_lower.ends_with(".pyw") || path_lower.contains("/python/") {
        return "python";
    }
    if path_lower.ends_with(".ts") || path_lower.ends_with(".tsx")
        || path_lower.ends_with(".mts") || path_lower.ends_with(".cts") {
        return "typescript";
    }
    if path_lower.ends_with(".js") || path_lower.ends_with(".jsx")
        || path_lower.ends_with(".mjs") || path_lower.ends_with(".cjs") {
        return "typescript"; // JS uses same FORGE pipeline
    }
    if path_lower.ends_with(".rs") {
        return "rust";
    }
    if path_lower.ends_with(".go") {
        return "go";
    }
    if path_lower.ends_with(".java") || path_lower.ends_with(".kt") {
        return "java";
    }
    if path_lower.ends_with(".cs") {
        return "csharp";
    }
    if path_lower.ends_with(".cpp") || path_lower.ends_with(".cc") || path_lower.ends_with(".cxx")
        || path_lower.ends_with(".hpp")
    {
        return "cpp";
    }
    if path_lower.ends_with(".c") || path_lower.ends_with(".h") {
        return "c";
    }
    if path_lower.ends_with(".gd") {
        return "gdscript";
    }
    if path_lower.ends_with(".tscn") || path_lower.ends_with(".tres") || path_lower.ends_with(".escn") {
        return "tscn";
    }
    if path_lower.ends_with(".gdshader") || path_lower.ends_with(".shader") {
        return "gdshader";
    }

    // Code fence language tag — strongest content signal when path is a
    // directory (common in test/benchmark contexts). Markdown fences like
    // ```rust, ```typescript, ```go are explicit language declarations.
    if let Some(lang) = detect_fence_language(content) {
        return lang;
    }

    // Content heuristics.
    // IMPORTANT: language-distinctive patterns checked FIRST to avoid
    // false Python detection (Python's `import` keyword also appears in
    // Go, Java, JS — would match Python scoring before reaching Go/Java).
    // Check ALL content lines — agent responses often have prose first,
    // then code later in the response.
    let lines = content;

    // Language-distinctive signals (unique to one language).
    // Java FIRST: semicolon-terminated dotted imports (`import a.b.C;`) are
    // uniquely Java. Python/JS imports never end with `;` (Python allows a
    // trailing `;` but real code never writes it, and the required dot rules
    // out `import os;`); Go imports are bare or parenthesized; C# uses `using`.
    // Spring/JVM code importing only third-party packages (org.springframework.*,
    // com.google.*, org.slf4j) has NO `import java.*` line, so the prefix check
    // below misses it and generic `import `/`;` signals would score it Python.
    // Secondary: `extends`/`implements` after a class decl — Java keywords,
    // absent from C# (`:`) and every other supported language. (F1)
    static JAVA_IMPORT_SEMI_RE: OnceLock<Regex> = OnceLock::new();
    static JAVA_CLASS_EXT_RE: OnceLock<Regex> = OnceLock::new();
    let java_import_semi = JAVA_IMPORT_SEMI_RE
        .get_or_init(|| {
            Regex::new(r"(?m)^\s*import\s+(?:static\s+)?[a-z_]\w*\.[\w.]+\s*;").unwrap()
        })
        .is_match(lines);
    let java_class_ext = JAVA_CLASS_EXT_RE
        .get_or_init(|| {
            Regex::new(r"(?m)^\s*(?:public\s+|final\s+|abstract\s+)*class\s+\w+\s+(?:extends|implements)\s").unwrap()
        })
        .is_match(lines);
    if java_import_semi || java_class_ext {
        return "java";
    }
    if lines.contains("import java.") || lines.contains("import javax.") {
        return "java";
    }
    if lines.contains("using System") || lines.contains("using Microsoft") {
        return "csharp";
    }
    if lines.contains("#include <") {
        return "cpp";
    }
    if regex::Regex::new(r"(?m)^\s*package\s+\w+").unwrap().is_match(&lines)
        && !lines.contains("package.json")
        && !lines.contains("node_modules")
    {
        // Only return Go if it has `package X` at line start AND looks like
        // real Go code (has func/import). Without this guard, prose mentioning
        // "package main" in a TS discussion triggers false Go detection.
        if lines.contains("func ") || lines.contains("import (\n") || lines.contains("fmt.") {
            return "go";
        }
    }
    if lines.contains("import (") && lines.contains("func") {
        return "go";
    }

    // TypeScript/JavaScript distinctive patterns — checked BEFORE Python scoring
    // to prevent misdetection. These patterns are essentially impossible in
    // other languages.
    if lines.contains("interface ") && lines.contains("export ") {
        return "typescript";
    }
    if (lines.contains("import {") || lines.contains("export {"))
        && (lines.contains("from '") || lines.contains("from \""))
    {
        return "typescript";
    }
    if lines.contains(": string") || lines.contains(": number")
        || lines.contains(": boolean") || lines.contains(": void")
        || lines.contains(": any") || lines.contains(": unknown")
    {
        return "typescript";
    }
    if lines.contains("as const") || lines.contains("satisfies ")
        || lines.contains("keyof ") || lines.contains("typeof ")
    {
        return "typescript";
    }
    if lines.contains("fn ") && (lines.contains("let ") || lines.contains("impl ")) {
        return "rust";
    }
    // GDScript: distinctive keywords absent from other languages.
    if lines.contains("extends ") && (lines.contains("func ") || lines.contains("onready ")) {
        return "gdscript";
    }

    // Python/TypeScript scoring (fallback after distinctive patterns).
    let py_signals = [
        ("def ", 4),
        ("import ", 4),
        ("from ", 3),
        ("elif ", 4),
        ("print(", 3),
        ("self.", 3),
        ("    @property", 5),
        ("lambda ", 4),
        // Additional Python-distinctive signals
        ("-> ", 4),              // return type annotation (Python 3)
        ("\"\"\"", 4),           // triple-quote docstring
        ("if __name__", 6),      // extremely Python-specific
        ("@dataclass", 5),       // Python decorator
        ("@staticmethod", 5),    // Python decorator
        ("@classmethod", 5),     // Python decorator
        ("f\"", 3),              // f-string (Python 3.6+)
        ("f'", 3),               // f-string
        ("raise ", 3),           // Python exception
        ("except ", 3),          // Python exception
        ("try:", 3),             // Python exception
        ("with ", 2),            // Python context manager
        ("None", 2),             // Python None (capitalized)
        ("True", 2),             // Python True (capitalized)
        ("False", 2),            // Python False (capitalized)
        ("__init__", 4),         // Python dunder
        ("__main__", 4),         // Python dunder
        ("__name__", 4),         // Python dunder
        (": str", 2),            // type annotation
        (": int", 2),            // type annotation
        (": bool", 2),           // type annotation
        (": float", 2),          // type annotation
        (": list", 2),           // type annotation
        (": dict", 2),           // type annotation
        (": Optional", 3),       // type annotation
        (": Tuple", 3),          // type annotation
        ("async def", 5),        // async function (Python)
        ("await ", 3),           // async (Python)
    ];
    let ts_signals = [
        ("const ", 1),
        ("interface ", 3),
        ("=> {", 2),
        ("export function", 3),
        (": string", 2),
        (": number", 2),
        ("useEffect", 4),
        ("useState", 4),
        // JS/TS-only stdlib surface: `console.log` never appears in Python/
        // Rust/Go/Java source. Weight 4 so console.log + const (a minimal
        // unfenced JS snippet) crosses the >= 5 threshold — closes the
        // unfenced-evasion vector where fence-less JS was scored "unknown".
        ("console.log", 4),
    ];
    let py_score: usize = py_signals.iter().map(|(s, w)| if lines.contains(s) { *w } else { 0 }).sum();
    let ts_score: usize = ts_signals.iter().map(|(s, w)| if lines.contains(s) { *w } else { 0 }).sum();
    if py_score >= 3 && py_score > ts_score {
        return "python";
    }
    if ts_score >= 5 {
        return "typescript";
    }

    "unknown"
}

/// Extract language from the first markdown code fence tag (```lang).
/// Returns None if no fenced block with a language tag is found.
fn detect_fence_language(content: &str) -> Option<&'static str> {
    static FENCE_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = FENCE_RE.get_or_init(|| Regex::new(r"```(\w+)").unwrap());
    let cap = re.captures(content)?;
    let lang = cap.get(1)?.as_str().to_lowercase();
    let mapped = match lang.as_str() {
        "python" | "py" | "python3" => "python",
        "typescript" | "ts" | "tsx" => "typescript",
        "javascript" | "js" | "jsx" | "mjs" | "cjs" => "typescript",
        "rust" | "rs" => "rust",
        "go" | "golang" => "go",
        "java" => "java",
        "csharp" | "cs" => "csharp",
        "cpp" | "c++" | "cc" | "cxx" => "cpp",
        "c" | "h" => "c",
        "gdscript" | "gd" => "gdscript",
        _ => return None,
    };
    Some(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f1_spring_third_party_imports_detect_java() {
        // The exact task-010 shape: no `import java.*`, only third-party
        // (org.springframework.*) — previously scored python via generic
        // `import `/`;` signals → PyPI misroute FP.
        let content = "import org.springframework.boot.SpringApplication;\nimport org.springframework.web.bind.annotation.RestController;\n\n@RestController\npublic class App {\n    public static void main(String[] args) {\n        SpringApplication.run(App.class, args);\n    }\n}\n";
        assert_eq!(detect_language(content, ""), "java");
    }

    #[test]
    fn f1_static_import_detects_java() {
        assert_eq!(
            detect_language("import static org.junit.Assert.assertEquals;\n", ""),
            "java"
        );
    }

    #[test]
    fn f1_class_extends_detects_java() {
        assert_eq!(
            detect_language("public class Loader extends BaseLoader implements AutoCloseable {\n}\n", ""),
            "java"
        );
    }

    #[test]
    fn python_still_wins_on_python_shape() {
        // Guard: real Python must not regress to java.
        let content = "import os\nimport sys\n\ndef main():\n    print(f\"hello {sys.argv}\")\n\nif __name__ == \"__main__\":\n    main()\n";
        assert_eq!(detect_language(content, ""), "python");
    }

    #[test]
    fn f2_guard_python_run_forge_returns_empty_on_java_shape() {
        // forge_python's Java-shape guard (F2) is async + runtime — verified
        // indirectly here by the same regex contract: python-shaped content
        // must NOT trip the java guard pattern.
        static JAVA_SHAPE_RE: OnceLock<Regex> = OnceLock::new();
        let re = JAVA_SHAPE_RE.get_or_init(|| {
            Regex::new(r"(?m)^\s*import\s+(?:static\s+)?[a-z_]\w*\.[\w.]+\s*;").unwrap()
        });
        assert!(!re.is_match("import os\nimport sys\n"));
        assert!(!re.is_match("from collections import OrderedDict\n"));
        assert!(re.is_match("import org.springframework.boot.SpringApplication;\n"));
    }
}
