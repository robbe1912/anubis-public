//! Java FORGE runner — extracted from forge_pipeline.rs (M1 chunk 7b).
//!
//! Verifies Java source for:
//!   1. Maven Central package imports
//!   2. Undefined variables — regex scope checker
//!   3. Method calls — javadoc.io introspection
//!   4. Parameter arity — flag 0-arg methods called with extra args

use crate::scanner::arity::check_call_arity;
use crate::scanner::forge_types::ForgeResult;
use crate::scanner::package_index::ImportStatus;
use crate::scanner::scope_extractor::{extract_undefined, ScopeExtractor};

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Java FORGE pipeline (partial).
/// Verifies imports against Maven Central + Java regex scope checker.
/// `project_root` gates import verification: without a pom.xml /
/// build.gradle the project has no Maven dependency context, so routing
/// third-party imports to Maven Central only produces FPs.
pub(crate) async fn run_forge_java(content: &str, project_root: &str) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();

    // Language-contamination + prose guard (mirror forge_cpp / forge_csharp).
    let lower = content.to_lowercase();
    let english_count = [
        "the ", " a ", " an ", " is ", " are ", " was ", " were ", " to ",
        " of ", " in ", " on ", " at ", " by ", " for ", " with ", " from ",
        " this ", " that ", " it ", " its ", " as ", " be ", " have ",
        " has ", " do ", " does ", " will ", " would ", " could ", " should ",
        " can ", " may ", " might ",
    ].iter().map(|w| lower.matches(w).count()).sum::<usize>();
    let java_kw_count = [
        "package ", "import ", "public class ", "public interface ",
        "public enum ", "public final ", "public static ",
        "private ", "protected ", "abstract ",
        "@override", "@autowired", "@service", "@repository", "@restcontroller",
        "@requestmapping", "@getmapping", "@postmapping", "@entity", "@table",
        "@springbootapplication", "@component", "@configuration", "@bean",
        "void ", "int ", "string ", "boolean ", "list<", "map<", "set<",
        "@test", "system.out.println", "system.err.println",
        "throws ", "throw new ", "new ", "return ",
        "this.", "super.", "instanceof",
    ].iter().map(|w| lower.matches(w).count()).sum::<usize>();
    let other_lang_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("def ") || t.starts_with("from ") || t.starts_with("import ") && t.contains(" as ")
            || t.starts_with("func ") && (t.contains(" {") || t.contains(" () {"))
            || t.starts_with("pub fn ") || t.starts_with("fn ") || t.starts_with("let ")
            || t.starts_with("var ") && t.contains(":=")
            || t.starts_with("using ") && t.contains(';') && !t.contains(".")
            || t.starts_with("#include")
            || t.starts_with("#!")
            || t.starts_with("extends node2d") || t.starts_with("extends sprite")
    }).count();
    let java_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("package ") || t.starts_with("import ")
            || t.starts_with("public ") || t.starts_with("private ")
            || t.starts_with("protected ") || t.starts_with("@")
            || t.starts_with("class ") || t.starts_with("interface ")
            || t.starts_with("enum ") || t.starts_with("//")
            || t.starts_with("/*") || t.starts_with("*")
            || t.starts_with("}")
    }).count();
    // Structural check: real Java code always has lines ending in `;` or
    // containing `{` / `}`. Python (which also uses `import`) has none —
    // disambiguates `import asyncio` from `import java.util.List;`.
    let java_structured_lines = content.lines().filter(|l| {
        let t = l.trim_end();
        t.ends_with(';') || t.ends_with('{') || t.ends_with('}') || t.contains('{') || t.contains('}')
    }).count();
    if other_lang_lines > java_lines
        || java_kw_count == 0
        || java_structured_lines == 0
        || english_count > java_kw_count * 3 && java_kw_count < 20
    {
        result.latency_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    // F3 manifest gate: third-party import verification only runs when the
    // project has a Java build manifest. Without pom.xml/build.gradle there
    // is no Maven dependency context — routing imports to Maven Central
    // flags plausible packages the snippet merely references (bench/temp
    // projects, polyglot repos), pure FP surface.
    let has_java_manifest = !project_root.is_empty()
        && ["pom.xml", "build.gradle", "build.gradle.kts"]
            .iter()
            .any(|m| std::path::Path::new(project_root).join(m).exists());

    let terms = extract_java_imports(content);
    result.claims_extracted = terms.len();
    if !has_java_manifest {
        // No dependency context to verify against — record as unknown, not
        // hallucinated.
        result.claims_unknown += terms.len();
    } else {
        for pkg in &terms {
            if pkg.starts_with('.') || pkg.starts_with('/') {
                continue;
            }
            let status = crate::scanner::package_index::verify_import_with_language("java", pkg).await;
            match status {
                ImportStatus::NotFound => {
                    result.warnings.push(format!(
                        "hallucinated-import: `{}` — not found in Maven Central", pkg
                    ));
                    result.claims_hallucinated += 1;
                }
                ImportStatus::Verified => result.claims_verified += 1,
                _ => result.claims_unknown += 1,
            }
        }
        // Per-class symbol verification against Maven Central's fc: index.
        // Catches import-package confusion (e.g. `javax.xml.soap.QName` vs
        // `javax.xml.namespace.QName`) — both package prefixes resolve, but
        // only one contains the class. Existing `verify_import_with_language`
        // only checks groupId existence at top-2 segments, so it cannot catch
        // this class-of-confusion case.
        let symbol_warnings = crate::scanner::java_introspect::verify_java_import_symbols(content).await;
        if !symbol_warnings.is_empty() {
            result.claims_extracted += symbol_warnings.len();
            result.claims_hallucinated += symbol_warnings
                .iter()
                .filter(|w| w.contains("hallucinated"))
                .count();
            result.warnings.extend(symbol_warnings);
        }
    }

    let undefined = extract_java_undefined_variables(content);
    for name in &undefined {
        if name.len() >= 3 {
            result.warnings.push(format!(
                "hallucinated-variable: `{}` — referenced but not defined in scope", name
            ));
            result.claims_hallucinated += 1;
        }
    }
    result.claims_extracted += undefined.len();

    let java_receiver_map = crate::scanner::java_introspect::build_java_receiver_map(content);
    if !java_receiver_map.is_empty() {
        let method_warnings = crate::scanner::java_introspect::verify_java_methods(content, &java_receiver_map).await;
        result.claims_extracted += method_warnings.len();
        result.claims_hallucinated += method_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(method_warnings);
    }

    // Bare method calls within enclosing class (no `this.` prefix needed in Java).
    // Catches hallucinations like `incrementValue()` vs `increment()` where the
    // receiver is implicit (same class). Only fires if enclosing class has cached
    // method data — avoids FPs on classes not in the bundle.
    let bare_warnings = crate::scanner::java_introspect::verify_java_bare_methods(content);
    if !bare_warnings.is_empty() {
        result.claims_extracted += bare_warnings.len();
        result.claims_hallucinated += bare_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(bare_warnings);
    }

    let arity_warnings = check_call_arity(content);
    if !arity_warnings.is_empty() {
        result.claims_extracted += arity_warnings.len();
        result.claims_hallucinated += arity_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(arity_warnings);
    }

    result.latency_ms = start.elapsed().as_millis() as u64;
    result
}

static JAVA_KEYWORDS: Lazy<HashSet<&str>> = Lazy::new(|| {
    [
        "abstract", "assert", "boolean", "break", "byte", "case", "catch",
        "char", "class", "const", "continue", "default", "do", "double",
        "else", "enum", "extends", "final", "finally", "float", "for", "goto",
        "if", "implements", "import", "instanceof", "int", "interface", "long",
        "native", "new", "package", "private", "protected", "public", "return",
        "short", "static", "strictfp", "super", "switch", "synchronized",
        "this", "throw", "throws", "transient", "try", "void", "volatile",
        "while", "true", "false", "null", "String", "Integer", "Boolean",
        "Object", "System", "Math", "Exception", "List", "Map", "Set",
        "ArrayList", "HashMap", "HashSet", "Iterator", "Comparable",
        "Override", "FunctionalInterface",
        "java", "javax", "sun", "com", "org", "net", "io", "awl",
        "jdk", "module",
    ]
    .iter().copied().collect()
});

static CATCH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bcatch\s*\(\s*\w+(?:\.\w+)*\s+(\w+)\s*\)").unwrap()
});
static FOREACH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bfor\s*\(\s*\w+(?:\.\w+)*\s+(\w+)\s*:").unwrap()
});
/// Declared TYPE token in `UserDto dto = ...` / `List<Foo> items;` — the
/// type identifier itself is a type reference, not an undefined variable.
/// Uppercase-initial gate matches Java type convention; primitives are
/// lowercase and already keywords.
static TYPE_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Z]\w*)(?:\s*<[^<>]*>)?(?:\s*\[\s*\])*\s+\w+\s*[=;]").unwrap()
});
/// Declared name in class/interface/enum/record declarations.
static CLASS_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:class|interface|enum|record)\s+([A-Za-z_]\w*)").unwrap()
});
static IDENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([a-zA-Z_]\w*)").unwrap()
});

static JAVA_DECL_REGEXES: &[&Lazy<Regex>] =
    &[&CATCH_RE, &FOREACH_RE, &TYPE_DECL_RE, &CLASS_DECL_RE];

/// Java scope-extraction plug-in for the shared [`extract_undefined`] driver.
pub struct JavaScope;

impl ScopeExtractor for JavaScope {
    fn keywords(&self) -> &'static Lazy<HashSet<&'static str>> {
        &JAVA_KEYWORDS
    }

    fn ident_regex(&self) -> &'static Lazy<Regex> {
        &IDENT_RE
    }

    fn decl_regexes(&self) -> &'static [&'static Lazy<Regex>] {
        JAVA_DECL_REGEXES
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
        // `.` = property/qualified access; `@` = annotation name
        // (@Test, @Service); alphanumeric = qualified suffix.
        if prev_byte == b'.' || prev_byte == b'@' || prev_byte.is_ascii_alphanumeric() {
            return true;
        }
        // Import / package directive prefixes: the LEADING segment of
        // `import lombok.Builder;` or `import jakarta.persistence.*;` is a
        // package name, not a variable reference (task-010 e2e FP:
        // `hallucinated-variable: lombok`). Structural line-shape check -
        // no symbol list (Rule 8).
        let line_start = content[..match_start]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let line = &content[line_start..];
        let trimmed = line.trim_start();
        trimmed.starts_with("import ") || trimmed.starts_with("package ")
    }

    fn collect_param(&self, parts: &[&str]) -> Option<String> {
        if parts.len() >= 2 {
            Some(parts[parts.len() - 1].trim_start_matches('*').to_string())
        } else {
            None
        }
    }
}

/// Extract undefined variables from Java source via the shared scope-extractor
/// driver.
fn extract_java_undefined_variables(content: &str) -> Vec<String> {
    extract_undefined(content, &JavaScope)
}

/// Extract Java-specific import terms from `import X.Y.Z;` directives only.
///
/// Replaces the generic `extract_lookup_terms` call for Java. The generic
/// extractor pulls ClassName.method patterns (e.g. `SpringApplication.run`)
/// and Python/JS/Rust/Go patterns — none apply to Java imports. Result was
/// that class names mentioned in prose were routed to Maven Central and
/// flagged as hallucinated.
///
/// Only true `import X.Y.Z;` and `import static X.Y.Z;` directives count.
/// Returns the **top-2 segment group** (e.g. `org.springframework` from
/// `org.springframework.boot.SpringApplication`) — this is what Maven
/// Central's solrsearch resolves cleanly. Full multi-segment paths 404.
///
/// JDK classes (java.*, javax.*, com.sun.*, sun.*) skipped — handled by
/// `verify_import_with_language` upfront via Skipped status.
fn extract_java_imports(content: &str) -> HashSet<String> {
    let mut terms = HashSet::new();
    let import_re = regex::Regex::new(r"\bimport\s+(?:static\s+)?([a-zA-Z_][\w.]*)\s*;").unwrap();
    for caps in import_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            let segs: Vec<&str> = path.split('.').collect();
            // Skip JDK and module-info / package-info noise.
            if path.starts_with("java.")
                || path.starts_with("javax.")
                || path.starts_with("com.sun.")
                || path.starts_with("sun.")
                || path.starts_with("jdk.")
            {
                continue;
            }
            // Take top-2 segments as Maven groupId (org.springframework,
            // com.fasterxml.jackson, jakarta.persistence, etc.).
            let group = match segs.len() {
                0 => continue,
                1 => segs[0].to_string(),
                _ => format!("{}.{}", segs[0], segs[1]),
            };
            terms.insert(group.to_lowercase());
        }
    }
    terms
}

#[cfg(test)]
mod prose_guard_tests {
    use super::*;

    async fn run_and_count(content: &str) -> usize {
        let result = run_forge_java(content, "").await;
        result.warnings.len()
    }

    #[tokio::test]
    async fn pure_english_prose_no_warnings() {
        let content = "Now scaffold the Spring Boot application. Configure \
                       JPA, write entity classes, repository interfaces, and \
                       REST controllers. Run the app to verify.";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn python_code_contamination_no_warnings() {
        let content = "import asyncio\nfrom fastapi import FastAPI\n\napp = FastAPI()\n";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn gdscript_code_contamination_no_warnings() {
        let content = "extends Node2D\n\nfunc _ready():\n    print('hello')\n";
        assert_eq!(run_and_count(content).await, 0);
    }

    #[tokio::test]
    async fn real_java_with_undefined_var_still_flagged() {
        let content = "\
package com.example;\n\n\
public class Foo {\n\
    public void bar() {\n\
        undefinedThing.run();\n    }\n\
}\n";
        let result = run_forge_java(content, "").await;
        assert!(
            result.warnings.iter().any(|w| w.contains("undefinedThing")),
            "expected undefinedThing warning, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn extract_java_imports_skips_jdk() {
        let content = "import java.util.List;\nimport javax.persistence.Entity;\n\
                       import java.io.IOException;\nimport com.sun.net.ServerSocket;\n";
        let terms = extract_java_imports(content);
        assert!(terms.is_empty(), "JDK imports must not route to Maven, got: {:?}", terms);
    }

    #[test]
    fn extract_java_imports_takes_top2_segments_for_maven_group() {
        // Top-2 segments = Maven groupId for Spring, jakarta.* etc.
        // Known limitation: Jackson's real groupId is `com.fasterxml.jackson.core`
        // (3 segments), so top-2 `com.fasterxml` 404s on Maven. That case is
        // left as a soft FP rather than expanding to top-3 (which would
        // mis-route Spring sub-packages like `org.springframework.context`).
        let content = "import org.springframework.boot.SpringApplication;\n\
                       import org.springframework.web.bind.annotation.RestController;\n\
                       import jakarta.persistence.Entity;\n";
        let terms = extract_java_imports(content);
        assert!(terms.contains("org.springframework"), "got: {:?}", terms);
        assert!(terms.contains("jakarta.persistence"), "got: {:?}", terms);
        // Two unique groups after dedup (both Spring imports collapse).
        assert_eq!(terms.len(), 2, "got: {:?}", terms);
    }

    #[test]
    fn extract_java_imports_handles_static_imports() {
        let content = "import static org.junit.jupiter.api.Assertions.assertEquals;\n";
        let terms = extract_java_imports(content);
        assert!(terms.contains("org.junit"), "got: {:?}", terms);
    }

    #[test]
    fn extract_java_imports_ignores_class_refs_in_prose() {
        // Crucial fix: previously SpringApplication.run() / ResponseEntity.status
        // patterns in prose were extracted as imports and routed to Maven.
        let content = "Plan: use SpringApplication.run() to bootstrap, then \
                       expose endpoints with ResponseEntity.status() for \
                       error responses and Collections.emptyList() for \
                       empty lists.";
        let terms = extract_java_imports(content);
        assert!(terms.is_empty(), "class refs in prose must not be imports, got: {:?}", terms);
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn undefined(content: &str) -> Vec<String> {
        extract_java_undefined_variables(content)
    }

    #[test]
    fn f5_annotation_names_not_undefined() {
        // @Test / @Service names were referenced-but-undefined FPs.
        let content = "public class Foo {\n@Test\nvoid run() { }\n}\n";
        let names = undefined(content);
        assert!(!names.contains(&"Test".to_string()), "got: {:?}", names);
    }

    #[test]
    fn f5_qualified_annotation_not_undefined() {
        let content = "@org.junit.jupiter.api.Test\nvoid run() { }\n";
        let names = undefined(content);
        assert!(!names.contains(&"Test".to_string()), "got: {:?}", names);
    }

    #[test]
    fn f5_import_package_prefix_not_undefined() {
        // task-010 e2e FP: leading segment of an import directive flagged
        // as an undefined variable (`lombok`, `jakarta`).
        let content = "package com.example.event.model;\n\nimport jakarta.persistence.*;\nimport lombok.AllArgsConstructor;\nimport lombok.Builder;\n\npublic class Event {\n}\n";
        let names = undefined(content);
        assert!(!names.contains(&"lombok".to_string()), "got: {:?}", names);
        assert!(!names.contains(&"jakarta".to_string()), "got: {:?}", names);
        assert!(!names.contains(&"com".to_string()), "got: {:?}", names);
    }

    #[test]
    fn f6_declared_type_token_not_undefined() {
        // `UserDto dto = other;` — UserDto is a type reference, not a variable.
        let content = "void m() {\nUserDto dto = other;\n}\n";
        let names = undefined(content);
        assert!(!names.contains(&"UserDto".to_string()), "got: {:?}", names);
    }

    #[test]
    fn f6_array_declared_type_token_not_undefined() {
        let content = "void m() {\nUserDto[] dtos = src;\n}\n";
        let names = undefined(content);
        assert!(!names.contains(&"UserDto".to_string()), "got: {:?}", names);
    }

    #[test]
    fn f6_generic_container_type_not_undefined() {
        let content = "void m() {\nResult<UserDto> r = outcome;\n}\n";
        let names = undefined(content);
        assert!(!names.contains(&"Result".to_string()), "got: {:?}", names);
    }

    #[test]
    fn f7_class_name_not_undefined() {
        // Class used as return type without a `Type name =` decl shape.
        let content = "class OrderService { }\nOrderService create() { return null; }\n";
        let names = undefined(content);
        assert!(!names.contains(&"OrderService".to_string()), "got: {:?}", names);
    }

    #[test]
    fn f7_interface_and_record_names_not_undefined() {
        let content = "interface Repo { }\nrecord Point(int xy) { }\n\
                      Repo lookup() { return null; }\n";
        let names = undefined(content);
        assert!(!names.contains(&"Repo".to_string()), "got: {:?}", names);
        assert!(!names.contains(&"Point".to_string()), "got: {:?}", names);
    }

    #[test]
    fn truly_undefined_variable_still_flagged() {
        let content = "public class Foo {\npublic void bar() {\nundefinedThing.run();\n}\n}\n";
        let names = undefined(content);
        assert!(
            names.iter().any(|n| n == "undefinedThing"),
            "undefinedThing must stay flagged, got: {:?}", names
        );
    }
}
