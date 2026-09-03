//! String-filter helpers — extracted from forge_pipeline.rs (M1 chunk 4).
//!
//! Two utilities used by per-language runners to sanitize content before
//! scope analysis:
//!   - `filter_function_calls` — drop names that appear as `name(` calls
//!     (avoids FP when a library function name like `Pointer(` is also
//!     referenced without parens elsewhere).
//!   - `strip_c_style_string_literals` — blank out string literals +
//!     comments so the scope checker doesn't pick up identifiers inside
//!     format strings, error messages, import paths, etc.

/// Filter out names that appear as function calls in the content.
/// Reduces false positives from scope checkers flagging library function
/// names (e.g., `Pointer(`, `Builder()`) as undefined variables.
pub(crate) fn filter_function_calls(content: &str, names: Vec<String>) -> Vec<String> {
    let bytes = content.as_bytes();
    names.into_iter().filter(|name| {
        let mut search = 0;
        while let Some(pos) = content[search..].find(name.as_str()) {
            let abs = search + pos + name.len();
            let mut i = abs;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') { i += 1; }
            if i < bytes.len() && bytes[i] == b'(' {
                return false; // Found as function call — filter out
            }
            search = search + pos + 1;
        }
        true
    }).collect()
}

/// Replace string literals + comments with blank space so the scope checker
/// doesn't treat words inside strings (e.g. import paths, error messages,
/// format strings) as referenced identifiers.
///
/// This is the generic C-style stripping pass — works for Rust, Java, C#,
/// C++, JavaScript, TypeScript. Languages with raw-string quirks (Go's
/// backtick raw strings, Rust's r#"..."#) call this AND then apply their
/// own extra pass.
///
/// Handles:
///   - Line comments: // ...
///   - Block comments: /* ... */
///   - Double-quoted strings: "..." (with `\` escape)
///   - Single-char literals: 'x'
///
/// Preserves newlines so line/column math still produces sensible positions.
pub(crate) fn strip_c_style_string_literals(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // Line comment — skip to end of line.
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        // Block comment — skip to */.
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' { out.push('\n'); } else { out.push(' '); }
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(' ');
                out.push(' ');
                i += 2;
            }
            continue;
        }
        // Double-quoted string. Handles \" escapes.
        if b == b'"' {
            out.push(' ');
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(' ');
                    if bytes[i + 1] == b'\n' { out.push('\n'); } else { out.push(' '); }
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' {
                    // Interpreted strings can't span raw newlines, but be safe.
                    break;
                }
                out.push(' ');
                i += 1;
            }
            if i < bytes.len() { out.push(' '); i += 1; }
            continue;
        }
        // Single-char literal: 'x' or '\n' etc.
        if b == b'\'' {
            out.push(' ');
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(' '); out.push(' ');
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' { break; }
                out.push(' ');
                i += 1;
            }
            if i < bytes.len() { out.push(' '); i += 1; }
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_drops_names_followed_by_paren() {
        let names = vec!["Pointer".to_string(), "Builder".to_string(), "Other".to_string()];
        let content = "let x = Pointer(...); let y = Other; Builder()";
        let kept = filter_function_calls(content, names);
        assert_eq!(kept, vec!["Other".to_string()]);
    }

    #[test]
    fn filter_tolerates_whitespace_before_paren() {
        let names = vec!["foo".to_string()];
        let content = "foo  ()";
        let kept = filter_function_calls(content, names);
        assert!(kept.is_empty(), "foo() with spaces should be filtered, got {:?}", kept);
    }

    #[test]
    fn strip_blanks_line_comments() {
        let content = "let x = 1; // comment with import path\nlet y = 2;";
        let stripped = strip_c_style_string_literals(content);
        assert!(!stripped.contains("import"));
        assert!(stripped.contains("let x = 1;"));
        assert!(stripped.contains("let y = 2;"));
    }

    #[test]
    fn strip_blanks_block_comments() {
        let content = "let x = /* hidden identifier */ 5;";
        let stripped = strip_c_style_string_literals(content);
        assert!(!stripped.contains("hidden"));
        assert!(stripped.contains("5;"));
    }

    #[test]
    fn strip_blanks_double_quoted_strings() {
        let content = "let s = \"from langchain import Document\";";
        let stripped = strip_c_style_string_literals(content);
        assert!(!stripped.contains("langchain"));
        assert!(!stripped.contains("Document"));
    }

    #[test]
    fn strip_blanks_char_literals() {
        let content = "let c = 'x';";
        let stripped = strip_c_style_string_literals(content);
        // The 'x' should be replaced with spaces (preserving length).
        assert!(!stripped.contains("'x'"));
    }

    #[test]
    fn strip_preserves_newlines_in_block_comments() {
        let content = "/* multi\nline\ncomment */ let x = 1;";
        let stripped = strip_c_style_string_literals(content);
        let newline_count = stripped.matches('\n').count();
        assert_eq!(newline_count, 2, "should preserve 2 newlines from comment, got: {:?}", stripped);
    }

    #[test]
    fn strip_handles_escaped_quote_in_string() {
        let content = "let s = \"escaped \\\" quote\";";
        let stripped = strip_c_style_string_literals(content);
        assert!(!stripped.contains("escaped"));
    }
}
