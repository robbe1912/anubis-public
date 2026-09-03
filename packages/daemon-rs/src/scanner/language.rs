//! Type-safe language enum for the FORGE pipeline dispatch.
//!
//! Replaces the previous `language: &str` parameter. A typo like
//! `"TypeScript"` (capital T, capital S) used to silently hit the
//! `_ => return result` fallthrough arm — disabling scanning with
//! zero signal. This enum makes typos compile-time errors.
//!
//! Council #3 finding #8 (MEDIUM).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    TypeScript,
    JavaScript,
    Rust,
    Go,
    Java,
    CSharp,
    Cpp,
    C,
    GdScript,
    Tscn,
    GdShader,
    Unknown,
}

impl Language {
    /// Parse from a string slice. Case-insensitive.
    /// Returns `Language::Unknown` for unrecognized strings.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "python" => Self::Python,
            "typescript" => Self::TypeScript,
            "javascript" => Self::JavaScript,
            "rust" => Self::Rust,
            "go" => Self::Go,
            "java" => Self::Java,
            "csharp" => Self::CSharp,
            "cpp" => Self::Cpp,
            "c" => Self::C,
            "gdscript" => Self::GdScript,
            "tscn" => Self::Tscn,
            "gdshader" => Self::GdShader,
            _ => Self::Unknown,
        }
    }

    /// Return the lowercase string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::TypeScript => "typescript",
            Self::JavaScript => "javascript",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Java => "java",
            Self::CSharp => "csharp",
            Self::Cpp => "cpp",
            Self::C => "c",
            Self::GdScript => "gdscript",
            Self::Tscn => "tscn",
            Self::GdShader => "gdshader",
            Self::Unknown => "unknown",
        }
    }

    /// LSP `languageId` sent in `textDocument/didOpen` (FOUND-003).
    ///
    /// Returns `Some(id)` for the 8 LSP-supported languages in the pivot
    /// sprint (Rust, Go, Python, TypeScript, JavaScript, C++, C, CSharp);
    /// `None` for Java (out-of-sprint), Godot scene/shader languages
    /// (deferred per lsp-expansion-master.md), and `Unknown`.
    ///
    /// Per <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocumentItem>.
    pub fn lsp_language_id(&self) -> Option<&'static str> {
        match self {
            Self::Rust => Some("rust"),
            Self::Go => Some("go"),
            Self::Python => Some("python"),
            Self::TypeScript => Some("typescript"),
            Self::JavaScript => Some("javascript"),
            Self::Cpp => Some("cpp"),
            Self::C => Some("c"),
            Self::CSharp => Some("csharp"),
            // Java gets LSP later; Godot scene/shader languages deferred.
            Self::Java | Self::GdScript | Self::Tscn | Self::GdShader | Self::Unknown => None,
        }
    }

    /// Per-language LSP spawn config (FOUND-008).
    ///
    /// Returns `Some(&cfg)` for the 8 LSP-supported languages in the pivot
    /// sprint (Rust, Go, Python, TypeScript, JavaScript, C++, C, CSharp);
    /// `None` for Java (out-of-sprint), Godot scene/shader languages
    /// (deferred per lsp-expansion-master.md), and `Unknown`.
    ///
    /// Configs live as `Lazy<LspSpawnConfig>` statics in
    /// [`crate::scanner::lsp_config`]. They are spawn recipes only — the
    /// registry (FOUND-005) owns the actual client lifecycle.
    pub fn lsp_config(&self) -> Option<&'static crate::scanner::lsp_config::LspSpawnConfig> {
        use crate::scanner::lsp_config::{C, CPP, CSHARP, GO, JAVASCRIPT, PYTHON, RUST, TYPESCRIPT};
        let cfg = match self {
            Self::Rust => &*RUST,
            Self::Go => &*GO,
            Self::Python => &*PYTHON,
            Self::TypeScript => &*TYPESCRIPT,
            Self::JavaScript => &*JAVASCRIPT,
            Self::Cpp => &*CPP,
            Self::C => &*C,
            Self::CSharp => &*CSHARP,
            // Java: not in current sprint. Godot scene/shader: deferred.
            Self::Java | Self::GdScript | Self::Tscn | Self::GdShader | Self::Unknown => return None,
        };
        Some(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_roundtrip() {
        for lang in [
            Language::Python, Language::TypeScript, Language::JavaScript,
            Language::Rust, Language::Go, Language::Java, Language::CSharp,
            Language::Cpp, Language::C, Language::GdScript, Language::Tscn,
            Language::GdShader,
        ] {
            assert_eq!(Language::from_str(lang.as_str()), lang);
        }
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!(Language::from_str("Python"), Language::Python);
        assert_eq!(Language::from_str("TYPESCRIPT"), Language::TypeScript);
        assert_eq!(Language::from_str("Rust"), Language::Rust);
    }

    #[test]
    fn from_str_unknown() {
        assert_eq!(Language::from_str("TypeScript"), Language::TypeScript);
        assert_eq!(Language::from_str("cobol"), Language::Unknown);
        assert_eq!(Language::from_str(""), Language::Unknown);
    }

    #[test]
    fn lsp_language_id_roundtrip_8_supported_langs() {
        // Per lsp-expansion-master.md: 8 LSP-supported languages.
        let supported = [
            (Language::Rust, "rust"),
            (Language::Go, "go"),
            (Language::Python, "python"),
            (Language::TypeScript, "typescript"),
            (Language::JavaScript, "javascript"),
            (Language::Cpp, "cpp"),
            (Language::C, "c"),
            (Language::CSharp, "csharp"),
        ];
        for (lang, expected_id) in supported {
            assert_eq!(
                lang.lsp_language_id(),
                Some(expected_id),
                "language {:?} languageId mismatch",
                lang,
            );
        }
    }

    #[test]
    fn lsp_language_id_none_for_out_of_scope_langs() {
        // Java: not in current sprint. Godot scene/shader: deferred. Unknown.
        for lang in [
            Language::Java,
            Language::GdScript,
            Language::Tscn,
            Language::GdShader,
            Language::Unknown,
        ] {
            assert_eq!(
                lang.lsp_language_id(),
                None,
                "language {:?} should have no languageId",
                lang,
            );
        }
    }

    #[test]
    fn lsp_config_returns_some_for_8_supported_langs_after_found_008() {
        // FOUND-008 wired real configs. All 8 should return Some.
        for lang in [
            Language::Rust,
            Language::Go,
            Language::Python,
            Language::TypeScript,
            Language::JavaScript,
            Language::Cpp,
            Language::C,
            Language::CSharp,
        ] {
            let cfg = lang.lsp_config();
            assert!(cfg.is_some(), "language {:?} should have a config post-FOUND-008", lang);
            // languageId must match the canonical LSP value.
            assert_eq!(
                cfg.unwrap().language_id,
                lang.lsp_language_id().unwrap(),
                "language {:?}: lsp_config().language_id != lsp_language_id()",
                lang,
            );
        }
    }

    #[test]
    fn lsp_config_returns_none_for_out_of_scope_langs() {
        for lang in [Language::Java, Language::GdScript, Language::Tscn, Language::GdShader, Language::Unknown] {
            assert!(lang.lsp_config().is_none(), "language {:?} should have no config", lang);
        }
    }
}
