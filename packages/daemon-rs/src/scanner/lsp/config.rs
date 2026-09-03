//! LSP spawn config + workspace root detection (COLD-001 façade).
//!
//! Re-exports the implementation in `scanner::lsp_config` (added in
//! FOUND-002 + FOUND-008). Kept as a separate module so callers can write
//! `scanner::lsp::config::LspSpawnConfig` per the master plan naming.

pub use crate::scanner::lsp_config::{
    detect_workspace_root, probe_csharp_sdk, csharp_sdk_status,
    CsharpSdkStatus, LspSpawnConfig,
    CSHARP, CPP, C, GO, JAVASCRIPT, PYTHON, RUST, TYPESCRIPT,
};

/// Convenience: look up the spawn config for a `Language` (COLD-002).
///
/// Returns `Some(&'static LspSpawnConfig)` for the 8 LSP-supported languages
/// wired in FOUND-008, `None` for out-of-scope languages (Java/Godot langs).
///
/// Re-exports what `Language::lsp_config()` already returns so callers can
/// either go via the enum or via this table-lookup style — whichever reads
/// better at the call site.
pub fn config_for(language: crate::scanner::language::Language) -> Option<&'static LspSpawnConfig> {
    language.lsp_config()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::language::Language;

    #[test]
    fn config_for_rust_returns_some_with_rust_analyzer_cmd() {
        let cfg = config_for(Language::Rust).expect("Rust config exists");
        assert_eq!(cfg.cmd, "rust-analyzer");
    }

    #[test]
    fn config_for_out_of_scope_langs_returns_none() {
        assert!(config_for(Language::Java).is_none());
        assert!(config_for(Language::GdScript).is_none());
        assert!(config_for(Language::Unknown).is_none());
    }

    #[test]
    fn all_8_supported_langs_have_configs() {
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
            assert!(
                config_for(lang).is_some(),
                "{:?} should have a config",
                lang,
            );
        }
    }
}
