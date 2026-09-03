//! SQLite-backed local symbol cache.
//!
//! Lives at ~/.anubis/symbols/cache.sqlite. Stores one row per
//! (library, version, path) triple. Queried by scanner Layer 1.5
//! for hallucination detection against locally-known symbols.

use crate::symbols::types::{Param, Symbol, SymbolKind, Visibility};
use rusqlite::{params, Connection};

/// Path to the on-disk cache file: `~/.anubis/symbols/cache.sqlite`.
pub fn cache_path() -> std::path::PathBuf {
    crate::dirs_home()
        .join(".anubis")
        .join("symbols")
        .join("cache.sqlite")
}

/// Persistent SQLite-backed symbol cache.
pub struct SymbolCache {
    conn: Connection,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS symbols (
    library             TEXT NOT NULL,
    version             TEXT NOT NULL,
    path                TEXT NOT NULL,
    name                TEXT NOT NULL,
    kind                TEXT NOT NULL,
    signature           TEXT,
    params_json         TEXT,
    return_type         TEXT,
    doc_text            TEXT,
    source_file         TEXT,
    visibility          TEXT NOT NULL,
    is_deprecated       INTEGER NOT NULL DEFAULT 0,
    deprecated_message  TEXT,
    extracted_at        INTEGER NOT NULL,
    PRIMARY KEY (library, version, path)
);

CREATE INDEX IF NOT EXISTS idx_symbols_lib_name ON symbols(library, name);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_lib_ver ON symbols(library, version);
"#;

/// SQLITE_BUSY retry budget (matches spec: 3 attempts × 100ms backoff).
const BUSY_RETRIES: u32 = 3;
const BUSY_BACKOFF_MS: u64 = 100;

impl SymbolCache {
    /// Open or create the cache at `~/.anubis/symbols/cache.sqlite`.
    /// Idempotently applies schema migrations.
    pub fn open() -> Result<Self, String> {
        let path = cache_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create cache dir {parent:?}: {e}"))?;
        }
        let conn = open_with_retry(&path)?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (for tests). Same schema as on-disk.
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("open_in_memory failed: {e}"))?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    fn init(conn: &Connection) -> Result<(), String> {
        // SQLite-native busy handler covers the 3 × 100ms retry budget
        // for every statement on this connection.
        conn.busy_timeout(std::time::Duration::from_millis(
            BUSY_RETRIES as u64 * BUSY_BACKOFF_MS,
        ))
        .map_err(|e| format!("busy_timeout: {e}"))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("schema migration: {e}"))?;
        Ok(())
    }

    /// Insert (or replace) a batch of symbols atomically.
    /// Returns count of rows written.
    pub fn insert_many(&self, symbols: &[Symbol]) -> Result<usize, String> {
        if symbols.is_empty() {
            return Ok(0);
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin tx: {e}"))?;
        let mut written = 0usize;
        for s in symbols {
            let params_json = if s.params.is_empty() {
                None
            } else {
                Some(
                    serde_json::to_string(&s.params)
                        .map_err(|e| format!("params json: {e}"))?,
                )
            };
            tx.execute(
                "INSERT OR REPLACE INTO symbols
                 (library, version, path, name, kind, signature, params_json,
                  return_type, doc_text, source_file, visibility, is_deprecated,
                  deprecated_message, extracted_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    &s.library,
                    &s.version,
                    &s.path,
                    &s.name,
                    kind_to_str(s.kind),
                    s.signature.as_deref(),
                    params_json.as_deref(),
                    s.return_type.as_deref(),
                    s.doc_text.as_deref(),
                    s.source_file.as_deref(),
                    visibility_to_str(s.visibility),
                    s.is_deprecated as i64,
                    s.deprecated_message.as_deref(),
                    s.extracted_at as i64,
                ],
            )
            .map_err(|e| format!("insert: {e}"))?;
            written += 1;
        }
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok(written)
    }

    /// Remove all symbols for a (library, version) pair atomically.
    /// Returns count of rows removed.
    pub fn remove_library(&self, library: &str, version: &str) -> Result<usize, String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin tx: {e}"))?;
        let removed = tx
            .execute(
                "DELETE FROM symbols WHERE library = ? AND version = ?",
                params![library, version],
            )
            .map_err(|e| format!("delete: {e}"))?;
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok(removed)
    }

    /// Look up a symbol by (library, name) using the latest available version.
    ///
    /// `name` may be either a bare symbol name (`"apply_scale"`) or a dotted
    /// path (`"Node2D.apply_scale"`). The last segment is matched against the
    /// `name` column; the full input is also matched against `path` for the
    /// exact-path case.
    pub fn lookup(&self, library: &str, name: &str) -> Option<Symbol> {
        let suffix = name.rsplit('.').next().unwrap_or(name);
        let is_path = name.contains('.');

        // When query is a dotted path (e.g. "Node2D.apply_scale"), match by PATH
        // only. This prevents cross-class false matches where Node2D.distance_to
        // incorrectly matches Vector2.distance_to (same suffix, different class).
        //
        // When query is a bare name (e.g. "apply_scale"), match by name suffix.
        let (sql, params_vec): (&str, Vec<&str>) = if is_path {
            (
                "SELECT library, version, path, name, kind, signature, params_json,
                        return_type, doc_text, source_file, visibility, is_deprecated,
                        deprecated_message, extracted_at
                 FROM symbols
                 WHERE library = ? AND path = ?
                 ORDER BY version DESC
                 LIMIT 1",
                vec![library, name],
            )
        } else {
            (
                "SELECT library, version, path, name, kind, signature, params_json,
                        return_type, doc_text, source_file, visibility, is_deprecated,
                        deprecated_message, extracted_at
                 FROM symbols
                 WHERE library = ? AND name = ?
                 ORDER BY version DESC
                 LIMIT 1",
                vec![library, suffix],
            )
        };

        let mut stmt = self.conn.prepare(sql).ok()?;
        let row = stmt.query_row(
            params![params_vec[0], params_vec[1]],
            row_to_symbol,
        );
        row.ok()
    }

    /// Look up all symbols matching `name` across every cached library.
    /// Matches both bare-name and dotted-path queries (see [`lookup`]).
    /// Look up all symbols whose path starts with `prefix` in a specific library.
    /// Used for finding all methods on a class (prefix = "ClassName.").
    pub fn lookup_prefix(&self, library: &str, prefix: &str) -> Vec<Symbol> {
        let pattern = format!("{}%", prefix);
        let mut stmt = match self.conn.prepare(
            "SELECT library, version, path, name, kind, signature, params_json,
                    return_type, doc_text, source_file, visibility, is_deprecated,
                    deprecated_message, extracted_at
             FROM symbols
             WHERE library = ? AND path LIKE ?
             ORDER BY version DESC"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![library, pattern], row_to_symbol);
        match rows {
            Ok(r) => r.filter_map(|x| x.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }
    pub fn lookup_global(&self, name: &str) -> Vec<Symbol> {
        let suffix = name.rsplit('.').next().unwrap_or(name);
        let mut stmt = match self.conn.prepare(
            "SELECT library, version, path, name, kind, signature, params_json,
                    return_type, doc_text, source_file, visibility, is_deprecated,
                    deprecated_message, extracted_at
             FROM symbols
             WHERE name = ? OR path = ?
             ORDER BY library, version DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![suffix, name], row_to_symbol);
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// List all (library, version, symbol_count) pairs cached locally.
    pub fn list_libraries(&self) -> Vec<(String, String, usize)> {
        let mut stmt = match self.conn.prepare(
            "SELECT library, version, COUNT(*) AS cnt
             FROM symbols
             GROUP BY library, version
             ORDER BY library, version",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |row| {
            let lib: String = row.get(0)?;
            let ver: String = row.get(1)?;
            let cnt: i64 = row.get(2)?;
            Ok((lib, ver, cnt as usize))
        });
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Total symbol count (debug + observability).
    pub fn count(&self) -> Result<usize, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM symbols", [], |row| {
                let n: i64 = row.get(0)?;
                Ok(n as usize)
            })
            .map_err(|e| format!("count: {e}"))
    }

    /// Find class-like names sharing a prefix across all cached libraries.
    ///
    /// Used by `check_symbols` to suggest corrections when an unknown class
    /// name appears in code (e.g., `PolynomialTransformer.fit()` — suggests
    /// `PolynomialFeatures` if cached). Returns `(library, class_name)` pairs.
    /// Caps at 50 candidates to bound cost.
    pub fn find_classes_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        if prefix.is_empty() {
            return Vec::new();
        }
        let mut stmt = match self.conn.prepare(
            "SELECT DISTINCT name, library FROM symbols
             WHERE name LIKE ?1 || '%'
             AND kind IN ('class', 'interface', 'struct', 'type_alias')
             LIMIT 50",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![prefix], |row| {
            let name: String = row.get(0)?;
            let lib: String = row.get(1)?;
            Ok((lib, name))
        });
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Find symbols of ANY kind (class, function, constant, method, ...)
    /// whose `name` starts with `prefix`, across every cached library.
    ///
    /// Unlike [`find_classes_with_prefix`], this includes functions and
    /// constants — needed for bare-function hallucination detection where
    /// the closest match to a hallucinated free function (e.g. `rescale`)
    /// is another free function (e.g. `reshape`), not a class.
    /// Returns (library, name, kind) tuples. Caps at 100 candidates.
    pub fn find_symbols_with_prefix(&self, prefix: &str) -> Vec<(String, String, String)> {
        if prefix.is_empty() {
            return Vec::new();
        }
        let mut stmt = match self.conn.prepare(
            "SELECT DISTINCT name, library, kind FROM symbols
             WHERE name LIKE ?1 || '%'
             LIMIT 100",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![prefix], |row| {
            let name: String = row.get(0)?;
            let lib: String = row.get(1)?;
            let kind: String = row.get(2)?;
            Ok((lib, name, kind))
        });
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Seed the cache from a JSONL bundle file (one Symbol per line).
    ///
    /// Each line must be valid JSON matching the SQLite schema:
    /// `library`, `version`, `path`, `name`, `kind`, `signature`, `params_json`,
    /// `return_type`, `doc_text`, `source_file`, `visibility`, `is_deprecated`,
    /// `deprecated_message`, `extracted_at`.
    ///
    /// Lines starting with `#` or blank are skipped. Returns count of inserted rows.
    ///
    /// **Clean semantics**: every (library, version) pair encountered in the
    /// bundle is DELETEd before any INSERT. This ensures entries removed from
    /// the bundle (e.g. a previously-bundled hallucinated function) do not
    /// linger in the cache and silently mask future detections. Stale rows
    /// are the same kind of bug as a wrong row — both produce wrong verdicts.
    pub fn seed_from_jsonl(&self, path: &std::path::Path) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;

        // Pass 1: collect every (library, version) pair present in the bundle
        // so we can wipe them before inserting. Without this, deleting a row
        // from the bundle has no effect on an already-seeded cache.
        let mut libs_to_clean: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        for raw in content.lines() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(obj) = v.as_object() {
                    let lib = obj.get("library").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let ver = obj.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    if !lib.is_empty() {
                        libs_to_clean.insert((lib, ver));
                    }
                }
            }
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("tx: {e}"))?;

        // Wipe every (library, version) the bundle is about to repopulate.
        // Uses parameterized IN clause via temporary table to avoid SQL
        // injection and to handle arbitrary set sizes.
        for (lib, ver) in &libs_to_clean {
            tx.execute(
                "DELETE FROM symbols WHERE library = ? AND version = ?",
                rusqlite::params![lib, ver],
            )
            .map_err(|e| format!("delete ({lib}, {ver}): {e}"))?;
        }

        let mut inserted = 0usize;
        for (lineno, raw) in content.lines().enumerate() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    // Pass 1 above silently skips malformed lines (gated by
                    // `if let Ok`). Pass 2 must match that lenient behaviour
                    // or a single corrupted bundle line (e.g. stderr leak
                    // from a fetch script accidentally appended to the JSONL)
                    // would abort daemon startup. Log + skip instead.
                    tracing::warn!(
                        target: "symbol_cache",
                        bundle = %path.display(),
                        line = lineno + 1,
                        error = %e,
                        "skipping malformed JSON line in bundle",
                    );
                    continue;
                }
            };
            let s = match v.as_object() {
                Some(obj) => obj,
                None => {
                    tracing::warn!(
                        target: "symbol_cache",
                        bundle = %path.display(),
                        line = lineno + 1,
                        "skipping non-object JSON line in bundle",
                    );
                    continue;
                }
            };
            let get_str = |k: &str| s.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let get_i64 = |k: &str| s.get(k).and_then(|x| x.as_i64()).unwrap_or(0);

            // Schema validation (cache-poisoning defense per council P1).
            // A legitimate symbol bundle entry must have a non-empty `name`
            // — entries with just library/version but no symbol name are
            // useless and suspicious (attacker could inject rows that bloat
            // the cache or mask real symbols). Skip + warn.
            let entry_name = get_str("name");
            if entry_name.is_empty() {
                tracing::warn!(
                    target: "symbol_cache",
                    bundle = %path.display(),
                    line = lineno + 1,
                    library = %get_str("library"),
                    "skipping bundle entry with empty `name` — possible cache poisoning",
                );
                continue;
            }

            // Validate `kind` is in known set (warn only, don't skip —
            // forward compatibility with new kinds).
            const KNOWN_KINDS: &[&str] = &[
                "function", "method", "class", "module", "variable",
                "constant", "type", "interface", "enum", "trait",
                "macro", "attribute", "constructor", "namespace",
            ];
            let entry_kind = get_str("kind");
            if !entry_kind.is_empty() && !KNOWN_KINDS.contains(&entry_kind.as_str()) {
                tracing::warn!(
                    target: "symbol_cache",
                    bundle = %path.display(),
                    line = lineno + 1,
                    library = %get_str("library"),
                    kind = %entry_kind,
                    "unusual `kind` in bundle entry — verify source",
                );
            }

            tx.execute(
                "INSERT OR REPLACE INTO symbols
                 (library, version, path, name, kind, signature, params_json,
                  return_type, doc_text, source_file, visibility, is_deprecated,
                  deprecated_message, extracted_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    get_str("library"),
                    get_str("version"),
                    get_str("path"),
                    get_str("name"),
                    get_str("kind"),
                    s.get("signature").and_then(|x| x.as_str()),
                    s.get("params_json").and_then(|x| x.as_str()),
                    s.get("return_type").and_then(|x| x.as_str()),
                    s.get("doc_text").and_then(|x| x.as_str()),
                    s.get("source_file").and_then(|x| x.as_str()),
                    get_str("visibility"),
                    get_i64("is_deprecated"),
                    s.get("deprecated_message").and_then(|x| x.as_str()),
                    get_i64("extracted_at"),
                ],
            )
            .map_err(|e| format!("bundle {}:{}: insert: {}", path.display(), lineno + 1, e))?;
            inserted += 1;
        }
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok(inserted)
    }
}

/// Open a connection to `path`, retrying on SQLITE_BUSY up to 3 times.
fn open_with_retry(path: &std::path::Path) -> Result<Connection, String> {
    let mut last_err: Option<rusqlite::Error> = None;
    for _ in 0..BUSY_RETRIES {
        match Connection::open(path) {
            Ok(c) => return Ok(c),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(BUSY_BACKOFF_MS));
            }
        }
    }
    Err(format!(
        "open {path:?} failed after {BUSY_RETRIES} retries: {}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Decode a row into a `Symbol`, mapping DB strings back to enum variants.
fn row_to_symbol(row: &rusqlite::Row<'_>) -> rusqlite::Result<Symbol> {
    let library: String = row.get(0)?;
    let version: String = row.get(1)?;
    let path: String = row.get(2)?;
    let name: String = row.get(3)?;
    let kind_str: String = row.get(4)?;
    let signature: Option<String> = row.get(5)?;
    let params_json: Option<String> = row.get(6)?;
    let return_type: Option<String> = row.get(7)?;
    let doc_text: Option<String> = row.get(8)?;
    let source_file: Option<String> = row.get(9)?;
    let visibility_str: String = row.get(10)?;
    let is_deprecated: i64 = row.get(11)?;
    let deprecated_message: Option<String> = row.get(12)?;
    let extracted_at: i64 = row.get(13)?;

    let params: Vec<Param> = match params_json.as_deref() {
        Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_default(),
        _ => Vec::new(),
    };
    let kind = kind_from_str(&kind_str).unwrap_or(SymbolKind::Method);
    let visibility = visibility_from_str(&visibility_str).unwrap_or(Visibility::Public);

    Ok(Symbol {
        library,
        version,
        path,
        name,
        kind,
        signature,
        params,
        return_type,
        doc_text,
        source_file,
        visibility,
        is_deprecated: is_deprecated != 0,
        deprecated_message,
        extracted_at: extracted_at.max(0) as u64,
    })
}

fn kind_to_str(k: SymbolKind) -> &'static str {
    match k {
        SymbolKind::Class => "class",
        SymbolKind::Method => "method",
        SymbolKind::Function => "function",
        SymbolKind::Property => "property",
        SymbolKind::Signal => "signal",
        SymbolKind::Constant => "constant",
        SymbolKind::Enum => "enum",
        SymbolKind::EnumMember => "enum_member",
        SymbolKind::Annotation => "annotation",
        SymbolKind::Interface => "interface",
        SymbolKind::TypeAlias => "type_alias",
        SymbolKind::Module => "module",
        SymbolKind::Constructor => "constructor",
    }
}

fn kind_from_str(s: &str) -> Option<SymbolKind> {
    Some(match s {
        "class" => SymbolKind::Class,
        "method" => SymbolKind::Method,
        "function" => SymbolKind::Function,
        "property" => SymbolKind::Property,
        "signal" => SymbolKind::Signal,
        "constant" => SymbolKind::Constant,
        "enum" => SymbolKind::Enum,
        "enum_member" => SymbolKind::EnumMember,
        "annotation" => SymbolKind::Annotation,
        "interface" => SymbolKind::Interface,
        "type_alias" => SymbolKind::TypeAlias,
        "module" => SymbolKind::Module,
        "constructor" => SymbolKind::Constructor,
        _ => return None,
    })
}

fn visibility_to_str(v: Visibility) -> &'static str {
    match v {
        Visibility::Public => "public",
        Visibility::Protected => "protected",
        Visibility::Private => "private",
        Visibility::Internal => "internal",
    }
}

fn visibility_from_str(s: &str) -> Option<Visibility> {
    Some(match s {
        "public" => Visibility::Public,
        "protected" => Visibility::Protected,
        "private" => Visibility::Private,
        "internal" => Visibility::Internal,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::types::{Param, SymbolKind, Visibility};

    fn make_symbol(library: &str, version: &str, path: &str) -> Symbol {
        let mut s = Symbol::new(library, version, path);
        s.extracted_at = 1_700_000_000;
        s
    }

    fn make_full_symbol() -> Symbol {
        let mut s = Symbol::new("godot", "4.3", "Node2D.apply_scale");
        s.kind = SymbolKind::Method;
        s.signature = Some("apply_scale(ratio: Vector2) -> void".into());
        s.params.push(Param {
            name: "ratio".into(),
            type_name: "Vector2".into(),
            default_value: None,
        });
        s.return_type = Some("void".into());
        s.doc_text = Some("Multiplies the current scale by the ratio vector.".into());
        s.source_file = Some("classes/node2d.xml".into());
        s.visibility = Visibility::Public;
        s.is_deprecated = false;
        s.deprecated_message = None;
        s.extracted_at = 1_700_000_000;
        s
    }

    #[test]
    fn open_in_memory_starts_empty() {
        let cache = SymbolCache::open_in_memory().unwrap();
        assert_eq!(cache.count().unwrap(), 0);
    }

    #[test]
    fn empty_cache_lookup_returns_none() {
        let cache = SymbolCache::open_in_memory().unwrap();
        assert!(cache.lookup("godot", "apply_scale").is_none());
        assert!(cache.lookup_global("useState").is_empty());
    }

    #[test]
    fn insert_many_then_count_returns_three() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let symbols = vec![
            make_symbol("test_lib", "1.0.0", "ClassA.method_name"),
            make_symbol("test_lib", "1.0.0", "ClassB.method_name"),
            make_symbol("test_lib", "1.0.0", "ClassC.other_method"),
        ];
        let written = cache.insert_many(&symbols).unwrap();
        assert_eq!(written, 3);
        assert_eq!(cache.count().unwrap(), 3);
        let hit = cache.lookup("test_lib", "method_name").expect("expected hit");
        assert_eq!(hit.library, "test_lib");
        assert_eq!(hit.name, "method_name");
        assert!(hit.path.ends_with(".method_name"));
    }

    #[test]
    fn insert_many_returns_full_symbol_fields() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let original = make_full_symbol();
        cache.insert_many(&[original.clone()]).unwrap();
        let hit = cache.lookup("godot", "apply_scale").expect("expected hit");
        assert_eq!(hit, original);
    }

    #[test]
    fn insert_many_twice_replaces_on_primary_key_conflict() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let mut v1 = make_symbol("lib", "1.0.0", "Klass.foo");
        v1.doc_text = Some("original".into());
        cache.insert_many(&[v1.clone()]).unwrap();
        assert_eq!(cache.count().unwrap(), 1);

        let mut v2 = make_symbol("lib", "1.0.0", "Klass.foo");
        v2.doc_text = Some("replaced".into());
        v2.signature = Some("foo() -> int".into());
        cache.insert_many(&[v2.clone()]).unwrap();

        assert_eq!(cache.count().unwrap(), 1);
        let hit = cache.lookup("lib", "foo").unwrap();
        assert_eq!(hit.doc_text.as_deref(), Some("replaced"));
        assert_eq!(hit.signature.as_deref(), Some("foo() -> int"));
    }

    #[test]
    fn lookup_by_bare_name_finds_path_suffix_match() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[make_symbol("godot", "4.3", "Node2D.apply_scale")])
            .unwrap();
        let hit = cache
            .lookup("godot", "apply_scale")
            .expect("bare-name lookup should hit");
        assert_eq!(hit.path, "Node2D.apply_scale");
        assert_eq!(hit.name, "apply_scale");
    }

    #[test]
    fn lookup_by_full_path_matches_exact() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[make_symbol("godot", "4.3", "Node2D.apply_scale")])
            .unwrap();
        let hit = cache
            .lookup("godot", "Node2D.apply_scale")
            .expect("full-path lookup should hit");
        assert_eq!(hit.path, "Node2D.apply_scale");
    }

    #[test]
    fn lookup_returns_latest_version() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let mut old = make_symbol("godot", "4.2", "Node2D.apply_scale");
        old.signature = Some("old".into());
        let mut new = make_symbol("godot", "4.3", "Node2D.apply_scale");
        new.signature = Some("new".into());
        cache.insert_many(&[old, new]).unwrap();
        let hit = cache.lookup("godot", "apply_scale").unwrap();
        assert_eq!(hit.version, "4.3");
        assert_eq!(hit.signature.as_deref(), Some("new"));
    }

    #[test]
    fn lookup_misses_when_library_differs() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[make_symbol("godot", "4.3", "Node2D.apply_scale")])
            .unwrap();
        assert!(cache.lookup("react", "apply_scale").is_none());
    }

    #[test]
    fn lookup_global_finds_across_libraries() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[
                make_symbol("react", "18.2.0", "useState"),
                make_symbol("preact", "10.19.0", "useState"),
                make_symbol("godot", "4.3", "Node2D.apply_scale"),
            ])
            .unwrap();
        let hits = cache.lookup_global("useState");
        let libs: Vec<&str> = hits.iter().map(|s| s.library.as_str()).collect();
        assert!(libs.contains(&"react"));
        assert!(libs.contains(&"preact"));
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn lookup_global_accepts_dotted_path() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[make_symbol("godot", "4.3", "Node2D.apply_scale")])
            .unwrap();
        let hits = cache.lookup_global("Node2D.apply_scale");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "apply_scale");
    }

    #[test]
    fn remove_library_deletes_only_matching_rows() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[
                make_symbol("godot", "4.3", "Node2D.apply_scale"),
                make_symbol("godot", "4.2", "Node2D.apply_scale"),
                make_symbol("react", "18.2.0", "useState"),
            ])
            .unwrap();
        assert_eq!(cache.count().unwrap(), 3);

        let removed = cache.remove_library("godot", "4.2").unwrap();
        assert_eq!(removed, 1);
        assert_eq!(cache.count().unwrap(), 2);
        assert!(cache.lookup("godot", "apply_scale").is_some());
        assert!(cache.lookup("react", "useState").is_some());
    }

    #[test]
    fn remove_library_returns_zero_when_no_match() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[make_symbol("godot", "4.3", "Node2D.apply_scale")])
            .unwrap();
        let removed = cache.remove_library("nonexistent", "0.0.0").unwrap();
        assert_eq!(removed, 0);
        assert_eq!(cache.count().unwrap(), 1);
    }

    #[test]
    fn list_libraries_aggregates_counts_by_pair() {
        let cache = SymbolCache::open_in_memory().unwrap();
        cache
            .insert_many(&[
                make_symbol("godot", "4.3", "Node2D.foo"),
                make_symbol("godot", "4.3", "Node2D.bar"),
                make_symbol("godot", "4.2", "Node2D.baz"),
                make_symbol("react", "18.2.0", "useState"),
            ])
            .unwrap();
        let libs = cache.list_libraries();
        let mut sorted: Vec<_> = libs;
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                ("godot".to_string(), "4.2".to_string(), 1usize),
                ("godot".to_string(), "4.3".to_string(), 2usize),
                ("react".to_string(), "18.2.0".to_string(), 1usize),
            ]
        );
    }

    #[test]
    fn params_json_round_trip_preserves_struct() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let mut s = make_symbol("lib", "1.0.0", "Mod.fn");
        s.kind = SymbolKind::Method;
        s.params.push(Param {
            name: "ratio".into(),
            type_name: "Vector2".into(),
            default_value: None,
        });
        s.params.push(Param {
            name: "depth".into(),
            type_name: "int".into(),
            default_value: Some("1".into()),
        });
        cache.insert_many(&[s.clone()]).unwrap();
        let hit = cache.lookup("lib", "fn").unwrap();
        assert_eq!(hit.params, s.params);
        assert_eq!(hit.params.len(), 2);
        assert_eq!(hit.params[1].default_value.as_deref(), Some("1"));
    }

    #[test]
    fn empty_params_round_trip_to_empty_vec() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let s = make_symbol("lib", "1.0.0", "Mod.constant");
        cache.insert_many(&[s.clone()]).unwrap();
        let hit = cache.lookup("lib", "constant").unwrap();
        assert!(hit.params.is_empty());
    }

    #[test]
    fn all_kind_variants_round_trip() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let kinds = vec![
            (SymbolKind::Class, "Class"),
            (SymbolKind::Method, "method"),
            (SymbolKind::Function, "fn"),
            (SymbolKind::Property, "prop"),
            (SymbolKind::Signal, "sig"),
            (SymbolKind::Constant, "MAX"),
            (SymbolKind::Enum, "Kind"),
            (SymbolKind::EnumMember, "KindA"),
            (SymbolKind::Annotation, "tool"),
            (SymbolKind::Interface, "IFace"),
            (SymbolKind::TypeAlias, "Alias"),
            (SymbolKind::Module, "mod"),
            (SymbolKind::Constructor, "new"),
        ];
        let symbols: Vec<Symbol> = kinds
            .iter()
            .enumerate()
            .map(|(i, (k, name))| {
                let mut s = Symbol::new("kinds", "1.0.0", format!("Ctx.{name}_{i}"));
                s.kind = *k;
                s.extracted_at = 1_700_000_000;
                s
            })
            .collect();
        cache.insert_many(&symbols).unwrap();
        for (i, (kind, name)) in kinds.iter().enumerate() {
            let path = format!("Ctx.{name}_{i}");
            let hit = cache
                .lookup("kinds", &path)
                .unwrap_or_else(|| panic!("missed {path}"));
            assert_eq!(hit.kind, *kind, "kind mismatch for {path}");
        }
    }

    #[test]
    fn all_visibility_variants_round_trip() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let variants = [
            (Visibility::Public, "pub"),
            (Visibility::Protected, "prot"),
            (Visibility::Private, "priv"),
            (Visibility::Internal, "intern"),
        ];
        let symbols: Vec<Symbol> = variants
            .iter()
            .map(|(v, name)| {
                let mut s = Symbol::new("vis", "1.0.0", format!("K.{name}"));
                s.visibility = *v;
                s.extracted_at = 1_700_000_000;
                s
            })
            .collect();
        cache.insert_many(&symbols).unwrap();
        for (v, name) in variants.iter() {
            let hit = cache.lookup("vis", name).unwrap();
            assert_eq!(hit.visibility, *v);
        }
    }

    #[test]
    fn deprecation_state_round_trips() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let mut deprecated = make_symbol("lib", "1.0.0", "K.old");
        deprecated.is_deprecated = true;
        deprecated.deprecated_message = Some("use K.new".into());
        cache.insert_many(&[deprecated.clone()]).unwrap();
        let hit = cache.lookup("lib", "old").unwrap();
        assert!(hit.is_deprecated);
        assert_eq!(hit.deprecated_message.as_deref(), Some("use K.new"));
    }

    #[test]
    fn extracted_at_round_trips() {
        let cache = SymbolCache::open_in_memory().unwrap();
        let mut s = make_symbol("lib", "1.0.0", "K.x");
        s.extracted_at = 1_690_000_000;
        cache.insert_many(&[s]).unwrap();
        let hit = cache.lookup("lib", "x").unwrap();
        assert_eq!(hit.extracted_at, 1_690_000_000);
    }

    #[test]
    fn cache_path_points_under_anubis_symbols() {
        let p = cache_path();
        let s = p.to_string_lossy();
        assert!(
            s.contains("symbols") && s.ends_with("cache.sqlite"),
            "unexpected cache_path: {s}"
        );
    }
}
