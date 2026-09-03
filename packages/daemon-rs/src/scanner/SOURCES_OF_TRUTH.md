# Sources of Truth — External Symbol Data

Tracks all external sources we fetch symbol data from. Each entry lists the source URL/API, what we fetch, how it's accessed, and known gaps.

## Python

| Source | What | How | Gap |
|--------|------|-----|-----|
| **PyPI registry** (pypi.org) | Package existence | `package_index::verify_import_with_language("python", pkg)` | Only checks existence, not API surface |
| **Python runtime `dir()`** | Top-level names | `introspect_python_module(module)` subprocess | Only top-level, no class methods |
| **Python runtime `dir(Class)`** | Class methods | `introspect_python_class(module, class)` subprocess | Cold-start 5-10s for large packages |
| **Pre-seeded bundle** | Class methods | `fetch_python_classes.py` → `symbol_bundle.jsonl` | 10 packages seeded (pandas, numpy, sqlalchemy, requests, pydantic, flask, fastapi, click, matplotlib, sklearn). More needed. |

## Rust

| Source | What | How | Gap |
|--------|------|-----|-----|
| **crates.io** (source tarball) | Type definitions | `fetch_rust_types.py` → `symbol_bundle.jsonl` | Only pub struct/enum/trait, no impl methods |
| **docs.rs** (rustdoc JSON v60+) | Full method lists | `rust_fetcher::fetch_rustdoc_json` + `rust_parser::parse_rustdoc_json` | 90s timeout, 7-day cache, format_version gate |
| **crates.io** (registry API) | Crate existence | `package_index::verify_import_with_language("rust", pkg)` | N/A |

## TypeScript / JavaScript

| Source | What | How | Gap |
|--------|------|-----|-----|
| **npm registry** | Package existence | `package_index::verify_import_with_language("typescript", pkg)` | Only existence |
| **Node.js `require()`** | Runtime exports | `ts_introspect::introspect_ts_module(pkg)` | Only runtime values, misses type-only exports |
| **TypeScript compiler** | Type-level API | `ts_method_checker::verify_ts_methods_via_compiler()` | Requires @types/X installed in workspace |
| **npm `.d.ts` files** | Type declarations | `fetch_npm_types.py` via jsDelivr CDN → `symbol_bundle.jsonl` | 12 packages seeded (react, zustand, zod, vitest, axios, express, @types/react, @types/express, @types/node, react-router-dom, @apollo/client, @testing-library/react). PINNED_VERSIONS for reproducibility. |

## Go

| Source | What | How | Gap |
|--------|------|-----|-----|
| **Go module proxy** (proxy.golang.org) | Package existence | `package_index::verify_import_with_language("go", pkg)` | Only existence |
| **Go source** | Type/method lists | (not automated) | No runtime introspection for Go |

## Java

| Source | What | How | Gap |
|--------|------|-----|-----|
| **Maven Central** | Package existence | `package_index::verify_import_with_language("java", pkg)` | Only existence |

## C#

| Source | What | How | Gap |
|--------|------|-----|-----|
| **NuGet** | Package existence | `package_index::verify_import_with_language("csharp", pkg)` | Only existence |

## C/C++

| Source | What | How | Gap |
|--------|------|-----|-----|
| **Curated header list** | Known headers | `c_introspect::verify_c_includes()` | Manual, not fetched |

## Godot

| Source | What | How | Gap |
|--------|------|-----|-----|
| **Godot docs** (77K+ symbols) | Full API | `godot_fetcher.rs` → `symbol_bundle_bulk.jsonl` | Comprehensive, few gaps |

## Common Skip Lists (hand-maintained)

| Location | What | When to grow | When NOT to grow |
|----------|------|--------------|------------------|
| `symbols/mod.rs` UNIVERSAL_TRAIT_METHODS | clone, iter, to_string etc. | Adding a new language | Never — language-agnostic |
| `symbols/mod.rs` COMMON_FRAMEWORK_METHODS | Framework-specific methods | Never — should be in bundle instead | Always |
| `symbols/mod.rs` PYTHON_STDLIB_CLASSES | Path, Column, Session etc. | Python stdlib changes | When a framework defines same-named class |
| `symbols/mod.rs` AXIOS_HEADERS_RECEIVERS | AxiosHeaders instance methods | Never — version-specific | Always |
| `scanner/claims.rs` skip_names | JS keywords + builtins | Language spec changes | For library-specific methods |
| `project_index.rs` COMMON_NAMES | Common method names | **AVOID** — fetch from source instead | When no fetcher exists |
| `local_introspect.rs` PYTHON_BUILTINS | Python builtins | Python spec changes | For library functions |

## Anti-pattern: Growing COMMON_NAMES

The COMMON_NAMES skip list in `project_index.rs` was growing commit-by-commit as
benchmark tasks revealed new FPs. This is a band-aid — the proper fix is to
**fetch the real symbol surface from the authoritative source** (package runtime,
docs.rs, npm .d.ts, etc.) and seed it into the bundle.

When a new FP appears:
1. Check if the method/class exists in the bundle → if not, fetch and seed
2. Check if the fetcher returns complete data → if not, fix the fetcher
3. Only add to COMMON_NAMES as last resort (truly universal methods like clone/iter)

## Current Bundle Totals (2026-08-01)

- Python: 4,270 entries (pandas 1381, numpy, sqlalchemy, requests, pydantic, flask, fastapi, click, matplotlib, sklearn)
- Rust: 1,317 entries (tokio, chrono, serde, serde_json, regex, rand, anyhow, uuid, tempfile 7)
- npm: 1,525 entries (react, zustand, zod, vitest, axios, express, @types/*, react-router-dom, @apollo/client, @testing-library/react)
- Total: ~8,803 entries

## Prose Contamination Guards

| Guard | Location | Triggers On |
|-------|----------|-------------|
| Language keyword count | forge_rust.rs | Python keywords > Rust keywords |
| English stop-word ratio (3:1) | forge_rust.rs | English freq > Rust kw freq x 3 |
| LLM API metadata strip | mod.rs strip_tool_outputs | prompt_tokens, completion_tokens, etc. |
| SCREAMING_SNAKE_CASE skip | rust/go/python extractors | ALL_CAPS identifiers |

## Fresh Install Process

1. Build: cd packages/daemon-rs && cargo build --release
2. Bootstrap bundle: python tests/bootstrap_bundle.py
   - Runs fetch_python_classes.py (needs pandas/numpy/sqlalchemy installed)
   - Runs fetch_npm_types.py (needs internet for jsDelivr CDN)
   - Runs fetch_rust_types.py (needs internet for crates.io)
3. Deploy: ./deploy.ps1

## Architecture: Generalized vs Hardcoded

### Bundle-based (generalized, auto-populated)
Primary source of truth. Populated by fetch scripts via bootstrap_bundle.py.
- Python: dir() runtime introspection → 4270 entries
- Rust: crates.io source tarball parse → 1317 entries
- npm: jsDelivr CDN .d.ts parse → 1525 entries
- Godot: pre-seeded 77K entries

### Hardcoded skip lists (universal patterns, stay in code)
These represent truly universal patterns that don't vary by installation:
- Language keywords (fn, let, use, def, import, class, etc.)
- Language builtins (print, len, range, println!, etc.)
- SCREAMING_SNAKE_CASE constants (always constants in all languages)
- Language test conventions (Test*, Benchmark*, Fuzz*, Example*)
- LLM API metadata fields (prompt_tokens, completion_tokens, etc.)
- English stop words for prose detection (the, a, is, was, etc.)

### Framework-specific lists (IDEALLY bundle-based, currently hardcoded)
These were added as quick fixes. They SHOULD eventually be populated
via bundle seeding scripts, not maintained in code:
- COMMON_NAMES (SQLAlchemy, Flask, Django, pandas methods)
- GO_FRAMEWORK_FUNCS (gin, GORM methods)
- COMMON_TS_EXPORTS (React hooks, Express types, Zod builders)
- COMMON_RUST_ECOSYSTEM_TYPES (chrono, serde, clap types)

**Migration path**: Expand fetch scripts to cover these packages.
The hardcoded lists serve as fallbacks until bundle coverage is complete.
