# Scanner Core (`packages/daemon-rs/src/scanner/`)

## Layer Architecture

### L1: Regex API Claim Extraction (`mod.rs`, `claims.rs`)
- `extract_api_claims(content)` — regex patterns for class methods, object methods, bare calls, imports
- `find_close_match_in_index(claim, index)` — Tier 1 typo (Levenshtein ≤2, ratio ≤0.25) + Tier 2 wrong-suffix (prefix ≥4, full distance ≤3)
- `COMMON_NAMES` skip list prevents fuzzy FPs on framework methods
- `extract_code_blocks_only(content)` — 3 strategies: fenced blocks, tool-call JSON, raw code filter

### L1.5: Symbol Cache (`symbols/`)
- SQLite-backed cache of library API surfaces
- `check_symbols(content, detected_language)` — language-gated lookup via `library_to_language()`
- `UNIVERSAL_TRAIT_METHODS` — skip to_string, clone, len, etc.
- `COMMON_FRAMEWORK_METHODS` — skip setState, render, describe, etc.
- `JS_GLOBAL_OBJECTS` — skip Date, Math, JSON, console, etc.
- `SCREAMING_SNAKE_CASE` constants skipped (FILTERS.map() not a class method)
- Cross-response: `SESSION_SYMBOLS` accumulator tracks definitions + imports across responses

### L2: FORGE Pipeline (`forge_pipeline.rs` + 17 modules)
- Language dispatch via `Language` enum (`language.rs`) — type-safe, compiler-enforced
- Per-language runners: `forge_python.rs` (pyo3 AST), `forge_rust.rs`/`forge_ts.rs`/`forge_go.rs` (tree-sitter), `forge_java.rs`/`forge_csharp.rs`/`forge_cpp.rs`/`forge_c.rs` (regex), `forge_gdscript/` (3 submodules), `forge_scene.rs` (tscn + gdshader)
- `detect_language(content, path)` in `language_detection.rs` — file extension first, then content heuristics (TS checked before Go!)
- Import verification: PyPI/crates.io/npm/Go proxy HTTP lookups
- Method verification: Python `dir()`, Rust docs.rs rustdoc JSON, TS `require()` + TSC, Go struct analysis
- Shared infrastructure: `forge_types.rs` (ForgeResult), `arity.rs`, `levenshtein.rs`, `string_filters.rs`, `scope_extractor.rs` (generic Extractor trait)
- `forge_pipeline.rs` now 530 LOC (was 4068, -87%) — pure dispatcher + confidence scoring

### L3: LLM Judge (`l3_per_claim.rs` + `l3_verdi.rs`)
- Model: GLM-4.7-Flash (no logprobs support — don't add logprob code)
- SV-CoT prompt: self-verifying consistency checks before final verdict
- Per-claim verification: **T=0.0, single sample** (falsification-judge redesign 2026-08-15), 512-token budget, one call per claim
- CaliDist dissent penalty: confident dissenting samples reduce majority confidence
- VERDI calibration (`l3_verdi.rs`): SVA/CLM/EGS structural signals, 0 extra API calls, post-hoc
- ECE + Brier measurement functions for weight tuning
- Few-shot: 5 examples covering full alignment spectrum
- Confidence calibration anchors: 0.95 (training certainty) → 0.10 (definitely hallucinated)
- Uncertainty-aware context: source confidence annotations (HIGH/MEDIUM/NONE)
- UNCERTAIN verdicts: surfaced as "⚠ low confidence" in details (advisory, not blocking)

## Tree-Sitter AST Extractors

| File | Language | Key Features |
|------|----------|-------------|
| `rust_ast_extractor.rs` | Rust | Keywords+builtins+macros+stdlib+prelude, structural prose detection, per-line filter, method/field name skipping, attribute stripping |
| `ts_ast_extractor.rs` | TypeScript/TSX | Keywords+globals+utility types, JSX element skipping, object property key skipping (CSS-in-JS), hex fragment filtering, import name collection, destructuring patterns |
| `go_ast_extractor.rs` | Go | Keywords+builtins+stdlib, range clause variables, struct fields, short var declarations, import path extraction |

All three share the same architecture:
1. Parse with tree-sitter grammar
2. Prose detection (structural node count + error ratio)
3. Per-line code-likeness filter (keyword prefix OR ≤6 words AND ≥2 punctuation)
4. Collect defined identifiers (declarations, imports, params, bindings)
5. Collect referenced identifiers (not in skip contexts)
6. Return referenced - defined - builtins

## Key Files

| File | Purpose |
|------|---------|
| `mod.rs` | `scan_response()` — main entry, orchestrates all layers |
| `forge_pipeline.rs` | FORGE pipeline + `detect_language()` + per-language FORGE runners |
| `l3_per_claim.rs` | L3 LLM judge with SV-CoT |
| `project_index.rs` | Project symbol index + session accumulator + fuzzy matching |
| `claims.rs` | Regex patterns for API claim extraction |
| `ast_extractor.rs` | Python pyo3 AST extraction |
| `scope_analysis.rs` | Instance method call type checking |

## Common Pitfalls

- **Cross-response imports**: tree-sitter scope checker only sees current response. Session symbols must be merged. Filter undefined-variable warnings against `get_session_symbols(project_root)`.
- **Prose contamination**: never pass raw agent responses to scope checkers. Always go through `extract_code_blocks_only()` or tree-sitter prose detection.
- **Language detection order**: TS distinctive patterns MUST be checked before Go (`package` keyword matches TS prose about npm packages).
- **CSS-in-JS**: React inline styles `{ padding: '1rem' }` — `property_identifier` nodes must be in SKIP_NODE_TYPES.
- **GLM-4.7-Flash**: no logprobs, structured JSON saturates confidence. Don't rely on token probabilities.

## Current State (2026-08-01)

- DELULU v1: Python 75%/0%, Rust 50%/0%, TypeScript 50%/0%
- DELULU v2: Python 64.8%/2.2%, Rust 33.33%/8.67%, TS 74%/2.2%
- Benchmark: task-003 Go 0 FPs, task-005 Python 1 FP, task-007 TS 0 FPs
- Test suite: 854 passed, 0 failed, 5 ignored
- Bundle: 13,097 entries (Python 8564 + Rust 1317 + npm 1525 + Godot 1691)
- forge_pipeline.rs: 530 LOC (was 4068, -87%), 17 modules extracted
- L3 pipeline: T=0.0 single-sample falsification judge + SV-CoT + mechanical quote check
- L3 latency budget (2026-08-18): p95 < 15s via MAX_JUDGED_CLAIMS=6 cap + `think:false` + `reasoning_effort:"none"` (ollama thinking models burn the whole max_tokens budget on hidden reasoning otherwise)
- Compiler gates: cold tsc/rustc spawn (8-12s) is ACCEPTED cold-start — `compiler_cache::global()` caches by content hash (1h TTL), warm hits skip the subprocess entirely
- Council #3: all 13 findings cleared
- Fresh install: cargo build -> python tests/bootstrap_bundle.py -> ./deploy.ps1
