# All-Language Benchmark Corpus (42 samples, 7 languages × 6)

All features ON: L1 regex + L1.5 symbol cache + L2 FORGE AST + L2 compiler
gates (rustc/tsc/go vet/clang/pyright/dotnet) + L3 falsification judge +
exact-match doc excerpts.

## Balance

| Language | Samples | TRUE | FALSE | api_existence | behavioral |
|---|---|---|---|---|---|
| python | 6 | 3 | 3 | 2 | 4 |
| typescript | 6 | 3 | 3 | 2 | 4 |
| rust | 4 | 2 | 2 | 2 | 2 |
| go | 6 | 3 | 3 | 5 | 1 |
| java | 6 | 3 | 3 | 3 | 3 |
| csharp | 6 | 3 | 3 | 3 | 3 |
| cpp | 6 | 3 | 3 | 3 | 3 |
| gdscript | 6 | 3 | 3 | 2 | 4 |
| **total** | **42** | **21** | **21** | **22** | **20** |

## Ground truth rules

- Every FALSE claim cites the official doc URL proving the API/behavior
  differs (fabricated method, wrong kwarg, wrong mutation direction).
- Every TRUE claim cites the canonical doc for the API.
- No sample is mutatable by implementation work — hallucination targets are
  real-world LLM confusions (kwargs misspelling, cross-language API
  transfer like java List.map, mutation-direction inversion).

## Runner

`tests/all_lang_bench.rs` — same harness pattern as doc_injection_bench:
tempdir project root + scaffold (TS junction + RUSTUP_HOME pin), NO_DOCS
arm (docs kill switch 0 — the L3 falsification judge runs doc-excerpt
matching from ANUBIS_DOCS_DIR), gemma4:e4b default via Ollama.

Hard sanity gates (fail test):
- 0 crashes across all samples
- at least 8 of 21 FALSE caught in total (no-op scanner guard)

Soft targets (warn): recall ≥ 60% weak / ≥ 80% strong, precision ≥ 90%,
per-language recall reported.
