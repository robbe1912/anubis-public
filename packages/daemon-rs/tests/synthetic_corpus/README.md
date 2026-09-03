# Synthetic Injection Recall Corpus

30 self-contained code snippets injected with **deterministic** hallucinations.
Validates the DELULU recall claim is **non-circular**: DELULU was used to tune
`compute_risk_score`, then used to measure recall. Held-out corpus produced 0
natural hallucinations, leaving recall unverifiable. This corpus breaks that
loop — every snippet is Docker-verified to fail (ImportError, AttributeError,
TypeError, E0599, panic, etc.) so any scanner that fails to flag it has a
**provable recall gap**, not a measurement artifact.

## Layout

```
synthetic_corpus/
├── README.md                   ← this file
├── l1_5_samples/  (10 files)   ← L1.5-attributed (symbol cache, scope, fuzzy)
├── l2_samples/    (12 files)   ← L2-attributed (FORGE AST extractors)
└── l3_samples/    (8 files)    ← L3-attributed (LLM semantic judge)
```

## Mutation Operators

| Code | Mutation                                  | Target Layer |
|------|-------------------------------------------|--------------|
| M1   | Cross-lib import (real symbol, wrong pkg) | L1.5         |
| M2   | Invented submodule / namespace            | L1.5         |
| M3   | Version-removed API (real deprecation)    | L1.5         |
| M4   | Parameter hallucination (wrong kwarg)     | L2           |
| M5   | Method on wrong type                      | L2           |
| L3-* | Semantic runtime bug (compiles, panics)   | L3           |

## Snippet Inventory (30 total)

### L1.5 — Symbol Cache / Scope / Fuzzy (10)

| ID                      | Lang | Mutation | Expected Error (Docker-verified)                            |
|-------------------------|------|----------|-------------------------------------------------------------|
| py_01_cross_lib_import  | py   | M1       | `ImportError: cannot import name 'LoginMgr' from 'flask_login'` |
| py_02_invented_submodule| py   | M2       | `ModuleNotFoundError: No module named 'pydantic.fields_extra'` |
| py_03_typing_io_replacement | py | M3     | `ModuleNotFoundError: No module named 'distutils'` (removed 3.12) |
| py_04_dunder_method_wrong | py | M3       | `TypeError: dict.fromkeys() takes no keyword arguments`     |
| rs_01_wrong_crate_method| rs   | M1       | `E0599: no method named 'read_unchecked' found for '&RwLock<i32>'` |
| rs_02_invented_trait    | rs   | M2       | `E0432: unresolved import 'serde::de::VisitorExt'`          |
| ts_01_wrong_named_export| ts   | M1       | `useState is not exported from 'react-dom'` (typeof undefined) |
| ts_02_invented_submodule| ts   | M2       | `Cannot find module 'lodashfp'`                             |
| go_01_wrong_pkg_symbol  | go   | M1       | `c.DoJSON undefined (type *http.Client has no field or method DoJSON)` |
| go_02_invented_subpkg   | go   | M2       | `undefined: context.WithTimeoutOrCancel`                    |

### L2 — FORGE AST (12)

| ID                          | Lang | Mutation | Expected Error (Docker-verified)                            |
|-----------------------------|------|----------|-------------------------------------------------------------|
| py_05_pandas_merge_suffices | py   | M4       | `TypeError: merge() got an unexpected keyword argument 'suffices'` |
| py_06_str_to_uppercase      | py   | M5       | `AttributeError: 'str' object has no attribute 'to_uppercase'` |
| py_07_requests_timeout      | py   | M4       | `TypeError: Session.request() got unexpected 'timeout_mode'`|
| py_08_builtins_invented     | py   | M5       | `AttributeError: 'list' object has no attribute 'flatten'`  |
| rs_03_wrong_arity           | rs   | M4       | `E0061: this function takes 1 argument but 2 arguments were supplied` |
| rs_04_method_on_wrong_type  | rs   | M5       | `E0599: no method named 'unwrap_or' found for type 'usize'` |
| rs_05_iter_wrong_method     | rs   | M5       | `E0599: no method named 'map_to_string' found for 'Iter<'_, i32>'` |
| ts_03_array_methods         | ts   | M5       | `TypeError: [1,2,3].sum is not a function`                  |
| ts_04_promise_methods       | ts   | M5       | `TypeError: Promise.resolve(...).retry is not a function`   |
| ts_05_object_keys           | ts   | M5       | `TypeError: Object.values(...).unique is not a function`    |
| go_03_wrong_arity           | go   | M4       | `too many arguments in call to http.Get`                    |
| go_04_method_on_wrong_type  | go   | M5       | `len(s).String undefined (type int has no field or method String)` |

### L3 — LLM Semantic Judge (8)

| ID                          | Lang | Mutation     | Expected Error (Docker-verified)                            |
|-----------------------------|------|--------------|-------------------------------------------------------------|
| py_09_semantic_async_await  | py   | await-scope  | `SyntaxError: 'await' outside async function`               |
| py_10_off_by_one_pandas     | py   | off-by-one   | Returns `[2,3]` from `[1,2,3,4]` (drops BOTH ends)          |
| py_11_recursion_no_base     | py   | no-base-case | `RecursionError: maximum recursion depth exceeded`          |
| rs_06_lifetime_subtle       | rs   | runtime-panic| `panic: already borrowed: BorrowMutError` (RefCell nested)  |
| rs_07_drop_order_bug        | rs   | use-after-free | `E0713: borrow may still be in use when destructor runs`  |
| ts_06_event_loop_blocking   | ts   | event-loop   | Sync `fs.readFileSync` blocks async handler                 |
| ts_07_promise_unhandled     | ts   | unhandled-rej| `UnhandledPromiseRejectionWarning: Error: neg`              |
| go_05_concurrency_bug       | go   | data-race    | `fatal error: concurrent map writes`                        |

## Reproducing Docker Verification

```powershell
# Python (3.12)
docker run --rm -v "${PWD}:/work" python:3.12-slim python /work/l1_5_samples/py_01_cross_lib_import.py

# TypeScript (node 20)
docker run --rm -v "${PWD}:/work" -w /work node:20-slim sh -c "npm i -s react react-dom lodash && node l2_samples/ts_03_array_methods.js"

# Rust (1.82) — wrap as module in throwaway lib, cargo check
docker run --rm -v "${PWD}:/work" rust:1.82-slim bash -c "..."

# Go (1.22)
docker run --rm -v "${PWD}:/work" -w /work golang:1.22-bookworm go vet l1_5_samples/go_01_wrong_pkg_symbol.go
```

## Ship Gate

`cargo test --test recall_corpus -- --nocapture` (with `$env:DELULU_LLM_API_KEY` set for L3 samples).

| Metric           | Required | Notes                                              |
|------------------|----------|----------------------------------------------------|
| Total caught     | ≥ 21/30  | Any layer warning fires                            |
| L1.5 caught      | ≥ 7/10   |                                                    |
| L2 caught        | ≥ 8/12   |                                                    |
| L3 caught        | ≥ 6/8    | Requires `DELULU_LLM_API_KEY` (else skipped)       |
| FP regression    | 0        | `eval_corpus_no_hard_false_positives_on_real_prs` still passes |
| DELULU regression| < 2/lang | `delulu_compare` FPR per language still 0%         |

## Failure Modes (per plan)

| Symptom              | Investigate                                                |
|----------------------|------------------------------------------------------------|
| L1.5 miss            | `check_symbols` + `check_instance_calls` + cache seeding   |
| L2 miss              | FORGE language extractor (`forge_python`, `forge_rust`, …) |
| L3 miss              | `l3_per_claim` system prompt — **do NOT loosen**           |
| FP regression        | Revert. Investigate before retrying.                       |
| DELULU regression    | Revert. `>2 samples/lang` = hard fail per AGENTS.md.       |

## Constraints (from `.omo/plans/synthetic-injection-corpus.md`)

- **Do NOT** mutate HumanEval (substrate mismatch)
- **Do NOT** use multi-judge filter (both Zhipu, correlated)
- **Do NOT** lower bar or weaken assertions to pass
- **Do NOT** add test-specific patches to scanner — only general fixes
- **Do NOT** push to remote (local commits only)
