# Doc Injection v2 Benchmark Corpus

Code-containing hallucination corpus for validating the v2 doc-injection /
reasoning-scanner redesign (see `.omo/plans/doc-injection-v2.md` Section 7).

The v1 corpus was out-of-distribution: pure-prose Godot claims with **no code
fences or imports**. The scanner's design contract is "agent responses with
code", so it was effectively a no-op (1/20 claims reached L3). This corpus
fixes that — every sample pairs real code with a real import with a prose
claim ABOUT that code, so `detect_libraries` fires naturally and L3 has
grounded evidence to work against.

## Layout

```
tests/doc_injection_corpus/
├── README.md          ← this file (methodology + ship gate)
├── samples.jsonl      ← one JSON object per sample (see schema below)
└── (runner lives at tests/doc_injection_bench.rs)
```

## Sample schema (samples.jsonl)

Each line is a single JSON object:

| Field           | Type    | Required | Notes                                                                |
|-----------------|---------|----------|----------------------------------------------------------------------|
| `id`            | string  | yes      | Unique kebab-case identifier (`py_true_pd_read_csv`, etc.)           |
| `language`      | string  | yes      | `python` \| `typescript` \| `rust`                                   |
| `claim_type`    | string  | yes      | `api_existence` \| `behavioral`                                      |
| `ground_truth`  | string  | yes      | `true` = claim accurately describes code/docs; `false` = hallucinated |
| `library`       | string  | yes      | Top-level package the claim is about (`pandas`, `react`, `tokio`)    |
| `imports`       | array   | yes      | Packages the code fences import — drives `detect_libraries`          |
| `code`          | string  | yes      | The fenced code block shown to the scanner (raw, no fences)          |
| `prose_claim`   | string  | yes      | Prose statement ABOUT the code — the claim under test                |
| `citation`      | string  | yes      | Official docs URL backing the ground truth                           |
| `rationale`     | string  | yes      | One-sentence justification of TRUE/FALSE tied to the citation        |
| `expected_layer`| string  | no       | Hint: which scanner layer *should* catch this (`L1.5`/`L2`/`L3`)     |
| `tags`          | array   | no       | Free-form labels (`kwarg`, `event-loop`, `drop-order`, ...)          |

The runner concatenates `code` + `prose_claim` into a fenced markdown block
(the shape `scan_response` expects from a real agent response):

````
```python
<code>
```

<prose_claim>
````

## Coverage (v2, 48 samples)

| Axis            | Breakdown                                                          |
|-----------------|--------------------------------------------------------------------|
| Language        | Python 16 · TypeScript 16 · Rust 16                                |
| Ground truth    | TRUE 24 · FALSE 24 (balanced so precision + recall are measurable) |
| Claim type      | api_existence 28 · behavioral 20                                   |
| Layer hint      | L1.5 8 · L2 16 · L3 24                                             |

Balance is **deliberate**. A recall-only corpus (all FALSE) can't measure
precision. A precision-only corpus (all TRUE) can't measure recall. Equal
TRUE/FALSE per language means every metric has ≥8 samples behind it.

The behavioral axis was doubled in the v2 rebalance (8 → 20 samples,
per-language behavioral 2/4/2 → 6/8/6) because the v2 redesign targets
behavioral recall specifically. Behavioral metrics now have ≥3 T and ≥3 F
samples per language — enough to spot per-language lift without a single
sample flipping the entire percentage.

## What "ground truth" means

- `ground_truth: "true"` — the prose claim is **correct**. Either:
  - Code is valid AND claim accurately describes what it does, OR
  - Claim asserts an API exists and it does.
  The scanner MUST NOT warn. A warning here = false positive.

- `ground_truth: "false"` — the prose claim is **wrong**. Either:
  - Code has a bug AND claim asserts it works, OR
  - Claim asserts an API exists and it does not (typo, wrong type, wrong pkg).
  The scanner SHOULD warn. No warning here = false negative (recall miss).

The citations are real official docs URLs (pandas.pydata.org,
developer.mozilla.org, doc.rust-lang.org, nodejs.org). A claim is only
authored if its truth value can be determined unambiguously from the cited
page — no subjective judgement calls.

## A/B methodology

`tests/doc_injection_bench.rs` runs the corpus twice against the SAME scanner
binary and SAME model, swapping only the L3 doc-injection kill switch
(`ANUBIS_L3_DOCS_IN_PROMPT` env var, read per-call by
`scanner::build_library_docs_fallback`):

| Arm                        | Kill switch value   | Behavior                                 |
|----------------------------|---------------------|------------------------------------------|
| **A (baseline)**           | `ANUBIS_L3_DOCS_IN_PROMPT=0` | Library docs stripped from L3 prompt |
| **B (treatment)**          | `ANUBIS_L3_DOCS_IN_PROMPT=1` | Library docs injected into L3 prompt |

**Why an env var, not a config field?** `ScannerConfig` does NOT have a
`doc_grounding` field — that was a v1 hallucination. The v1 bench wrote
`doc_grounding: off|lazy` into a tempdir `~/.anubis/config.yaml` and tried to
read it back via `cfg.scanner.doc_grounding`, which never compiled (or, in
the looser variants, was silently ignored by serde because `ScannerConfig`
has no `deny_unknown_fields`). Both arms therefore ran byte-identically,
which is exactly what the v2 plan Section 1 calls out: "no actual effect was
measured — all 20 verdicts byte-identical between baseline and treatment."
The kill switch env var is wired through: `build_library_docs_fallback`
checks it at the top of every call and returns an empty string when it equals
`"0"`, which in turn zeros out `docs_assisted` downstream.

The swap is implemented in `HomeGuard` inside the bench: it captures the
prior `USERPROFILE`, `HOME`, and `ANUBIS_L3_DOCS_IN_PROMPT`, sets them per
arm, runs all samples in that arm, then restores them. The tempdir's
`~/.anubis/config.yaml` is still written for log readability (it records the
arm name as `scanner.arm_label`), but it is NOT consulted for behavior — the
env var is the only operative knob.

Run a single arm:
```powershell
$env:DELULU_LLM_API_KEY = "<key>"
$env:DOC_INJECTION_ARM   = "lazy"        # or "off" or "both" (default)
cargo test --release --test doc_injection_bench -- --nocapture
```

`DELULU_FORGE_ONLY=1` strips the API key (L3 short-circuits before
`build_library_docs_fallback` runs), so the kill switch has no observable
effect in that mode — useful for L1.5/L2-only smoke.

## Three scanner models

Per Section 7 point 6, the corpus is exercised against three models via the
existing `DELULU_LLM_MODEL` env var (no new config plumbing):

| Tier        | Model                  | Env                                                            |
|-------------|------------------------|----------------------------------------------------------------|
| Strong      | `glm-4.7`              | `$env:DELULU_LLM_MODEL = "glm-4.7"`                            |
| Weak local  | `gemma4:e4b` (ollama)  | `$env:DELULU_LLM_MODEL = "gemma4:e4b"; base_url=ollama:11434`  |
| Weak alt    | `qwen2.5:4b` (ollama)  | `$env:DELULU_LLM_MODEL = "qwen2.5:4b"`                         |

The runner reads `DELULU_LLM_MODEL` and `DELULU_LLM_BASE_URL` and stamps
them into the metrics report so each model produces a separate row.

## Metrics (per arm × per model)

| Metric                  | Formula                                            | Target (lazy)    |
|-------------------------|----------------------------------------------------|------------------|
| Recall                  | `TP / (TP + FN)` over FALSE samples                | ≥ 60% (weak), ≥ 80% (strong) |
| Precision               | `TP / (TP + FP)`                                   | ≥ 90%            |
| FP rate (TRUE samples)  | `FP / (FP + TN)`                                   | ≤ 10%            |
| Warning emission rate   | samples where ≥1 user-visible warning surfaced / total FALSE | ≥ 80%            |
| Latency p50 / p95       | per-sample scan wall time                          | ≤ 5s p50, ≤ 30s p95 |

Where:
- TP = FALSE sample AND scanner emitted ≥1 warning.
- FN = FALSE sample AND scanner emitted zero warnings.
- FP = TRUE sample AND scanner emitted ≥1 warning.
- TN = TRUE sample AND scanner emitted zero warnings.

## Ship gate (asserted at end of `doc_injection_bench`)

Soft gate — warn loudly but do not fail the build (the corpus is measurement
infrastructure, not a correctness gate). Hard gate only when there are zero
hits at all (= scanner is no-op, like v1):

```rust
// Hard fail only when scanner is provably broken (0 hits on FALSE samples).
assert!(total_tp + total_fn > 0, "scanner produced zero verdicts — broken.");
assert!(total_tp > 0, "scanner caught 0/{} FALSE samples — no-op recall.", n_false);
```

Soft targets print a `WARN` line if missed. After Phase 1 lands (Fix A-G in
`doc-injection-v2.md` Section 6), re-run and check the lazy arm beats the off
arm on recall + warning emission.

## Validation checklist (per sample before commit)

1. Code block parses standalone (no missing imports, no undefined names that
   aren't part of the bug).
2. `imports` array lists every package the code fences import.
3. `citation` is a live official docs URL (no 404, no marketing blog).
4. `rationale` is a single sentence that names the specific API or behavior
   from the citation that determines TRUE/FALSE.
5. For FALSE samples: the failure is Docker-reproducible (matches the
   existing `tests/synthetic_corpus` standard). Verified via:

   ```powershell
   docker run --rm -v "${PWD}:/work" python:3.12-slim python -c "<code>"
   docker run --rm -v "${PWD}:/work" -w /work node:20-slim node -e "<code>"
   docker run --rm -v "${PWD}:/work" rust:1.82-slim cargo check   # in temp crate
   ```

## Non-goals

- **Not** a replacement for `tests/synthetic_corpus/` — that corpus tests
  pure-code recall across L1.5/L2/L3. This corpus tests prose-claim
  verification specifically against doc-grounded L3.
- **Not** a replacement for `held_out_rescan.rs` — held-out stays frozen,
  this corpus is tunable.
- **Not** for CI gating (soft targets). Use `recall_corpus.rs` for that.
- **Not** mutatable by Phase 1 implementation work. If Phase 1 needs a new
  claim to demonstrate a fix, add it here ONLY if it meets the validation
  checklist — otherwise it's overfitting (Rule 8, AGENTS.md).
