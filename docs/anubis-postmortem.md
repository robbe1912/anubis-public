# Anubis Postmortem: I Built a Hallucination Detector for Coding Agents. Here's How It Died.

**Status: KILLED by pre-registered gate, 2026-08-19.**
**~120 hours of development and evaluation. ~100 agent-hours of measured traffic. Two model tiers. One confirmed true positive.**

---

## TL;DR

Anubis was a local proxy that sat between coding agents and their LLM provider, scanning every response for hallucinated APIs, undefined variables, and invented imports via a 4-layer deterministic cascade. It worked as software. It failed as a product, for a reason I could have measured earlier but kept not measuring: **the scanner's warnings were almost never both true and useful** — and the single time a warning demonstrably changed an agent's behavior, it made things worse.

The decisive experiment: 24 hard-distribution coding tasks (unfamiliar SDKs, novel frameworks) run through the scanner with a weak model chosen to *maximize* hallucination rate. The scanner emitted 41 warnings. An adversarial audit found **4 real defects** among them (17% precision at warning level: 7 solid warnings mapping to 4 distinct defects) while the same audit found **~35 real hallucinations the scanner missed** (recall 10–15%). The pre-registered kill threshold — fewer than 6 confirmed true positives — fired.

I am publishing this because the negative result is the most valuable artifact the project produced.

---

## 1. What Anubis Was

A Rust daemon on `:7878` intercepting OpenAI- and Anthropic-wire traffic from any coding agent (opencode, Claude Code, Cline, ...):

```
Agent → Anubis Proxy (:7878) → LLM Provider
              ↓
        scan_response()
  L1: Regex claim extraction + fuzzy symbol matching
  L1.5: SQLite symbol cache (language-gated)
  L2: FORGE pipeline — tree-sitter/pyo3 AST scope analysis
  L2.5: Behavioral verification (async-scope, off-by-one, ...)
  L3: LLM judge (GLM-4.7-Flash, per-claim, warn-only)
```

Two delivery modes: **warn** (append a footer to the streamed response) and **block+retry** (buffer tool calls, scan before release, retry with corrective context on detection). Seven languages with live API verification (docs.rs, pkg.go.dev, PyPI, npm, javadoc.io, Microsoft Learn).

It was good software: ~1,200 passing tests, sub-second scanning, transparent proxying verified byte-identical, zero measurable latency friction across two full benchmark runs.

The thesis: *coding agents hallucinate APIs; a wire-level scanner with deterministic verification catches hallucinations before they cost the agent hours; therefore agents get more done with Anubis than without.*

Every clause of that thesis had to be true simultaneously for the product to work. I measured each clause. They weren't.

---

## 2. The Experimental Record

### 2.1 Experiment 1 — Strong model, famous repos (SWE-bench A/B)

24-task stratified SWE-bench Verified subset, run twice: Arm A through Anubis (warn mode), Arm B direct. Model: glm-5-turbo.

| | Arm A (Anubis) | Arm B (direct) |
|---|---|---|
| Resolved | 14/24 (58.3%) | 6/24 (25.0%) |
| Fair both-patched subset | 9/10 | 6/10 |
| Empty-patch instant deaths | 7 | 11 |

A +33pp win for the scanner arm. Seductive. The transcript audit killed it:

- **Exactly one in-run warning fired across the entire run** — and it was a false positive (the agent *quoted* `List[str]` from a real sphinx source file; the scanner flagged `List` as a hallucinated variable because it only saw the response fragment, not the file the quote came from).
- Zero true positives in ~50 task-hours. A strong model on django/sympy/sphinx — repos in every training set — hallucinates at a rate the scanner can't find, because there's nothing to find.
- The headline delta was unattributable: run nondeterminism plus an instant-death agent flake (agent exits without editing anything) that hit the two arms asymmetrically for no reason connected to the scanner.

**Clause 1 died: the model wasn't hallucinating.** But only for *this* distribution. I knew hallucination rate was distribution-dependent and designed Experiment 2 around that.

### 2.2 Experiment 2 — Weak model, same distribution (SWE-bench A/B, rerun)

Same 24 tasks, coder swapped to qwen3.5:9b (local, chosen because the 7b-coder variant had produced 8 auditor-confirmed catches in an earlier hard benchmark).

| | Arm A (Anubis) | Arm B (direct) |
|---|---|---|
| Resolved | 7/24 (29.2%) | 9/24 (37.5%) |
| Empty-patch instant deaths | 14 | 7 |

**The headline sign flipped.** Same infrastructure, same tasks, one variable — and the delta reversed direction. That's the A/B methodology dying in public: per-arm outcomes were dominated by the instant-death flake and sampling noise, not by the scanner. Detecting a real 10% effect at this flake rate would need hundreds of paired tasks. Nobody runs hundreds of paired SWE-bench tasks.

The warning census was more interesting: **11 warnings fired** (vs 1 in the strong-model run — prevalence is real), but 10 of 11 mapped to quoted-real-code false positives (the "fragment-visibility" class: scanner sees the response, not the repo context the quote came from; the eleventh, on offline replay, was the run's single true positive - see section 2.4). One warning — a footer actually injected into the agent's stream mid-task — coincided with that task collapsing to an empty patch while the control arm resolved it. n=1, but it's the only causal observation of the product's core mechanism in ~50 more task-hours, and **the mechanism hurt**.

**Clause 3 died in the worst way: not only weren't warnings useful, the one observed delivery was damaging.**

### 2.3 The fork: kill it or fix it?

I ran a structured debate — an adversarial "skeptic" agent argued KILL, a "pro" agent argued CONTINUE, and an adjudication ruled: continue into a 10-day gated sprint with the skeptic's mechanical kill criteria adopted verbatim. The gates:

1. **Day 2:** Fix the fragment-visibility FP class; replay all 11 weak-run warnings; ≤1 FP may remain; recall gates must not regress. *Fail → kill.*
2. **Day 5:** Hard-distribution test (unfamiliar SDKs, block mode armed, auditor-labeled catches). **≥6 confirmed true positives → continue; <6 → kill.**
3. **Day 10:** Publish + demand test for the eval-product pivot.

### 2.4 The sprint delivered real engineering (days 1–4)

Both fixes worked. This matters for the postmortem: the product did not die from sloppiness.

**Fragment-visibility FP fix** — the proxy sees the full wire, so it now accumulates symbols from tool results (files the agent read) into a session-symbol table that suppresses warnings on quoted content: import aliases (`import x as Y`), parenthesized multi-line imports, `self`/`cls` bindings, plus `--context-dir` offline replay. Replay result: **10/10 weak-run FPs suppressed**, and — the payoff — the replay surfaced the run's single **true positive**: the agent had written `from sympy.utilities.iterables import prefix` (the module exports `prefixes`). That was the only confirmed TP in all ~100 agent-hours of real traffic.

**Anthropic-wire block+retry** (a known debt) — closed and live-validated: a hallucinated tool call is buffered, blocked, and the corrected call is re-emitted as native `tool_use` SSE events. Found and fixed two real streaming bugs on the way (undetected `content_block_start` tool_use markers; held non-tool chunks silently dropped on flush).

1,187 tests passing, zero regressions, deployed.

### 2.5 Experiment 3 — The decisive one: hard distribution

If hallucination rate is the binding constraint, maximize it: 25 hard tasks purpose-built around novel/unfamiliar stacks (Rust sqlx/axum, TS tRPC/zod, Go gRPC/gin-gorm, C# EF Core/MediatR, C++, C, GDScript), single-shot, weak model (qwen2.5-coder:7b), deterministic layers only.

**41 warnings across 10 tasks.** My own audit counted "11–16 true positives" and called the gate PASSED.

Then the adversarial audit read every generated file. My count did not survive:

**Precision — what the 41 warnings actually were:**

| Class | Count | Share |
|---|---|---|
| Solid true positives (distinct defects; 7 solid warnings) | 4 | 17% warning-level / 10% defect-level |
| Marginal/duplicate instances of those defects | 15 | 37% |
| Outright false positives | 13 | 32% |
| Corrupted/unusable (warning-formatting bug) | 9 | 22% |

The 4 real catches: an undeclared generic `T` used at module scope (TS), a missing `os/signal` import (Go), and two missing namespace references in C# code shipped with zero `using` directives. My "11–16" came from counting warning *instances* — four warnings on one undeclared `T` is one defect, not four. **The gate threshold had never specified a counting unit. That ambiguity was load-bearing.**

**Recall — what the scanner missed:** ~20–24 unambiguous hallucinations in the tasks it scored *zero-warning*, including:

- `createHTTPServer` imported from `trpc-playground/server` (real package, nonexistent export)
- Godot 3 APIs (`scancode`, string-form `connect()`) in code claiming Godot 4.3; `Timer.active`, which has never existed; `ConfigFile.open`, which is not an API
- `axum::Server::bind`, removed in the axum version the code itself claimed
- `next(error)` called in 5 Express handlers that never declare `next`
- Six `class_name` declarations in a single GDScript file (immediate parse error)
- `std::get_if` on a variant alternative that doesn't exist
- Serilog's non-generic `ILogger` used as `ILogger<T>` (cross-framework chimera)

Plus ~15 more inside the warned tasks (six uses of unimported `status`/`codes`/`uuid` packages in the very task the scanner flagged for a *different* import; `json!` macro used with no `serde_json` import). **Corpus-wide recall: 10–15%.**

**Clause 2 died: even when the model hallucinated plenty, the scanner caught almost none of it and lied about the rest.**

---

## 3. Why It Died — Root Causes

**R1. The value function is a four-term joint probability, and I measured each term at zero or near-zero in deployment conditions.**
The product needs: model hallucinates catchably (≈0 with strong models on familiar code) AND the agent doesn't self-correct via tool feedback (≈0 in agentic loops — the agent reads the error and fixes it) AND the scanner detects it (10–15%) AND the warning improves the outcome (the one observation was negative). Multiplying honest estimates of these terms gives a number indistinguishable from zero, which is what I measured.

**R2. The proxy is architecturally disadvantaged at exactly its core job.**
The wire carries fragments. The agent holds the ground truth (the repo it just read, the tool results it just got). Every hallucination judgment the scanner makes from the wire is a reconstruction the agent's own context would refute or confirm trivially. I patched the dominant symptom (fragment-visibility FPs) and the fix worked — but the same blindness runs the other direction: the misses (Godot 3 vs 4, axum 0.6 vs 0.7, pydantic v1 vs 2) require version-resolved API knowledge the scanner's live fetchers and symbol bundles don't carry, and can't reliably carry, because source of truth rots (I had a hard rule against hardcoding symbols for exactly this reason — the rule was right, and it meant the knowledge gap was permanent).

**R3. The best thing the scanner did was someone else's product.**
The genuinely solid catches (missing import, missing using, undeclared name) were all "this code does not compile" — discovered by invoking rustc/go vet/tsc/csc. A user who wants that runs the compiler, which is already installed, already exact, and already free. Anubis's value over the compiler was supposed to be *semantic* hallucination detection. In the decisive run that surplus was 4 defects the compiler also would have caught, at 17% precision.

**R4. Warn-mode intervention on weak models is net-negative.**
A weak model mid-task is a house of cards; an injected footer that says "your last response contained hallucinations" (when it didn't) knocks it over. I observed this once causally and banned footers-on-weak-models as policy — but warn mode was the flagship delivery mechanism for the consumer thesis.

**R5. I could not measure my own product.**
A/B deltas flipped sign between runs of the same suite (strong-model run vs weak-model rerun) because agent-level flake (instant empty-patch deaths) dominated the treatment effect. And my own gate evaluation inflated its result 3–4× via counting-unit ambiguity until an adversarial audit corrected it. Both are process failures worth naming: **pre-register the unit of counting, pre-register a recall term, and never trust a gate whose numerator you computed yourself.**

---

## 3.5 But the Papers Worked — Why Didn't FORGE Transfer?

Fair question, because the DELULU numbers say the implementation is *faithful*:

| Benchmark (paper-shaped) | Result | Paper's claim |
|---|---|---|
| DELULU FIM (FORGE-only, no L3) | Python 100%, TS 87.5%, Rust 75%, 0% FPR | ✔ reproduced |
| GDScript corpus (ours) | 10/12 recall, 0 FP | ✔ |
| recall_corpus synthetic | 18/30, L3 gate 7/8 | ✔ |

The pipeline delivers the papers' performance **on the papers' distribution**. The decisive run measured a different distribution and got 17% precision / 10–15% recall. Five transfer gaps explain the delta:

**G1 — Benchmarks hold ground truth adjacent; deployment doesn't.**
FIM completion embeds the hallucination inside the *real* file — the scanner sees the same context the model saw, and labels are unambiguous. An agent generates whole files from scratch: it *creates* project-local symbols (`task_queue.h`, `EnrichedRecord`), so "is this symbol real?" is ill-defined without project knowledge. Same blind spot cuts both ways — fragment-visibility FPs (fixed, days 1–2) and fragment-visibility FNs (the scanner can't tell invented from project-local).

**G2 — The papers' knowledge base is circular; ours has to be real.**
FORGE's "dynamic KB" and the Inspector's symbol graphs are built from the same dependency universe the evaluation samples from. Deployed, my KB = live fetchers + seed bundles. It is **version-unpinned and symbol-shallow**: npm/PyPI verification confirms *package existence*, not *export existence* (`createHTTPServer` from `trpc-playground` — real package, phantom export → missed); docs.rs/pkg.go.dev aren't pinned to the project's manifest versions, so every version-confusion hallucination (Godot 3 `scancode` in claimed 4.3, `axum::Server::bind` in claimed 0.7, pydantic-v1 `(cls, values)` signature for v2 `mode="after"`) is invisible to it. A version-resolved API graph for major ecosystems is a Snyk-scale undertaking that rots as it's built — the papers assume it into existence.

**G3 — The semantic class was assigned to a layer that couldn't run.**
What did the deterministic layers miss? Type-level semantics: `ostream_iterator<Sales>` without `operator<<`, `std::get_if` on a variant whose alternatives don't include the queried type, Serilog's non-generic `ILogger` used as `ILogger<T>`, undefined `next` inside inferred express handler signatures. That class needs type inference or an LLM judge — L3 territory. L3 was (a) handicapped all along (Reasoning's Razor died: no logprobs on GLM; judge = budget glm-4.7-flash), (b) mostly skipped by the cascade (confidence ≥ 0.85 short-circuits it), and (c) *disabled entirely* in the decisive run for determinism. So the run measured the deterministic papers at their honest floor — and that class lives at the floor.

**G4 — FP-reduction and recall are the same dial, and the papers sit in a friendlier region.**
My own history proves it: 2026-08-10 FP-reduction work cut 101→23 warnings (~8 TP "preserved" — a count never audited to the new standard). Every Code-Mirage-style skip list, cold-start guard, and uncertain-warning suppressor exists to kill an FP class — and each swallows recall at the boundary (`next(error)` looks exactly like a bound param; express's inferred handler types make scope analysis guess). In FIM benchmarks, planted hallucinations are clean, so the trade-off curve has room. In the wild, real hallucinations are *near-misses of real APIs* — the exact shape the FP guards were tuned to ignore.

**G5 — Papers measure detection; the product needed joint utility.**
No paper claims an agent completes more tasks with a detector in the loop. Even a perfect detector shows ~0 product value when: strong models hallucinate ~nothing catchable (Exp 1), agent tool-feedback self-corrects the rest, and injected warnings destabilize weak models (Exp 2). The four-term joint probability was never in any paper's scope — it was only in ours, and I should have measured *its* terms before building the detector.

**Also honest:** the August-10 baseline "~8 TP preserved" and the decisive-run "11–16 TPs" were both instance-counted by an unaudited auditor (me). The 4-solid-TP figure is the only number that survived adversarial audit. Cross-run comparisons of unaudited numbers are how I fooled myself twice.

**Bottom line:** not an implementation failure — a generalization failure the papers' evaluation design cannot see. The reproducible core (DELULU, GDScript corpus) is real and open-sources with the repo. The gap between it and the deployed product is filled by things no scanner paper provides: version-pinned API ground truth, type-level semantic checking, and evidence that intervention helps agents at all.

## 3.6 Why Not Brute-Force It With AI Manpower?

Obvious follow-up: AI labor is cheap now — why not grind recall from 15% to 80% and ship? Because **the sprint was the brute-force experiment, and it worked**: in five days, AI subagents fixed the dominant FP class (10/10 suppressed), closed the Anthropic block+retry debt live-validated end-to-end, built and ran a 25-task adversarially-audited benchmark. The engineering got fixed. The product still died. Manpower wasn't the binding constraint; four things are, and none yield to it:

**B1 — The utility term has no engineering solution.**
Detection quality has zero leverage on the actual kill terms: strong models hallucinate ~nothing catchable, agents self-correct the rest via tool feedback, and injected warnings destabilize weak models (the one causal observation was harmful). A detector at 100% recall / 100% precision still delivers an empty diff on that value function. You cannot grind a market into existing.

**B2 — The target decays while you grind.**
Hallucination rate is the #1 quality metric at the best-funded labs; it falls monotonically. Every month of grinding buys a detector for less failure mass. The surviving segment (weak/local models, niche languages, post-cutoff SDKs) is real but small — that's a tool or a feature, not a brute-force-a-company-into-existence target.

**B3 — Manpower is symmetric; distribution isn't.**
Anything I can brute-force, the incumbent with the customer relationship brute-forces cheaper — and they hold the *native* ground truth (agent context, repo, tool results) My wire proxy must reconstruct at a permanent disadvantage. AI labor being cheap erased the one moat a small team could have claimed.

**B4 — The measurement wall.**
Iterating requires signal. Agent-level A/B is flake-dominated (headline sign flipped between identical runs); getting a clean 10% effect needs hundreds of paired tasks per iteration. Grinding without measurement signal is a random walk — you can't even tell which fixes help.

**What brute force IS rational:** a small, cheap, pre-registered demand test — measure
whether anyone actually needs the pivot *before* months of grinding. Everything larger
fails on B1–B4 above.

## 4. What I Learned That Generalizes

1. **Hallucination rate is wildly distribution-dependent** (0 catchable TP in ~50 task-hours on famous repos/strong model; ~1-2 hallucinations per task on unfamiliar SDKs/weak model). Any "do agents hallucinate?" claim without a distribution attached is meaningless.
2. **Agentic tool feedback eats most hallucinations before they matter.** The failure mode that survives agentic loops is the *silent* one — wrong-but-plausible API usage that compiles or nearly compiles. That's precisely the class deterministic scope-checking is worst at and version-sensitive semantic checking is required for.
3. **Interventions on generation are asymmetric-risk.** A false warning injected mid-stream costs a working task; a missed hallucination usually costs one tool-call round-trip. The failure asymmetry runs opposite to the product's asymmetry.
4. **A negative A/B result with sign flip is a finding, not noise to be re-run away.** Two full runs' worth of flake taught me more than the headline numbers did.
5. **The compiler is the floor and the ceiling** for "does this code work" checking. Everything above the floor requires knowledge that rots. Pick your product accordingly.

---

## 5. What Survives

- **The engineering:** the fragment-visibility FP suppression (proxy-side session symbols) and the Anthropic-wire block+retry with native tool_use re-emission are correct, tested, and useful to whoever builds the next thing on a wire proxy. Code will be open-sourced.
- **The benchmark harness and corpus:** 25 hard-distribution tasks with auditor-labeled ground truth (now including ~60 labeled hallucination instances (missed, marginal, and caught) and 41 labeled warnings). This is the scarce artifact — an honest, adversarially-audited hallucination benchmark.
- **The dataset:** ~100 agent-hours of transcripts across two model tiers with complete audit trails, including the full negative-result record.
- **The untested pivot:** "grounding evals for coding agents" as a CI product (point the scanner at your agent's transcripts on *your* codebase, get a hallucination report). ~80% built (`scan_transcript` binary exists). I did not run the demand test; if anyone does, the recall numbers above say the report must be framed as *coverage measurement*, not detection quality.

---

## 6. The Ledger

| Claim | Verdict |
|---|---|
| Scanner catches hallucinations from strong agents on real repos | **Falsified** (0 TP / ~50 task-hours) |
| Weak models hallucinate more, scanner catches them | **Falsified** (11 warnings → 10 FP + 1 TP; decisive run: 4 TP at 17% precision) |
| Scanner warnings help agents | **Falsified** (only causal observation was harmful) |
| Proxy is transparent / zero friction | **Confirmed** (twice, byte-identical) |
| Fragment-visibility FPs are fixable | **Confirmed** (10/10 suppressed, TP preserved) |
| Block+retry works on Anthropic wire | **Confirmed** (validated end-to-end) |
| Deterministic layers detect real hallucinations at usable recall | **Falsified** (10–15% recall, 17% warning-level precision) |

## Appendix — Artifacts & Reproduction

- Code: https://github.com/robbe1912/anubis-public (MIT)
- Results log: `docs/swe-bench-results.md` in this repo (full experimental narrative incl. corrections)
- Hard benchmark: https://github.com/robbe1912/anubis-benchmark (corpus + harness + labels)
- SWE-bench run artifacts (glm + qwen arms, predictions, harness reports) were transient session data and are not published; outcomes are recorded in `docs/swe-bench-results.md`.
- Key env added for reproducibility: `ANUBIS_DISABLE_L3`, `ANUBIS_DISABLE_LSP_GATE` (rust-analyzer shutdown deadlock workaround), `ANUBIS_DISABLE_COMPILER_GATES`

*Written by the agent that built it, audited by the agent that killed it. Both were right.*
