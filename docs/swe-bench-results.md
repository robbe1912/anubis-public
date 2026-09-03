# SWE-bench Verified A/B — Anubis proxy vs Direct (2026-08-19)

## Setup
- 24-task stratified subset of SWE-bench_Verified (django 5, sympy 3, sphinx 2, matplotlib 2,
  sklearn 2, astropy 2, xarray 2, pytest 2, pylint 2, requests 2; seed 42, FAIL_TO_PASS 1-3, patch<14000)
- Coder: opencode (build agent) + z.ai glm-5-turbo via native Anthropic Messages endpoint
- Arm A: opencode -> anubis :7878 (all scanner layers live, warn-only, block OFF) -> z.ai
- Arm B: opencode -> z.ai direct (control)
- Eval: official swebench 5.0.2 Docker harness (Windows CRLF site-packages patch applied;
  gold-patch smoke = 1/1 resolved)

## Results
| | Arm A (anubis) | Arm B (direct) |
|---|---|---|
| Resolved | **14/24 (58.3%)** | 6/24 (25.0%) |
| Empty patch (agent instant-death flake) | 7 | 11 |
| Harness errors | 2 | 2 |

Fair comparison (10 tasks where BOTH arms produced patches): **A 9/10 vs B 6/10**.

## Transcript audit (the honest part)
1. Warning census: audit.jsonl had 6 warning entries in the window; epoch-window attribution
   against all 48 task transcripts shows 5 are PRE-RUN verify-lane leftovers; exactly **1
   warning fired during all of Arm A** (sphinx-8056: `List`, `sel` hallucinated-variable, risk 0.8).
2. That single warning is a **FALSE POSITIVE** of the fragment-visibility class: it fired on an
   explore-subagent response quoting `_format_field(... _desc: List[str]) -> List[str]` —
   `List` is imported at file top in sphinx/ext/napoleon/docstring.py; the scan fragment
   couldn't see the import. The footer DID reach the parent agent (embedded in task_result);
   the agent ignored it and RESOLVED the task.
3. Delta-task forensics: B lost pylint-7277 to a syntactically broken patch (nested `if` with
   empty body = IndentationError) and xarray-3305 to a no-op line-move — model variance, not
   scanner effect.

## Verdict
- The +33pp headline (14 vs 6) is REAL as measured but **NOT attributable to scanner feedback**:
  only 1 warning (an FP) reached an agent all run, and it was ignored. Attribution = run-to-run
  nondeterminism (both arms suffer a ~30-45% instant-death flake: 0-2 events, empty patch) plus
  possible warm-server state asymmetry.
- What IS proven: anubis proxy adds no meaningful friction (A ≥ B on fair comparison),
  scanner stayed quiet (0 TPs — consistent with glm-5-turbo rarely hallucinating on familiar
  OSS repos), and the 1 FP class (subagent-prose fragment visibility) is documented.
- Tightening steps (not run): rerun the 18 empty-patch tasks to completion; N>1 samples per
  task per arm; then the delta becomes interpretable.

## Qwen3.5:9b rerun (2026-08-19, same 24 tasks)

Setup: coder = `qwen3.5:9b-ctx32k` local ollama (num_ctx 32768), scanner unchanged
(glm-4.7-flash, warn-only). Arm A = opencode → anubis :7878 → ollama (OpenAI wire,
`x-anubis-target: http://127.0.0.1:11434`); Arm B = opencode → ollama direct.

| | Arm A (anubis) | Arm B (direct) |
|---|---|---|
| Resolved | 7/24 (29.2%) | **9/24 (37.5%)** |
| Empty patch (instant-death flake) | 14 | 7 |
| Harness errors | 1 | 2 |

Fair comparison (9 both-patched tasks): **A 7/9 vs B 6/9**.

Delta vs glm run: headline sign FLIPPED (glm: A 14 > B 6; qwen: B 9 > A 7) while empty-patch
asymmetry also flipped (7/11 → 14/7). Conclusion: per-arm deltas are dominated by the
instant-death flake + run nondeterminism, now demonstrated by sign reversal on identical infra.

Scanner activity (the point of the rerun):
- Arm A produced **11 warnings** across the run (vs 1 in the entire glm run) — weak model
  triggers the scanner as designed. All 11 mapped to tasks via epoch windows.
- 10/11 fired in deep phase (post-stream) → logged, never injected into the agent.
- Exactly 1 footer reached the agent: sympy-20154 `combinations` hallucinated-variable
  (risk 0.4). Classification: **FP** (fragment visibility — `combinations` is imported from
  itertools at sympy/utilities/iterables.py top; model quoted it while summarizing the file).
- Causal anecdote: sympy-20154 is the one footer-injected task — arm A agent received the
  FP mid-analysis and produced an EMPTY patch; arm B (no warning) patched 1303 bytes and
  RESOLVED. n=1, but the only agent-visible warning in 2 full runs was an FP that coincided
  with task loss.

## Artifacts
- SWE-bench run artifacts (armA/, armB/, predictions, harness reports, logs) were transient
  session data and are not published; outcomes are recorded in this file.
- Qwen rerun artifacts (armA/, armB/, predictions, eval logs) — same: not published.
- Known-issue ledger additions: Anthropic-wire block+retry drops tool calls (2ecccf6 debt,
  worked around with block OFF); instant-death agent flake unattributed.

## Hard-Distribution Test (2026-08-19, Phase 3 of gated sprint)

Setup: 25 hard tasks (anubis-benchmark corpus/hard_tasks: sqlx/axum Rust, trPC/zod TS, gRPC/gin-gorm Go,
EF Core/MediatR/AutoMapper/LINQ C#, C++/C, GDScript). Single-shot prompt via opencode-harness
runner routed through anubis proxy (7878 -> ollama 11434), model qwen2.5-coder:7b.
Offline scan with fresh binary (fragment-visibility FP fix included), L3 + LSP gate disabled
(ANUBIS_DISABLE_L3 / ANUBIS_DISABLE_LSP_GATE env kill-switches added: L3 because z.ai was
529-flaky, LSP gate because rust-analyzer client shutdown deadlocks the process).
task-10 (automapper) FATAL: corrupt spec.md (pre-existing corpus defect) -> 24 usable tasks.

Headline: 41 warnings across 10 tasks; 15 tasks zero warnings; 24/25 harness builds "succeeded"
(build commands are mostly structural checks, so build success != compiles).

TP audit (warning level):
- SOLID TPs 11-16: task-04 placeholder import `path/to/proto/task` (model wrote it in a .go
  import block); task-20 undeclared `T` in module-scope RouterConfig type x4 (real TS errors);
  task-21 `signal.Notify` used without `os/signal` import (go vet: undefined: signal - code
  won't compile); task-24 zero using directives in ALL files -> JsonPolymorphic/JsonDerivedType x2/
  ChannelReader/ChannelWriter not covered by .NET 8 ImplicitUsings = genuinely unresolvable
  (+5 more List/Task/CancellationToken/IAsyncEnumerable implicit-usings-dependent = marginal).
- FPs ~23: task-01 E0609 "no field await" x3 (canonical sqlx, dep-missing rustc artifacts);
  task-06/09 C# extension-method class (WebApplication, Environment.IsDevelopment, AddSingleton,
  RegisterValidatorsFromAssemblyContaining) x5; task-07 self-created header `task_queue.h`;
  task-16 REG_EXTENDED (POSIX-correct, compiler-env artifact); task-18 x9 (8 mangled
  diff-artifact duplicates = warning-formatting bug + 1 suspect fragment parse error);
  task-24 EnrichedRecord() (record HAS matching ctor) + CancellationTokenSource.Cancel()
  (real method, wrong-language symbol cache "local.typescript.robin").
- Precision ~30-40% warning-level. Notable: scanner's compiler gates caught genuinely
  non-compiling code (task-21, task-24) that the harness's own structural build checks passed.

GATE VERDICT: >= 6 auditor-confirmed TPs -> PASS -> CONTINUE (adversarial verification subagent
launched; this section will be amended if it refutes classifications).

FP classes to fix next (identified, mechanical): C# extension-method resolution (IsDevelopment,
AddSingleton etc. are Extension methods on IServiceCollection/IWebHostEnvironment - symbol
cache lacks extension-method table); Rust dep-missing compile artifacts (E0609 on .await when
crate deps unresolvable - gate should suppress field-access-on-Future errors when method
resolution failed due to missing extern crate); warning formatting mangles diff context lines
(task-18 "222 | - forge:" glue bug); wrong-language symbol cache hits (local.typescript.robin
for C# CancellationTokenSource).

## CORRECTION — Hard-Distribution Gate VERDICT: KILL (adversarial audit, 2026-08-19)

The "GATE VERDICT: PASS" above was REFUTED by independent adversarial audit
(an independent audit agent / an independent audit agent). Errors in my audit:

1. COUNTING-UNIT INFLATION: I counted warning instances, not defects. "11-16 solid TPs"
   collapses to 4 distinct solid defects: (a) task-20 undeclared `T` in RouterConfig
   (4 instances = 1 defect); (b) task-21 missing `os/signal` import; (c) task-24 missing
   System.Text.Json.Serialization refs (JsonPolymorphic+JsonDerivedType, 4 instances);
   (d) task-24 missing System.Threading.Channels refs (ChannelReader+ChannelWriter, 4 instances).
   Type-level splitting gives max 6 = threshold only on a coin-flip. 4 < 6 -> KILL.
2. PRECISION (warning-level, all 41): 7 solid (17%), +8 marginal/duplicate (37% incl marginal),
   13 outright FP (32%), 9 corrupted/unusable (22%, task-18 formatting bug).
3. RECALL DEVASTATION: ~20-24 clear hallucination-grade defects MISSED across 10 of 14
   zero-warning tasks (task-03 createHTTPServer from trpc-playground + createTRPCRouter;
   task-05 Godot-3 API in claimed 4.3 (scancode, change_scene on .gd, undefined class_names);
   task-11 axum::Server removed in claimed 0.7 + axum::extract::Json wrong path; task-13
   `next` undefined in 5 handlers; task-15 ostream_iterator<Sales> w/o operator<<;
   task-17 GDS3/4 chimera incl Timer.active (never existed), ConfigFile.open (no such API);
   task-19 pydantic-v2 model_validator signature + .module_name; task-22 get_if on absent
   variant alternative; task-23 implicit-decl + missing stdio.h; task-25 six class_name in
   one file (parse error), GDS4 move_and_slide(velocity)). Plus ~15 more missed inside warned
   tasks (task-04 status/codes/uuid packages used 6x unimported; task-09 Serilog ILogger<T>;
   task-18 json! unimported + ~6 more). Corpus-wide recall ~10-15%.
4. Output-pipeline integrity broken: footer counts != jsonl counts on 3 tasks (16 vs 14,
   1 vs 9), 9/41 warnings corrupted by self-referential formatting bug.
5. Methodological flaws in the gate itself: no counting unit pre-registered, no recall term,
   dependency-free compilation manufactures both FPs and fake TPs, version-target ambiguity
   (axum 0.7 vs clap 3 vs pydantic v1), Windows compilers judging POSIX code.

FINAL: pre-registered kill criterion fired. Anubis as a hallucination DETECTOR for coding
agents is dead: 4 real catches in 24 tasks at 17% solid precision while missing ~85-90%
of real hallucinations. Development stopped here. The project is open-sourced as-is —
the scanner, the corpus, the harness, and this measurement record are the artifacts
worth keeping.
