# Anubis

> I built a hallucination detector for coding agents. Then I measured it to death.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-daemon--rs-orange)](packages/daemon-rs)

Anubis is a **local proxy daemon** that sits between AI coding agents (Claude Code, OpenCode, Cursor, Copilot, Aider, …) and your LLM provider. It intercepts every response and scans generated code for hallucinated APIs, invented imports, and undefined symbols across 7 languages.

**It works as built. It did not work as a product.** This repository is published as an honest postmortem: ~120 dev-hours, ~100 agent-hours of measurement, two model tiers, adversarially-audited results.

**Read the postmortem first: [`docs/anubis-postmortem.md`](docs/anubis-postmortem.md)** — it is the most valuable file here.

## The numbers that killed it

| Experiment | Result |
|---|---|
| SWE-bench Verified A/B, strong model (GLM-5-Turbo), 24×2 tasks | **0 true positives** in ~50 task-hours; the single warning delivered was a false positive |
| SWE-bench Verified A/B, weak model (Qwen3.5-9B), 24×2 tasks | 11 warnings — on replay 10 false positives (fragment-visibility class), 1 real; headline sign **flipped between runs** — A/B deltas were flake, not signal |
| Hard-distribution corpus (novel SDKs, 25 tasks), adversarially audited | 41 warnings → **4 solid true positives** (kill criterion was ≥6); precision 17%, recall 10–15% |
| One observed live intervention (warn mode, weak model) | Coincided with the task **collapsing** while the control arm resolved it |

Detection quality was never the binding constraint. Prevalence, agent self-correction, and intervention asymmetry were. The postmortem explains why in detail — including why the research papers (FORGE 2026, Code Mirage, MARIN, …) reproduced cleanly on their own benchmarks and still didn't transfer.

## What's actually here

| Path | What it is | Honest value |
|---|---|---|
| [`packages/daemon-rs/`](packages/daemon-rs/) | The Rust daemon: HTTP proxy (OpenAI + Anthropic wires, streaming SSE), 4-layer scan cascade (regex → symbol cache → AST/FORGE → LLM judge), block+retry with tool-call re-emission, TUI dashboard, admin API | Wire-level engineering is the best part — dual-wire streaming interception with hold-buffer-and-replay is genuinely scarce. The scan cascade is faithful to the papers; the papers' distribution is not the agent distribution. |
| [`packages/eval/`](packages/eval/) | TS eval harness + ~70 case files | Language-agnostic cases, reusable |
| [`docs/anubis-postmortem.md`](docs/anubis-postmortem.md) | Full postmortem with pre-registered gates, adversarial audit, root causes | **The point of this repo** |
| [`docs/swe-bench-results.md`](docs/swe-bench-results.md) | Raw A/B experiment log, both model tiers | Reproducible negative result |
| [anubis-benchmark](https://github.com/robbe1912/anubis-benchmark) | Hard-distribution corpus + harness + auditor labels (~60 labeled hallucination instances, all 41 warnings classified) | The falsifiable core — run your detector against it |

## Build

```bash
cd packages/daemon-rs
cargo build --release
./target/release/anubis-daemon   # starts proxy on 127.0.0.1:7878
```

Point your agent at `http://127.0.0.1:7878/v1` (OpenAI wire) or `/v1/messages` (Anthropic wire) with an `x-anubis-target` header naming the real upstream. Config lives at `~/.anubis/config.yaml`. See [`packages/daemon-rs/README.md`](packages/daemon-rs/README.md).

Useful env switches discovered during benchmarking: `ANUBIS_DISABLE_L3` (skip LLM judge), `ANUBIS_DISABLE_LSP_GATE` (skip rust-analyzer/gopls gate — its shutdown can deadlock batch runs), `SKIP_COMPILER_GATES`.

## Why open-source it

1. The negative result is real information. Detector papers report recall on planted hallucinations; nobody publishes the deploy-time joint probability (does the model hallucinate catchably × does the agent not self-correct × does the detector fire true × does the warning help). I measured it. It's approximately zero for strong models on familiar code, and the FP branch fires more than the TP branch for weak models.
2. The wire-proxy machinery (Anthropic `tool_use` SSE block + re-emit, hold-buffer-and-replay streaming) is useful to anyone building agent middleware.
3. Grave-dancing is cheap; publishing your own kill is not. Trust compounds.

## Fork it — beat the numbers

I killed this on *my* numbers: my models, my distribution, my measurement budget. That's a data point, not a law of nature. If you think reliable hallucination detection for coding agents is buildable, the whole rig is here — dual-wire proxy, 4-layer cascade, a labeled hard-distribution corpus, and the benchmark harness that killed it. Fork it, beat the numbers, publish the writeup. Open source is combined brainpower; brute force welcome.

## License

MIT. Use the code, cite the failure.

---

*The Egyptian god Anubis weighed hearts against the Feather of Truth. This Anubis weighed its own claims the same way — and did not survive the scales. Ammit ate well.*
