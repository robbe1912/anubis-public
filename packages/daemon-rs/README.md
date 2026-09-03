# anubis-daemon

The Rust daemon behind the Anubis hallucination detector — an experiment I
measured to death and open-sourced. Read [`docs/anubis-postmortem.md`](../docs/anubis-postmortem.md)
for why this exists as a repo instead of a product.

## What it is

A Rust binary that runs as an HTTP proxy between AI coding agents and their
LLM provider. It intercepts responses, scans generated code for hallucinated
APIs / undefined symbols via a multi-layer cascade (regex → symbol tables →
AST analysis → LLM judge), and can warn or block. my own measurements showed
it catches too little of what matters at too low precision to be worth running
in production — details in the postmortem. Ship as a research artifact.

## Modules

| Module | Purpose |
|---|---|
| `src/proxy.rs` | HTTP server, stream interception, block+retry machinery |
| `src/scanner/` | Multi-layer scanning pipeline |
| `src/remote_docs.rs` | HTTP client for a self-hostable docs Worker (optional) |
| `src/docs_fetcher.rs` | Local npm + GitHub + website scraper (offline tier) |
| `src/docs_cli.rs` | `anubis docs add/list/remove/refresh` CLI |
| `src/license.rs` | Keygen.sh license machinery — **disabled** (`LICENSE_ENFORCEMENT_ENABLED = false`) |
| `src/trial.rs` | Offline JWT trial verification — **disabled**, reference only |
| `src/api.rs` | Local daemon HTTP API (health, validate, metrics) |
| `src/dashboard.rs` | TUI dashboard (ratatui) |
| `src/classify.rs` | Layer 1 verdict classification |
| `src/harness.rs` | OpenCode plugin harness adapter |
| `src/setup.rs` | First-run setup wizard |
| `src/stats.rs` | Request + scan metrics |
| `src/config.rs` | Config loading + persistence |
| `src/symbols/` | Symbol table subsystem (L1.5) |

## Binaries

- `anubis` — CLI: dashboard, daemon control, docs/symbols cache management
- `anubis-daemon` — HTTP proxy + scanner
- `scan_transcript` — offline post-hoc scanner for OpenAI-format JSONL transcripts

## Build

```bash
cd packages/daemon-rs
cargo build --release
# Binaries at target/release/
```

## Tests

```bash
cargo test --lib                          # Unit tests
cargo test --lib symbols::                # Symbol subsystem only
cargo test -- --ignored                   # Network integration tests
```

## License enforcement

The commercial licensing (Keygen activation, trial JWTs, tier gating) shipped
in the original product is **compiled out by default**: every gate short-circuits
and no license or trial is required to run any binary. The machinery is retained
in `license.rs` / `trial.rs` for reference. To re-arm it in a private build, set
`ANUBIS_KEYGEN_ACCOUNT` / `ANUBIS_KEYGEN_PRODUCT` at compile time and flip
`LICENSE_ENFORCEMENT_ENABLED`.

## Documentation

- [`../README.md`](../README.md) — project overview
- [`../docs/anubis-postmortem.md`](../docs/anubis-postmortem.md) — why it was killed, with data
- [`../docs/swe-bench-results.md`](../docs/swe-bench-results.md) — A/B and hard-distribution results

## License

MIT — see [`../LICENSE`](../LICENSE).
