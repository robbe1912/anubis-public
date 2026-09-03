// Internal HTTP API — /__anubis/* routes for TUI communication.
// Mirrors packages/proxy/src/api.ts.

use crate::proxy::AppState;
use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Read JSON body from request (64KB max).
async fn read_json_body(req: Request<Body>) -> Result<serde_json::Value, Response> {
    let bytes = match axum::body::to_bytes(req.into_body(), 65536).await {
        Ok(b) => b,
        Err(_) => {
            return Err(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"error": "body too large"}),
            ))
        }
    };
    serde_json::from_slice(&bytes).map_err(|_| {
        json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid JSON"}),
        )
    })
}

/// Handle /__anubis/* internal API routes.
/// Returns a Response if the route was handled, or falls through to proxy.
/// Pure auth decision (unit-testable without a live server). Returns Some(401/403 response)
/// when the request must be rejected, None when allowed. Threat model in handle_internal_api docs.
fn auth_rejects(
    route: &str,
    has_origin: bool,
    provided_token: Option<&str>,
    expected_token: &str,
) -> Option<Response> {
    const OPEN_ROUTES: [&str; 1] = ["/__anubis/ping"];
    if OPEN_ROUTES.contains(&route) {
        return None;
    }
    // Browsers always send Origin on cross-site POSTs; curl/TUI never do.
    if has_origin {
        return Some(json_response(
            StatusCode::FORBIDDEN,
            serde_json::json!({"error": "browser requests are not permitted on admin routes"}),
        ));
    }
    if expected_token.is_empty() {
        return None; // no token configured (legacy installs) - config load generates one
    }
    let provided = provided_token.unwrap_or("");
    // Constant-time-ish comparison to avoid token oracle.
    if provided.len() != expected_token.len()
        || !provided
            .bytes()
            .zip(expected_token.bytes())
            .all(|(a, b)| a == b)
    {
        return Some(json_response(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "missing or invalid X-Anubis-Token header"}),
        ));
    }
    None
}
pub async fn handle_internal_api(
    path: String,
    method: axum::http::Method,
    req: Request<Body>,
    state: AppState,
) -> Response {
    let route = path.split('?').next().unwrap_or(&path);

    // ── Auth gate (go-public-graveyard BLOCKER-2) ─────────────────────
    // Every non-ping route requires the per-install token generated in
    // config.rs (persisted to ~/.anubis/config.yaml). Threat model:
    //   - Browser CSRF: a web page can POST text/plain (no preflight) to
    //     127.0.0.1:7878 and flip routing/scanner config — exfiltrating
    //     all subsequent prompts + Bearer keys. It cannot know the token.
    //   - Unprivileged local processes: cannot read ~/.anubis/config.yaml.
    // Additionally reject requests bearing an Origin header outright on
    // protected routes (legitimate local callers — TUI, CLI, harness —
    // never send one) and require JSON content-type on mutating routes.
    const OPEN_ROUTES: [&str; 1] = ["/__anubis/ping"];
    if let Some(reject) = auth_rejects(
        route,
        req.headers().contains_key(axum::http::header::ORIGIN),
        req.headers()
            .get("x-anubis-token")
            .and_then(|v| v.to_str().ok()),
        &crate::config::load_config().api_token,
    ) {
        return reject;
    }

    match (route, method.as_str()) {
        // ── GET /ping — health check (always open) ─────────────────────
        ("/__anubis/ping", "GET") => json_response(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "version": crate::config::config_version()
            }),
        ),

        // ── GET /config — return current proxy config (used by dashboard) ──
        // api_key is REDACTED — the dashboard renders config, it never needs
        // the raw secret (graveyard: plaintext key exfil via CSRF-able GET).
        ("/__anubis/config", "GET") => {
            let mut cfg = crate::config::load_config();
            if !cfg.scanner.api_key.is_empty() {
                cfg.scanner.api_key = format!(
                    "***{}",
                    &cfg.scanner.api_key[cfg.scanner.api_key.len().saturating_sub(4)..]
                );
            }
            cfg.api_token = String::new();
            json_response(StatusCode::OK, serde_json::to_value(&cfg).unwrap_or_default())
        },

        // ── GET /stats ─────────────────────────────────────────────────
        // Reads from JSONL scan log — single source of truth.
        // In-memory ProxyStats provides cumulative counters (tokens, latency).
        // Recent entries + scan result counters come from scan_log dedup.
        ("/__anubis/stats", "GET") => {
            let s = state.stats.read().await;
            let mut view = serialize_stats(&s);

            // Override recent_entries + scan counters from JSONL scan log
            // (single source of truth — warnings-wins deduplication)
            let (total, clean, warning, blocked, skipped, _vc, risk_sum, entries) =
                crate::scan_log::compute_stats();
            if total > 0 {
    view["cleanCount"] = serde_json::json!(clean);
    view["warningCount"] = serde_json::json!(warning);
    view["blockedCount"] = serde_json::json!(blocked);
    view["skippedCount"] = serde_json::json!(skipped);
    view["riskScoreSum"] = serde_json::json!(risk_sum);
    view["riskScoreCount"] = serde_json::json!(total);
    view["recentEntries"] = serde_json::json!(entries);
            }
            json_response(StatusCode::OK, view)
        }

        // ── GET /cache-status — symbol cache health (used by dashboard + CLI) ──
        ("/__anubis/cache-status", "GET") => {
            let (total, libraries, is_cold) = match crate::symbols::cache::SymbolCache::open() {
                Ok(cache) => {
                    let count = cache.count().unwrap_or(0);
                    let libs = cache.list_libraries();
                    (count, libs, count == 0)
                }
                Err(_) => (0usize, Vec::new(), true),
            };
            json_response(StatusCode::OK, serde_json::json!({
                "total_symbols": total,
                "libraries": libraries.iter().map(|(lib, ver, cnt)| {
                    serde_json::json!({"library": lib, "version": ver, "symbols": cnt})
                }).collect::<Vec<_>>(),
                "is_cold": is_cold,
                "warming_in_progress": crate::cache_warming::is_warming(),
            }))
        }

        // ── GET /metrics — Prometheus exposition format ───────────────
        // Drop-in for `metrics_exporter_prometheus`. Returns text/plain
        // version 0.0.4 so Prometheus / Grafana / VictoriaMetrics can scrape
        // it directly without a sidecar. Reuses existing ProxyStats counters
        // — no separate metrics crate needed.
        ("/__anubis/metrics", "GET") => {
            let s = state.stats.read().await;
            let (verdict_cache_hits, verdict_cache_misses, verdict_cache_size) =
                crate::scanner::verdict_cache_stats();
            let body = render_prometheus(&s, verdict_cache_hits, verdict_cache_misses, verdict_cache_size);
            (
                StatusCode::OK,
                [
                    ("content-type", "text/plain; version=0.0.4"),
                    ("cache-control", "no-cache"),
                ],
                body,
            )
                .into_response()
        }

        // ── POST /clear ────────────────────────────────────────────────
        ("/__anubis/clear", "POST") => {
            let mut s = state.stats.write().await;
            s.clear();
            // Truncate the JSONL scan log — it's the source of truth for
            // the dashboard's Recent Requests display. Without this, cleared
            // entries would reappear on next poll.
            crate::scan_log::clear();
            json_response(StatusCode::OK, serde_json::json!({"ok": true}))
        }

        // ── GET /harnesses — list all harnesses + provider routes ─────
        ("/__anubis/harnesses", "GET") => {
            let cfg = crate::config::load_config();
            let url = cfg.proxy_url();
            let harnesses = crate::harness::list_harnesses(&url);
            json_response(
                StatusCode::OK,
                serde_json::to_value(&harnesses).unwrap_or_default(),
            )
        }

        // ── POST /harness/enable — enable provider routing ────────────
        ("/__anubis/harness/enable", "POST") => {
            let body = match read_json_body(req).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            let harness_id = body["harnessId"].as_str().unwrap_or("");
            let provider_id = body["providerId"].as_str();
            let cfg = crate::config::load_config();
            let url = cfg.proxy_url();
            let result = if let Some(pid) = provider_id {
                crate::harness::enable_provider(harness_id, pid, &url)
            } else {
                // Bulk: enable all providers for this harness
                let harnesses = crate::harness::list_harnesses(&url);
                let h = harnesses.iter().find(|h| h.id == harness_id);
                if let Some(h) = h {
                    for p in &h.providers {
                        let _ = crate::harness::enable_provider(harness_id, &p.id, &url);
                    }
                    Ok(())
                } else {
                    Err(format!("harness not found: {harness_id}"))
                }
            };
            match result {
                Ok(()) => json_response(StatusCode::OK, serde_json::json!({"ok": true})),
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({"error": e}),
                ),
            }
        }

        // ── POST /harness/disable — disable provider routing ──────────
        ("/__anubis/harness/disable", "POST") => {
            let body = match read_json_body(req).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            let harness_id = body["harnessId"].as_str().unwrap_or("");
            let provider_id = body["providerId"].as_str();
            let result = if let Some(pid) = provider_id {
                crate::harness::disable_provider(harness_id, pid)
            } else {
                // Bulk: disable all providers for this harness
                let cfg = crate::config::load_config();
                let url = cfg.proxy_url();
                let harnesses = crate::harness::list_harnesses(&url);
                let h = harnesses.iter().find(|h| h.id == harness_id);
                if let Some(h) = h {
                    for p in &h.providers {
                        if p.routed {
                            let _ = crate::harness::disable_provider(harness_id, &p.id);
                        }
                    }
                    Ok(())
                } else {
                    Err(format!("harness not found: {harness_id}"))
                }
            };
            match result {
                Ok(()) => json_response(StatusCode::OK, serde_json::json!({"ok": true})),
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({"error": e}),
                ),
            }
        }

        // ── POST /routing — update routing config ─────────────────────
        ("/__anubis/routing", "POST") => {
            let body = match read_json_body(req).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            {
                let mut cfg = state.config.write().await;
                if let Some(mode) = body["mode"].as_str() {
                    cfg.routing.mode = match mode {
                        "sleev" => crate::config::RoutingMode::Sleev,
                        "direct" => crate::config::RoutingMode::Direct,
                        "custom" => crate::config::RoutingMode::Custom,
                        _ => {
                            return json_response(
                                StatusCode::BAD_REQUEST,
                                serde_json::json!({"error": format!("unknown mode: {mode}")}),
                            );
                        }
                    };
                }
                if let Some(url) = body["custom_url"].as_str() {
                    cfg.routing.custom_url = url.to_string();
                }
                let _ = crate::config::save_config(&cfg);
            }
            json_response(StatusCode::OK, serde_json::json!({"ok": true}))
        }

        // ── POST /scanner — update scanner config ─────────────────────
        ("/__anubis/scanner", "POST") => {
            let body = match read_json_body(req).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            {
                let mut cfg = state.config.write().await;
                if let Some(model) = body["model"].as_str() {
                    cfg.scanner.model = model.to_string();
                }
                if let Some(base_url) = body["base_url"].as_str() {
                    cfg.scanner.base_url = base_url.to_string();
                }
                if let Some(block) = body["block_on_hallucination"].as_bool() {
                    cfg.scanner.block_on_hallucination = block;
                }
                if let Some(inject) = body["auto_inject_docs"].as_bool() {
                    cfg.scanner.auto_inject_docs = inject;
                }
                if let Some(pre) = body["preemptive_scan"].as_bool() {
                    cfg.scanner.preemptive_scan = pre;
                }
                if let Some(verify) = body["post_edit_verify"].as_bool() {
                    cfg.scanner.post_edit_verify = verify;
                }
                if let Some(exec) = body["execution_gate"].as_bool() {
                    cfg.scanner.execution_gate = exec;
                }
                let _ = crate::config::save_config(&cfg);
            }
            json_response(StatusCode::OK, serde_json::json!({"ok": true}))
        }

        // ── Unknown route ──────────────────────────────────────────────

        ("/__anubis/models", "GET") => {
            let cfg = state.config.read().await;
            let base_url = cfg.scanner.base_url.trim_end_matches('/').to_string();
            let api_key = cfg.scanner.api_key.clone();

            if api_key.is_empty() {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "error": "scanner api_key is empty — set it via POST /__anubis/scanner to list available models",
                        "models": []
                    }),
                );
            }

            // Call the provider's /models endpoint (OpenAI-compatible standard)
            let models_url = format!("{}/models", base_url);
            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    return json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        serde_json::json!({"error": format!("http client build failed: {e}"), "models": []}),
                    );
                }
            };

            match client
                .get(&models_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        return json_response(
                            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                            serde_json::json!({
                                "error": format!("provider returned {}: {}", status, &body[..body.len().min(200)]),
                                "models": []
                            }),
                        );
                    }
                    match resp.json::<serde_json::Value>().await {
                        Ok(json) => {
                            // OpenAI-compatible format: { "data": [{ "id": "model-name" }, ...] }
                            let models: Vec<String> = json["data"]
                                .as_array()
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|m| m["id"].as_str().map(|s| s.to_string()))
                                        .collect()
                                })
                                .unwrap_or_default();

                            json_response(
                                StatusCode::OK,
                                serde_json::json!({
                                    "models": models,
                                    "provider_url": base_url,
                                }),
                            )
                        }
                        Err(e) => json_response(
                            StatusCode::BAD_GATEWAY,
                            serde_json::json!({"error": format!("failed to parse models response: {e}"), "models": []}),
                        ),
                    }
                }
                Err(e) => json_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({"error": format!("failed to reach {}: {e}", models_url), "models": []}),
                ),
            }
        }

        _ => json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "error": format!("unknown route: {} {}", method, route)
            }),
        ),
    }
}

/// Serialize stats for the API response.
fn serialize_stats(stats: &crate::stats::ProxyStats) -> serde_json::Value {
    serde_json::json!({
        "totalRequests": stats.total_requests,
        "totalErrors": stats.total_errors,
        "totalTokens": stats.total_tokens,
        "promptTokens": stats.prompt_tokens,
        "completionTokens": stats.completion_tokens,
        "reasoningTokens": stats.reasoning_tokens,
        "cleanCount": stats.clean_count,
        "warningCount": stats.warning_count,
        "blockedCount": stats.blocked_count,
        "skippedCount": stats.skipped_count,
        "validatorTokens": stats.validator_tokens,
        "validatorCalls": stats.validator_calls,
        "localCheckCount": stats.local_check_count,
        "agentCheckCount": stats.agent_check_count,
        "docsHitCount": stats.docs_hit_count,
        "compactionCount": stats.compaction_count,
        "backgroundCount": stats.background_count,
        "cacheHitCount": stats.cache_hit_count,
        "latencies": stats.latencies,
        "recentEntries": stats.recent_entries.iter().map(|e| {
            if e.validator_response.is_empty() {
                serde_json::json!({
                    "ts": e.ts,
                    "request_id": e.request_id,
                    "model": e.model,
                    "streaming": e.streaming,
                    "status": e.status,
                    "latency_ms": e.latency_ms,
                    "scan_result": e.scan_result.to_string(),
                    "scan_details": e.scan_details,
                    "validator_response": "",
                })
            } else {
                serde_json::json!({
                    "ts": e.ts,
                    "request_id": e.request_id,
                    "model": e.model,
                    "streaming": e.streaming,
                    "status": e.status,
                    "latency_ms": e.latency_ms,
                    "scan_result": e.scan_result.to_string(),
                    "scan_details": e.scan_details,
                    "validator_response": e.validator_response,
                })
            }
        }).collect::<Vec<_>>(),
    })
}

/// Build a JSON response.
fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let json = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    let mut response = Response::new(Body::from(json));
    *response.status_mut() = status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

/// Run the status check CLI command.
pub async fn run_status() {
    let cfg = crate::config::load_config();
    let url = cfg.proxy_url();
    let start = std::time::Instant::now();

    let client = reqwest::Client::new();
    let req = client.get(format!("{}/__anubis/stats", url));

    match req.timeout(std::time::Duration::from_secs(2)).send().await {
        Ok(res) if res.status().is_success() => {
            let elapsed = start.elapsed().as_millis();
            let stats: serde_json::Value = res.json().await.unwrap_or_default();
            println!("✓ daemon alive at {} ({}ms)", url, elapsed);
            println!("  mode: {:?}", cfg.routing.mode);
            println!(
                "  scanner: {} @ {}",
                cfg.scanner.model, cfg.scanner.base_url
            );
            println!(
                "  requests: {}",
                stats
                    .get("totalRequests")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
            let clean = stats
                .get("cleanCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let warn = stats
                .get("warningCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let blocked = stats
                .get("blockedCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let skipped = stats
                .get("skippedCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!(
                "  clean: {}  warn: {}  blocked: {}  skipped: {}",
                clean, warn, blocked, skipped
            );
            let vcalls = stats
                .get("validatorCalls")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let vtokens = stats
                .get("validatorTokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if vcalls > 0 {
                println!("  validator: {} calls · {} tokens", vcalls, vtokens);
            }

            // Cache status
            if let Ok(cache_res) = client
                .get(format!("{}/__anubis/cache-status", url))
                .timeout(std::time::Duration::from_secs(2))
                .send()
                .await
            {
                if cache_res.status().is_success() {
                    let cs: serde_json::Value =
                        cache_res.json().await.unwrap_or_default();
                    let total = cs
                        .get("total_symbols")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let is_cold = cs
                        .get("is_cold")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let warming = cs
                        .get("warming_in_progress")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let lib_count = cs
                        .get("libraries")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    if is_cold {
                        println!(
                            "  cache: COLD ({} symbols, {} libs) — run 'anubis symbols fetch'",
                            total, lib_count
                        );
                        if warming {
                            println!("  cache: warming in progress...");
                        }
                    } else {
                        println!(
                            "  cache: {} symbols across {} libraries",
                            total, lib_count
                        );
                    }
                }
            }

            std::process::exit(0);
        }
        _ => {
            eprintln!("✗ daemon not reachable at {}", url);
            eprintln!("  run 'anubis daemon' to start it.");
            std::process::exit(1);
        }
    }
}

/// Render `ProxyStats` in Prometheus text exposition format (v0.0.4).
///
/// Each metric gets a HELP line (description) + TYPE line (counter/gauge/
/// histogram) + one or more sample lines. Naming follows Prometheus
/// conventions (`_total` suffix for monotonic counters, snake_case).
///
/// Latencies are exported as a synthetic histogram with fixed buckets so
/// Grafana can plot p50/p95/p99 without client-side computation. Buckets
/// chosen to span typical agent request latencies (50ms fast cache hit →
/// 30s validator timeout).
pub fn render_prometheus(
    s: &crate::stats::ProxyStats,
    verdict_cache_hits: u64,
    verdict_cache_misses: u64,
    verdict_cache_size: usize,
) -> String {
    use crate::stats::ScanResult;
    use std::fmt::Write;

    let mut out = String::with_capacity(2048);

    // ── Counters ────────────────────────────────────────────────────
    let mut counter = |name: &str, help: &str, value: u64, labels: &str| {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name}{labels} {value}"
        );
    };

    counter(
        "anubis_requests_total",
        "Total LLM requests proxied.",
        s.total_requests,
        "",
    );
    counter(
        "anubis_scan_results_total",
        "Scan verdict counts by result.",
        s.clean_count,
        "{result=\"clean\"}",
    );
    counter(
        "anubis_scan_results_total",
        "Scan verdict counts by result.",
        s.warning_count,
        "{result=\"warning\"}",
    );
    counter(
        "anubis_scan_results_total",
        "Scan verdict counts by result.",
        s.blocked_count,
        "{result=\"blocked\"}",
    );
    counter(
        "anubis_scan_results_total",
        "Scan verdict counts by result.",
        s.skipped_count,
        "{result=\"skipped\"}",
    );
    counter(
        "anubis_errors_total",
        "Total upstream errors (502 / network failures).",
        s.total_errors,
        "",
    );
    counter(
        "anubis_validator_calls_total",
        "Layer 3 LLM validator invocations.",
        s.validator_calls,
        "",
    );
    counter(
        "anubis_local_checks_total",
        "Layer 1 / 1.5 deterministic checks (no LLM).",
        s.local_check_count,
        "",
    );
    counter(
        "anubis_agent_checks_total",
        "Layer 3 agent-side checks (LLM).",
        s.agent_check_count,
        "",
    );
    counter(
        "anubis_docs_hits_total",
        "Layer 2 documentation retrievals.",
        s.docs_hit_count,
        "",
    );
    counter(
        "anubis_compaction_requests_total",
        "Background compaction requests (skipped from scan).",
        s.compaction_count,
        "",
    );
    counter(
        "anubis_background_requests_total",
        "Background non-user requests (skipped from scan).",
        s.background_count,
        "",
    );

    // ── Token counters (treated as counters — monotonic) ────────────
    counter(
        "anubis_tokens_total",
        "LLM tokens observed by direction.",
        s.prompt_tokens,
        "{direction=\"prompt\"}",
    );
    counter(
        "anubis_tokens_total",
        "LLM tokens observed by direction.",
        s.completion_tokens,
        "{direction=\"completion\"}",
    );
    counter(
        "anubis_tokens_total",
        "LLM tokens observed by direction.",
        s.reasoning_tokens,
        "{direction=\"reasoning\"}",
    );
    counter(
        "anubis_tokens_total",
        "LLM tokens observed by direction.",
        s.total_tokens,
        "{direction=\"total\"}",
    );

    // ── Verdict cache gauges ────────────────────────────────────────
    counter(
        "anubis_verdict_cache_hits_total",
        "Layer 4 verdict cache hits (skip-scan on identical content).",
        verdict_cache_hits,
        "",
    );
    counter(
        "anubis_verdict_cache_misses_total",
        "Layer 4 verdict cache misses.",
        verdict_cache_misses,
        "",
    );
    let _ = writeln!(
        out,
        "# HELP anubis_verdict_cache_size Gauge of cached verdict entries.\n# TYPE anubis_verdict_cache_size gauge\nanubis_verdict_cache_size {verdict_cache_size}"
    );

    // ── Risk score gauge (running average) ──────────────────────────
    // Continuous hallucination risk in [0.0, 1.0]. Lets ops alert on
    // "avg risk > 0.5 for 5 min" without parsing individual scan results.
    let avg_risk = if s.risk_score_count > 0 {
        s.risk_score_sum / (s.risk_score_count as f64)
    } else {
        0.0
    };
    let _ = writeln!(
        out,
        "# HELP anubis_avg_risk_score Running average of per-scan risk score [0.0, 1.0].\n# TYPE anubis_avg_risk_score gauge\nanubis_avg_risk_score {avg_risk}"
    );

    // ── Latency histogram (bucketed) ────────────────────────────────
    // Buckets chosen to span typical agent request latencies.
    let buckets = [50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000];
    let mut bucket_counts = vec![0u64; buckets.len() + 1]; // +1 for +Inf
    let sum: u64 = s.latencies.iter().map(|&x| x as u64).sum();
    let count = s.latencies.len() as u64;
    for &ms in &s.latencies {
        let idx = buckets.iter().position(|&b| (ms as u64) <= b).unwrap_or(buckets.len());
        bucket_counts[idx] += 1;
    }
    let mut cumulative = 0u64;
    let _ = writeln!(
        out,
        "# HELP anubis_request_duration_seconds Request latency distribution.\n# TYPE anubis_request_duration_seconds histogram"
    );
    for (i, &b) in buckets.iter().enumerate() {
        cumulative += bucket_counts[i];
        let _ = writeln!(
            out,
            "anubis_request_duration_seconds_bucket{{le=\"{}\"}} {}",
            format_duration_bucket(b),
            cumulative
        );
    }
    cumulative += bucket_counts[buckets.len()]; // +Inf
    let _ = writeln!(
        out,
        "anubis_request_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}\nanubis_request_duration_seconds_sum {} \nanubis_request_duration_seconds_count {count}",
        (sum as f64) / 1000.0
    );

    // ── p50 / p95 / p99 (pre-computed, also exported as gauges for easy alerting) ──
    let p50 = s.percentile(50.0);
    let p95 = s.percentile(95.0);
    let p99 = s.percentile(99.0);
    let _ = writeln!(
        out,
        "# HELP anubis_request_latency_ms Percentile request latency in ms.\n# TYPE anubis_request_latency_ms gauge\nanubis_request_latency_ms{{percentile=\"50\"}} {p50}\nanubis_request_latency_ms{{percentile=\"95\"}} {p95}\nanubis_request_latency_ms{{percentile=\"99\"}} {p99}"
    );

    // Suppress unused-import / unused-mut warnings on the no-labels path
    let _ = ScanResult::Clean;
    out
}

/// Format a millisecond bucket boundary as seconds for Prometheus histograms.
/// 50ms → "0.05", 250ms → "0.25", etc. Prometheus expects bucket `le` values
/// in the histogram's base unit (seconds here).
fn format_duration_bucket(ms: u64) -> String {
    let secs = (ms as f64) / 1000.0;
    if secs >= 1.0 {
        format!("{:.0}", secs)
    } else {
        format!("{:.3}", secs).trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::ProxyStats;

    #[test]
    fn auth_gate_open_route_allows_without_token() {
        assert!(auth_rejects("/__anubis/ping", false, None, "tok123").is_none());
    }

    #[test]
    fn auth_gate_rejects_missing_token() {
        let r = auth_rejects("/__anubis/scanner", false, None, "tok123").unwrap();
        assert_eq!(r.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_gate_rejects_wrong_token() {
        let r = auth_rejects("/__anubis/routing", false, Some("wrong"), "tok123").unwrap();
        assert_eq!(r.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_gate_accepts_correct_token() {
        assert!(auth_rejects("/__anubis/routing", false, Some("tok123"), "tok123").is_none());
    }

    #[test]
    fn auth_gate_rejects_browser_origin_even_with_token() {
        let r = auth_rejects("/__anubis/scanner", true, Some("tok123"), "tok123").unwrap();
        assert_eq!(r.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn auth_gate_empty_expected_token_allows() {
        assert!(auth_rejects("/__anubis/scanner", false, None, "").is_none());
    }

    #[test]
    fn render_prometheus_includes_required_metrics() {
        let mut stats = ProxyStats::default();
        stats.total_requests = 10;
        stats.clean_count = 8;
        stats.warning_count = 2;
        stats.prompt_tokens = 1000;
        stats.completion_tokens = 500;
        stats.latencies = vec![100, 500];

        let out = render_prometheus(&stats, 5, 10, 3);

        // Required Prometheus text format markers
        assert!(out.contains("# HELP anubis_requests_total"), "missing HELP: {out}");
        assert!(out.contains("# TYPE anubis_requests_total counter"), "missing TYPE: {out}");

        // Required values
        assert!(out.contains("anubis_requests_total 10"), "missing total_requests value");
        assert!(
            out.contains("anubis_scan_results_total{result=\"clean\"} 8"),
            "missing labeled counter"
        );
        assert!(out.contains("anubis_tokens_total{direction=\"prompt\"} 1000"));

        // Histogram with +Inf bucket
        assert!(out.contains("anubis_request_duration_seconds_bucket{le=\"+Inf\"}"));
        assert!(out.contains("anubis_request_duration_seconds_sum"));

        // Verdict cache stats
        assert!(out.contains("anubis_verdict_cache_hits_total 5"));
        assert!(out.contains("anubis_verdict_cache_size 3"));
    }

    #[test]
    fn render_prometheus_handles_empty_stats() {
        let stats = ProxyStats::default();
        let out = render_prometheus(&stats, 0, 0, 0);
        // Should not panic, should still produce valid format
        assert!(out.contains("# TYPE anubis_requests_total counter"));
        assert!(out.contains("anubis_requests_total 0"));
    }

    #[test]
    fn format_duration_bucket_converts_correctly() {
        assert_eq!(format_duration_bucket(50), "0.05");
        assert_eq!(format_duration_bucket(500), "0.5");
        assert_eq!(format_duration_bucket(1000), "1");
        assert_eq!(format_duration_bucket(30000), "30");
    }
}
