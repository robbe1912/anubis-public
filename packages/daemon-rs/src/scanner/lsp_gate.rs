//! LSP FP Gate — suppresses FORGE false positives using LSP servers as negative oracle.
//!
//! Architecture:
//! ```
//! FORGE warnings → extract symbol → ask LSP (rust-analyzer/gopls) → resolved? → suppress FP
//!                                                                    → unresolved? → keep (real hallucination)
//! ```
//!
//! LSP servers are persistent subprocesses keyed by project_root. They index
//! the workspace once (cold start), then provide sub-second diagnostics for
//! subsequent scans.
//!
//! Supported: rust-analyzer (Rust), gopls (Go).
//! See .omo/plans/scanner-generalization.md for full design.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use crate::scanner::language::Language;

/// Minimum rust-analyzer warmup before accepting diagnostics.
const WARMUP_MS: u64 = 3000;

/// Maximum wait for publishDiagnostics after didOpen.
/// 30s accommodates `cargo check` (flycheck) for non-trivial workspaces.
const DIAGNOSTIC_TIMEOUT_MS: u64 = 30000;

/// Maximum wait for initialize handshake.
const INIT_TIMEOUT_MS: u64 = 30000;

/// Quiet period: assume diagnostics are settled when no publishDiagnostics
/// arrives for this duration. rust-analyzer sends MULTIPLE incremental
/// batches (parse pass first, then type-check pass) — breaking on the first
/// batch misses type errors like `NonExistentType` that only appear in the
/// second pass.
///
/// 3500ms accommodates rust-analyzer's `cargo check` (flycheck) cycle on
/// top of native diagnostics. Flycheck runs `cargo check --workspace` in
/// the background after each file change (default `checkOnSave: true`) and
/// pushes a publishDiagnostics batch when it completes. For a minimal
/// workspace this takes ~2-5s; for large workspaces it can take 30s+, so
/// DIAGNOSTIC_TIMEOUT_MS (the overall cap) is set to 30s.
const DIAGNOSTIC_QUIET_MS: u64 = 3500;

/// RAII guard for restoring an on-disk file overwritten with probe code.
/// On drop (or explicit restore) writes the original bytes back to disk.
/// Used by `suppress_fps` when writing probe code to the user's actual
/// lib.rs/main.rs so rust-analyzer's file watcher triggers re-analysis.
struct ProbeRestore {
    path: PathBuf,
    original: Vec<u8>,
}

/// Owned LSP client subprocess + JSON-RPC transport.
/// Exposed `pub(crate)` so the `scanner::lsp::prewarm` module can call
/// [`LspClient::start`] when prewarming through the registry façade.
pub(crate) struct LspClient {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    root_uri: String,
    next_id: u64,
}

/// Persistent LSP server state, keyed by project_root via the registry.
/// FOUND-006: OnceCell statics replaced by `lsp_registry::LspRegistry`
/// (DashMap<(workspace, language), Arc<Mutex<LspState>>>). The registry
/// caps at 8 concurrent clients process-wide and reaps idle ones after
/// 5 min (see FOUND-007 for the reaper task).
///
/// FOUND-005: `last_used` enables the registry's idle reaper to evict
/// clients unused for > idle_timeout_ms. Field is `pub(crate)` so the
/// registry in `scanner::lsp_registry` can update it on access.
pub(crate) struct LspState {
    pub(crate) client: Option<LspClient>,
    pub(crate) root: String,
    pub(crate) last_used: std::time::Instant,
}

impl LspState {
    /// Empty state — client unavailable, root unset, last_used now.
    /// Used when LSP server fails to start or is missing from PATH.
    pub(crate) fn empty() -> Self {
        Self {
            client: None,
            root: String::new(),
            last_used: std::time::Instant::now(),
        }
    }

    /// Refresh `last_used` to now. Called by the registry on each access
    /// so the idle reaper can distinguish active vs dormant clients.
    pub(crate) fn touch(&mut self) {
        self.last_used = std::time::Instant::now();
    }

    /// Check if the underlying LSP child process has exited (COLD-004).
    ///
    /// Returns `false` (alive) when:
    /// - `client` is `None` (empty state — Vacant slot, not dead per se)
    /// - `client` is `Some` AND the child has NOT exited
    ///
    /// Returns `true` (dead) when:
    /// - `client` is `Some` AND `child.try_wait()` reports `Ok(Some(_))`
    ///   (process exited with any status)
    ///
    /// Caller must hold the mutex (we take `&mut self` because `try_wait`
    /// on a `Child` requires `&mut`). The registry's `reap_dead` calls this
    /// under each entry's `try_lock`; on success, it removes the entry.
    ///
    /// Per master plan COLD-004: "per-client child-exit watcher" — catches
    /// OOM-killed or crashed LSP servers immediately rather than waiting
    /// the full idle timeout (5 min default).
    pub(crate) fn is_dead(&mut self) -> bool {
        let Some(client) = self.client.as_mut() else {
            return false; // Vacant slot — not "dead", just unused.
        };
        // try_wait is non-blocking: returns Ok(Some(status)) if exited,
        // Ok(None) if still running, Err on waitpid failure (treat as alive).
        match client._child.try_wait() {
            Ok(Some(_)) => true,
            _ => false,
        }
    }
}

impl LspClient {
    /// Start an LSP server (rust-analyzer or gopls), send initialize + initialized.
    pub(crate) async fn start(binary: &str, project_root: &Path) -> Option<Self> {
        let cmd = crate::scanner::command_hidden(binary);
        let mut child = tokio::process::Command::from(cmd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            // Debug: inherit stderr so rust-analyzer logs are visible in
            // test output. Remove before production.
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .ok()?;

        let stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        let root_uri = format!("file:///{}", project_root.to_string_lossy().replace('\\', "/"));

        let mut client = LspClient {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
            root_uri,
            next_id: 1,
        };

        // Send initialize request (FOUND-004: typed InitializeParams replaces
        // hand-rolled serde_json::json!). lsp_types follows LSP 3.17 spec —
        // typed structs catch typos in field names that JSON values silently
        // drop (a wrong key like "rootURL" vs "rootUri" would silently
        // disable workspace indexing on every server).
        //
        // initialization_options for rust-analyzer enables experimental
        // diagnostics: by default `unresolved-method-call`, `unresolved-
        // field`, `unresolved-macro-call`, etc. are OFF. These are exactly
        // the hallucination signals we need to detect, so we enable them.
        let init_options = if binary == "rust-analyzer" {
            Some(serde_json::json!({
                "diagnostics": {
                    "experimental": { "enable": true }
                }
            }))
        } else {
            None
        };

        let init_params = lsp_types::InitializeParams {
            work_done_progress_params: lsp_types::WorkDoneProgressParams {
                work_done_token: None,
                ..Default::default()
            },
            process_id: Some(std::process::id()),
            root_path: None,
            root_uri: Some(
                lsp_types::Url::parse(&client.root_uri)
                    .inspect_err(|e| {
                        tracing::warn!(target: "lsp_gate", "root_uri parse failed: {} (uri={})", e, client.root_uri)
                    })
                    .ok()?,
            ),
            initialization_options: init_options,
            capabilities: lsp_types::ClientCapabilities {
                text_document: Some(lsp_types::TextDocumentClientCapabilities {
                    publish_diagnostics: Some(lsp_types::PublishDiagnosticsClientCapabilities {
                        related_information: Some(false),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            trace: None,
            workspace_folders: None,
            client_info: Some(lsp_types::ClientInfo {
                name: "anubis-lsp-gate".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
            locale: None,
        };

        // send_request takes serde_json::Value — serialize the typed params.
        // Serialization cannot fail for InitializeParams (no enums/Maps with
        // non-string keys), so unwrap is safe here per lsp-types contract.
        let init_value = serde_json::to_value(&init_params)
            .expect("InitializeParams serialization cannot fail");

        let _init_result = client
            .send_request("initialize", init_value, INIT_TIMEOUT_MS)
            .await?;

        // Send initialized notification (required by spec). InitializedParams
        // is an empty struct in lsp-types — keeps the notification typed too.
        let initialized_value = serde_json::to_value(&lsp_types::InitializedParams {})
            .expect("InitializedParams serialization cannot fail");
        client
            .send_notification("initialized", initialized_value)
            .await;

        tracing::info!(target: "lsp_gate", "{} initialized for {}", binary, client.root_uri);

        // Give the server a moment to start indexing.
        tokio::time::sleep(std::time::Duration::from_millis(WARMUP_MS)).await;

        Some(client)
    }

    /// Send a JSON-RPC request and wait for the response.
    async fn send_request(
        &mut self,
        method: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Option<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });

        self.write_message(&msg).await.ok()?;

        // Read until we get the response with matching id.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }

            let msg = match tokio::time::timeout(remaining, self.read_message()).await {
                Ok(Some(msg)) => msg,
                _ => continue,
            };

            if msg.get("id").and_then(|v| v.as_u64()) == Some(id) {
                return msg.get("result").cloned();
            }
            // Skip notifications and other responses.
        }
    }

    /// Send a JSON-RPC notification (no response expected).
    async fn send_notification(&mut self, method: &str, params: serde_json::Value) {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        let _ = self.write_message(&msg).await;
    }

    /// Send a JSON-RPC response to a server-initiated request.
    /// Required for `workspace/configuration` and `workspace/diagnostic/refresh`
    /// requests — if we don't respond, rust-analyzer may fall back to default
    /// config (no experimental diagnostics) and refuse to push real diagnostics.
    async fn send_response(&mut self, id: serde_json::Value, result: serde_json::Value) {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        });
        let _ = self.write_message(&msg).await;
    }

    /// Build the rust-analyzer config we want applied: experimental
    /// diagnostics enabled so `unresolved-method-call`, `unresolved-field`,
    /// and `unresolved-macro-call` are reported natively (no cargo check
    /// required). These are the hallucination signals we need.
    fn rust_analyzer_config() -> serde_json::Value {
        serde_json::json!({
            "diagnostics": {
                "experimental": { "enable": true }
            }
        })
    }

    /// Handle an incoming JSON-RPC request (one that has an `id` field).
    /// Server-to-client requests we know about:
    /// - `workspace/configuration`: rust-analyzer asks for the full config
    ///   after `initialized`. If unanswered, falls back to defaults.
    /// - `workspace/diagnostic/refresh`: hint to re-pull diagnostics; the
    ///   spec says respond with null.
    /// - `window/workDoneProgress/create`: cancel-token creation; respond null.
    /// Unknown requests get an empty-object response so the server isn't blocked.
    async fn handle_server_request(&mut self, msg: &serde_json::Value) {
        let Some(id) = msg.get("id") else {
            return; // notification, no response needed
        };
        let id = id.clone();
        let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let result = match method {
            "workspace/configuration" => {
                // rust-analyzer expects an array of configs, one per requested
                // item. Each item's config is a flat object. We always return
                // the same config — it has no per-section granularity.
                Self::rust_analyzer_config()
            }
            "workspace/diagnostic/refresh" | "window/workDoneProgress/create" => {
                serde_json::Value::Null
            }
            _ => serde_json::json!({}),
        };
        self.send_response(id, result).await;
    }

    /// Send textDocument/didOpen + didChange and wait for publishDiagnostics.
    ///
    /// Why didChange after didOpen: rust-analyzer has been observed to NOT
    /// run a full type-check pass on didOpen alone for files already in the
    /// workspace — it treats didOpen as "client now owns truth" but defers
    /// heavy analysis until didChange signals content modification. The
    /// explicit didChange with the same content forces a re-analysis pass.
    ///
    /// Why quiet-period collection: rust-analyzer sends publishDiagnostics
    /// incrementally — first an empty/parse-only batch, then later batches
    /// with type errors. Breaking on the first matching-URI message (the old
    /// behavior) missed type errors that arrive in subsequent batches. We
    /// accumulate the LATEST diagnostics for our URI, replacing earlier
    /// batches, and only return once no new message arrives for
    /// `DIAGNOSTIC_QUIET_MS` or the overall deadline expires.
    async fn check_code(
        &mut self,
        uri: &str,
        language_id: &str,
        code: &str,
    ) -> Vec<LspDiagnostic> {
        tracing::info!(
            target: "lsp_gate",
            uri = %uri,
            code_len = code.len(),
            "check_code: didOpen"
        );
        eprintln!(
            "[LSP-GATE] check_code start: uri={} code_len={}",
            uri, code.len()
        );

        // 1. didOpen — declare file open in client, set initial text.
        // For workspace files already tracked by rust-analyzer, didOpen with
        // the new text is what makes the in-memory state authoritative. We
        // intentionally do NOT send didChange after didOpen: rust-analyzer
        // rejects didChange for files it considers "closed in the client"
        // (workspace files that the client never explicitly opened before),
        // logging "unexpected DidChangeTextDocument" and discarding both
        // the didChange AND any preceding didOpen content.
        self.send_notification(
            "textDocument/didOpen",
            serde_json::json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": language_id,
                    "version": 1,
                    "text": code
                }
            }),
        )
        .await;

        // 3. Collect diagnostics with quiet period.
        // Track latest batch for our URI; previous batches are overwritten
        // (rust-analyzer sends full diagnostic state each time, not deltas).
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(DIAGNOSTIC_TIMEOUT_MS);
        let quiet = std::time::Duration::from_millis(DIAGNOSTIC_QUIET_MS);
        let mut latest_diags: Vec<LspDiagnostic> = Vec::new();
        let mut last_batch_at = tokio::time::Instant::now();
        let mut received_any_batch = false;

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            // Settle once a quiet period has elapsed AFTER the first batch.
            // Empty batches also count — they signal "file is clean" from
            // rust-analyzer (e.g., the type-check pass found nothing).
            if received_any_batch && now.duration_since(last_batch_at) >= quiet {
                break;
            }

            // Wait up to the earlier of (remaining deadline, quiet period).
            let remaining_to_deadline = deadline.saturating_duration_since(now);
            let wait = remaining_to_deadline.min(quiet);

            let msg = match tokio::time::timeout(wait, self.read_message()).await {
                Ok(Some(msg)) => msg,
                _ => {
                    // Timeout with no new message this iteration. The loop
                    // will re-check the settle condition above and break
                    // out if the quiet period has elapsed since the last
                    // batch.
                    continue;
                }
            };

            // DEBUG: log every incoming message.
            let method = msg
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("<response>");
            let diag_uri_dbg = msg
                .get("params")
                .and_then(|p| p.get("uri"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            eprintln!(
                "[LSP-GATE] recv method={} uri={} has_id={}",
                method,
                diag_uri_dbg,
                msg.get("id").is_some()
            );

            // Handle server-to-client requests (workspace/configuration etc.)
            // before filtering — unanswered requests cause rust-analyzer to
            // fall back to default config (no experimental diagnostics).
            if msg.get("id").is_some() && msg.get("method").is_some() {
                self.handle_server_request(&msg).await;
                continue;
            }

            // Check for publishDiagnostics.
            if msg.get("method").and_then(|v| v.as_str())
                == Some("textDocument/publishDiagnostics")
            {
                let params = match msg.get("params") {
                    Some(p) => p,
                    None => continue,
                };

                let diag_uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Normalize URIs for case-insensitive comparison. LSP
                // servers on Windows normalize the drive letter to lowercase
                // (e.g. `file:///c:/Users/...`) while we construct URIs with
                // the uppercase drive letter from `to_string_lossy()`. A
                // direct string compare would discard every diagnostic.
                // We lowercase both sides — `file:///` prefix is already
                // lowercase, and Windows paths are case-insensitive.
                if uri_eq(diag_uri, uri) {
                    // Replace latest — each batch is full state, not delta.
                    latest_diags.clear();
                    let mut total_diags = 0;
                    if let Some(diags) = params.get("diagnostics").and_then(|v| v.as_array()) {
                        total_diags = diags.len();
                        for d in diags {
                            if let Some(parsed) = LspDiagnostic::from_json(d) {
                                latest_diags.push(parsed);
                            }
                        }
                    }
                    eprintln!(
                        "[LSP-GATE] received batch: diag_count={} version={:?}",
                        total_diags,
                        params.get("version").and_then(|v| v.as_u64())
                    );
                    last_batch_at = tokio::time::Instant::now();
                    received_any_batch = true;
                }
            }
        }

        // 4. Close the document to free rust-analyzer resources.
        self.send_notification(
            "textDocument/didClose",
            serde_json::json!({ "textDocument": { "uri": uri } }),
        )
        .await;

        tracing::info!(
            target: "lsp_gate",
            uri = %uri,
            batches = received_any_batch,
            diag_count = latest_diags.len(),
            "check_code: settled"
        );
        eprintln!(
            "[LSP-GATE] check_code settled: batches={} diag_count={} messages_sample={:?}",
            received_any_batch,
            latest_diags.len(),
            latest_diags.iter().take(3).map(|d| d.message.clone()).collect::<Vec<_>>()
        );

        latest_diags
    }

    /// Write a JSON-RPC message with Content-Length header.
    async fn write_message(&mut self, msg: &serde_json::Value) -> std::io::Result<()> {
        let body = serde_json::to_string(msg)?;
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        self.stdin.write_all(header.as_bytes()).await?;
        self.stdin.write_all(body.as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Read a single JSON-RPC message (Content-Length framed).
    async fn read_message(&mut self) -> Option<serde_json::Value> {
        let mut content_length = None;

        // Read headers.
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).await.ok()?;
            if n == 0 {
                return None; // EOF
            }

            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break; // End of headers.
            }

            if let Some(len_str) = trimmed.strip_prefix("Content-Length: ") {
                content_length = trimmed["Content-Length: ".len()..].trim().parse::<usize>().ok();
            }
        }

        let len = content_length?;

        // Read body.
        let mut body = vec![0u8; len];
        self.stdout.read_exact(&mut body).await.ok()?;
        serde_json::from_slice(&body).ok()
    }
}

/// A single LSP diagnostic, filtered to hallucination-relevant info.
#[derive(Debug, Clone)]
struct LspDiagnostic {
    message: String,
    severity: u8, // 1=Error, 2=Warning, ...
}

impl LspDiagnostic {
    fn from_json(d: &serde_json::Value) -> Option<Self> {
        let message = d.get("message")?.as_str()?.to_string();
        let severity = d.get("severity").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        Some(LspDiagnostic { message, severity })
    }

    fn is_error(&self) -> bool {
        self.severity == 1
    }
}

/// Extract backtick-quoted symbol names from a string.
/// FORGE warnings: "hallucinated-variable: `Bytes` — referenced..."
/// LSP messages: "unresolved import `bytes`", "cannot find type `Bytes`"
pub fn extract_backtick_symbols(text: &str) -> HashSet<String> {
    let mut symbols = HashSet::new();
    let mut in_backtick = false;
    let mut current = String::new();

    for ch in text.chars() {
        if ch == '`' {
            if in_backtick {
                if !current.is_empty() {
                    symbols.insert(current.clone());
                }
                current.clear();
            }
            in_backtick = !in_backtick;
        } else if in_backtick {
            current.push(ch);
        }
    }

    symbols
}

/// Case-insensitive URI comparison for `publishDiagnostics` matching.
///
/// On Windows, LSP servers normalize the drive letter in `file://` URIs to
/// lowercase (`file:///c:/Users/...`) while client-side URI construction
/// typically uses the OS-provided uppercase drive letter
/// (`file:///C:/Users/...`). A direct string compare would silently discard
/// every diagnostic, causing the FP-gate to suppress ALL warnings as false
/// positives (the canonical detached-file bug).
///
/// Per RFC 8089, the `file:` scheme and authority are case-insensitive; on
/// Windows the path is also case-insensitive (NTFS). We lowercase both sides
/// uniformly — `file:///` prefix is already lowercase and stays unchanged.
fn uri_eq(a: &str, b: &str) -> bool {
    a.to_ascii_lowercase() == b.to_ascii_lowercase()
}

/// Get or start the LSP client for a project root + language.
/// Dispatches to rust-analyzer (Rust) or gopls (Go) via the process-wide
/// `LspRegistry` (FOUND-006: replaces per-language OnceCell statics).
///
/// The registry keys clients by (workspace_root, language) so multi-workspace
/// scans get isolated clients (one rust-analyzer per Cargo workspace) while
/// the same workspace reuses its client across scans. Caps at 8 clients
/// process-wide; idle clients reaped after 5 min (FOUND-007).
async fn get_client(language: &str, project_root: &Path) -> Option<Arc<Mutex<LspState>>> {
    let lang = match language {
        "rust" => Language::Rust,
        "go" => Language::Go,
        _ => return None,
    };
    let (binary, version_arg): (&str, &str) = match language {
        "rust" => ("rust-analyzer", "--version"),
        "go" => ("gopls", "version"),
        _ => return None,
    };
    let root_str = project_root.to_string_lossy().to_string();
    let workspace = project_root.to_path_buf();

    let registry = crate::scanner::lsp_registry::global_registry();
    let arc = registry
        .get_or_spawn(workspace, lang, || {
            let root_str = root_str.clone();
            let project_root = project_root.to_path_buf();
            let binary = binary.to_string();
            let version_arg = version_arg.to_string();
            let language = language.to_string();
            async move {
                // Check if the LSP server is on PATH before spawning.
                let mut check = crate::scanner::command_hidden_tokio(&binary);
                check
                    .arg(&version_arg)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                match check.status().await {
                    Ok(s) if s.success() => {}
                    Ok(_) => {
                        tracing::info!(
                            target: "lsp_gate",
                            "{} {} check failed — LSP gate disabled for {}",
                            binary,
                            version_arg,
                            language,
                        );
                        return LspState::empty();
                    }
                    Err(_) => {
                        tracing::info!(
                            target: "lsp_gate",
                            "{} not found on PATH — LSP gate disabled for {}",
                            binary,
                            language,
                        );
                        return LspState::empty();
                    }
                }

                match LspClient::start(&binary, &project_root).await {
                    Some(client) => {
                        tracing::info!(
                            target: "lsp_gate",
                            "{} started for {:?}",
                            binary,
                            project_root,
                        );
                        LspState {
                            client: Some(client),
                            root: root_str,
                            last_used: std::time::Instant::now(),
                        }
                    }
                    None => {
                        tracing::warn!(
                            target: "lsp_gate",
                            "{} failed to start — LSP gate disabled for {}",
                            binary,
                            language,
                        );
                        LspState::empty()
                    }
                }
            }
        })
        .await;

    // If the cached client was spawned for a different project root
    // (e.g. workspace got renamed), restart it. Registry key is the
    // workspace path so this is rare but possible if the same key was
    // reused after a directory move.
    {
        let mut guard = arc.lock().await;
        if guard.root != root_str {
            if !guard.root.is_empty() {
                tracing::info!(
                    target: "lsp_gate",
                    "project root changed — restarting {}",
                    binary,
                );
            }
            guard.client = LspClient::start(binary, project_root).await;
            guard.root = root_str;
            guard.touch();
        }
    }

    Some(arc)
}

/// Ensure the warm probe module exists in the user's project.
///
/// Creates `src/anubis_probe.rs` (empty) if missing, and adds
/// `pub mod anubis_probe;` to `src/lib.rs` if not already present.
/// This is idempotent — safe to call on every scan.
///
/// The probe module is a LEAF module: nothing depends on it, so
/// rust-analyzer only re-analyzes this one file on didChange (<500ms),
/// not the entire crate graph (20-35s).
///
/// For non-Rust languages this is a no-op (Python/TS/Go don't need
/// module declarations).
fn ensure_probe_module(project_root: &Path) {
    // Only create probe module if this is a real Rust project (has Cargo.toml).
    // Bare tempdirs / benchmark skeletons without Cargo.toml → skip (compiler
    // gate handles those cases without LSP).
    if !project_root.join("Cargo.toml").exists() {
        return;
    }
    let src_dir = project_root.join("src");
    let _ = std::fs::create_dir_all(&src_dir);

    let probe_file = src_dir.join("anubis_probe.rs");
    if !probe_file.exists() {
        let _ = std::fs::write(&probe_file, "");
        tracing::info!(
            target: "lsp_gate",
            path = %probe_file.display(),
            "created warm probe module (leaf module for incremental LSP analysis)"
        );
    }

    // Add `pub mod anubis_probe;` to lib.rs if not already present.
    let lib_rs = src_dir.join("lib.rs");
    if lib_rs.exists() {
        if let Ok(content) = std::fs::read_to_string(&lib_rs) {
            if !content.contains("anubis_probe") {
                let updated = if content.is_empty() {
                    "pub mod anubis_probe;\n".to_string()
                } else {
                    format!("{}pub mod anubis_probe;\n", content)
                };
                let _ = std::fs::write(&lib_rs, updated);
                tracing::info!(
                    target: "lsp_gate",
                    "added 'pub mod anubis_probe;' to lib.rs"
                );
            }
        }
    }
}

/// Suppress FORGE false positives using LSP as negative oracle.
///
/// For each FORGE warning: if the LSP server does NOT report the same symbol
/// as unresolved, the warning is a false positive and is suppressed.
///
/// Returns the filtered warning list. If LSP is unavailable or cold-starting,
/// returns warnings unchanged (safe default — don't filter).
pub async fn suppress_fps(
    warnings: Vec<String>,
    code: &str,
    language: &str,
    project_root: &Path,
) -> Vec<String> {
    if warnings.is_empty() {
        return warnings;
    }

    // Kill switch for benchmark/offline runs: the spawned LSP client's
    // shutdown can deadlock (rust-analyzer "client exited without proper
    // shutdown sequence") hanging the whole scan process. Presence of this
    // env var (any value) skips the gate entirely - same safe default as
    // an unavailable LSP.
    if std::env::var("ANUBIS_DISABLE_LSP_GATE").is_ok() {
        return warnings;
    }

    // Only Rust and Go have LSP FP gates (best project context).
    if language != "rust" && language != "go" {
        return warnings;
    }

    // Get or start LSP client for this language.
    let cell = match get_client(language, project_root).await {
        Some(c) => c,
        None => return warnings,
    };

    let mut guard = cell.lock().await;
    let client = match guard.client.as_mut() {
        Some(c) => c,
        None => return warnings, // LSP unavailable
    };

    // Write code to a virtual URI in the project workspace so the LSP has
    // full project context (Cargo.toml deps / go.mod imports).
    //
    // ── Warm module slot: use a LEAF module (anubis_probe.rs) instead of ──
    // the crate root (lib.rs). rust-analyzer only re-analyzes the changed
    // module + its direct dependents. Since anubis_probe is a leaf (nothing
    // depends on it), re-analysis is <500ms instead of 20-35s full re-index.
    //
    // The probe module is created ONCE (at LSP spawn, see ensure_probe_module)
    // and stays for the daemon's lifetime. Per-scan: write probe code →
    // didChange → get diagnostics → restore empty.
    let probe_path = if language == "rust" {
        let probe = project_root.join("src").join("anubis_probe.rs");
        // Ensure the module exists + mod declaration in lib.rs.
        ensure_probe_module(project_root);
        probe
    } else {
        let ext = if language == "go" { "go" } else { "rs" };
        let _ = std::fs::create_dir_all(project_root);
        project_root.join(format!("anubis_lsp_check.{}", ext))
    };
    let temp_path = probe_path;
    let uri = format!(
        "file:///{}",
        temp_path.to_string_lossy().replace('\\', "/")
    );

    tracing::info!(
        target: "lsp_gate",
        temp_path = %temp_path.display(),
        uri = %uri,
        on_disk_exists = temp_path.exists(),
        "LSP FP gate chose probe path"
    );
    eprintln!(
        "[LSP-GATE] temp_path={} uri={} on_disk={}",
        temp_path.display(),
        uri,
        temp_path.exists()
    );

    // Write probe code to the warm probe module file. Since anubis_probe.rs
    // is OUR file (starts empty), no backup needed. Just write probe code,
    // get diagnostics, restore empty.
    let _probe_guard = if language == "rust" {
        // Write probe code to anubis_probe.rs on disk.
        match std::fs::write(&temp_path, code.as_bytes()) {
            Ok(_) => {
                tracing::debug!(
                    target: "lsp_gate",
                    path = %temp_path.display(),
                    probe_len = code.len(),
                    "probe code written to warm module slot"
                );
                Some(temp_path.clone())
            }
            Err(e) => {
                tracing::warn!(
                    target: "lsp_gate",
                    path = %temp_path.display(),
                    err = %e,
                    "failed to write probe code — falling back to didChange only"
                );
                None
            }
        }
    } else {
        None
    };

    // Wrap check_code in an overall timeout. The LSP gate is a false-positive
    // SUPPRESSOR — its only failure mode is suppressing too little (returning
    // warnings unchanged). On timeout we keep the safe default: don't filter.
    //
    // Production proxy cannot tolerate 20-35s blocks per response; benchmarks
    // override via LSP_GATE_TIMEOUT_MS (e.g. 30000) for thorough scanning.
    let lsp_timeout_ms = std::env::var("LSP_GATE_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3000);

    let lsp_result = tokio::time::timeout(
        std::time::Duration::from_millis(lsp_timeout_ms),
        client.check_code(&uri, language, code),
    )
    .await;

    let diagnostics = match lsp_result {
        Ok(diags) => diags,
        Err(_) => {
            tracing::warn!(
                target: "lsp_gate",
                timeout_ms = lsp_timeout_ms,
                uri = %uri,
                "LSP gate timed out — skipping (safe default: no filtering)"
            );
            eprintln!(
                "[LSP-GATE] TIMEOUT after {}ms — restoring probe file and skipping gate",
                lsp_timeout_ms
            );
            // CRITICAL: restore probe file to empty even on timeout.
            // anubis_probe.rs is OUR file — restore to empty (not user content).
            if let Some(probe_path) = &_probe_guard {
                let _ = std::fs::write(probe_path, "");
            }
            return warnings;
        }
    };

    // Restore probe file to empty after successful diagnostics.
    if let Some(probe_path) = &_probe_guard {
        let _ = std::fs::write(probe_path, "");
    }

    // Extract symbols that rust-analyzer could NOT resolve (Error severity).
    let unresolved: HashSet<String> = diagnostics
        .iter()
        .filter(|d| d.is_error())
        .flat_map(|d| extract_backtick_symbols(&d.message))
        .collect();

    tracing::info!(
        target: "lsp_gate",
        warnings_in = warnings.len(),
        lsp_errors = diagnostics.iter().filter(|d| d.is_error()).count(),
        unresolved_symbols = ?unresolved,
        "LSP FP gate checking warnings"
    );

    // Suppress warnings where the symbol IS resolved by rust-analyzer
    // (symbol NOT in the unresolved set).
    let mut suppressed = 0;
    let filtered: Vec<String> = warnings
        .into_iter()
        .filter(|w| {
            let symbols = extract_backtick_symbols(w);
            if symbols.is_empty() {
                return true; // Can't extract symbol — keep warning.
            }

            // If ANY symbol in the warning is unresolved per LSP, keep it.
            let any_unresolved = symbols.iter().any(|s| unresolved.contains(s));

            if !any_unresolved {
                // LSP resolved all symbols in this warning → suppress FP.
                suppressed += 1;
                tracing::debug!(
                    target: "lsp_gate",
                    warning = %w,
                    "SUPPRESSED FP — LSP resolved symbol"
                );
                false
            } else {
                true
            }
        })
        .collect();

    tracing::info!(
        target: "lsp_gate",
        warnings_in = filtered.len() + suppressed,
        suppressed = suppressed,
        warnings_out = filtered.len(),
        "LSP FP gate complete"
    );

    filtered
}
