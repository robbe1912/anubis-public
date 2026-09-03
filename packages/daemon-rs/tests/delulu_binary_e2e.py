"""
End-to-end DELULU test against the BUILT anubis-daemon binary.

Spins up a mock OpenAI upstream returning DELULU hallucinated content,
starts the real anubis-daemon binary pointing at it, sends requests
through the proxy, and verifies warning injection.

Usage:
    python tests\delulu_binary_e2e.py
    python tests\delulu_binary_e2e.py --binary target\release\anubis-daemon.exe
    python tests\delulu_binary_e2e.py --samples 5
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Force UTF-8 output — daemon stderr contains box-drawing chars (→, etc.)
# that crash cp1252 codec on Windows.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


REPO_ROOT = Path(__file__).resolve().parents[3]
DAEMON_DIR = REPO_ROOT / "packages" / "daemon-rs"
DEFAULT_BINARY = DAEMON_DIR / "target" / "release" / "anubis-daemon.exe"
DELULU_FIXTURE = DAEMON_DIR / "tests" / "fixtures" / "delulu_subset.jsonl"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def load_delulu_samples(limit: int | None = None) -> list[dict]:
    if not DELULU_FIXTURE.exists():
        raise SystemExit(f"DELULU fixture not found: {DELULU_FIXTURE}")
    samples = []
    with DELULU_FIXTURE.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit:
        samples = samples[:limit]
    return samples


class MockUpstreamHandler(BaseHTTPRequestHandler):
    """Returns canned OpenAI-format responses with DELULU hallucinated content."""

    samples: list[dict] = []  # set by main thread
    current_index = 0
    lock = threading.Lock()

    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def do_POST(self):
        # Read request body to determine if streaming requested
        content_length = int(self.headers.get("Content-Length", 0))
        request_body_raw = self.rfile.read(content_length) if content_length else b""
        is_stream = False
        try:
            req = json.loads(request_body_raw)
            is_stream = bool(req.get("stream", False))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Pick next sample (round-robin)
        with MockUpstreamHandler.lock:
            sample = MockUpstreamHandler.samples[
                MockUpstreamHandler.current_index % len(MockUpstreamHandler.samples)
            ]
            MockUpstreamHandler.current_index += 1

        content = sample.get("hallucinated_completion", "")
        prompt = sample.get("prompt", "") or ""
        suffix = sample.get("suffix", "") or ""
        full_content = f"{prompt}{content}{suffix}"

        if is_stream:
            # SSE streaming response — emit content as delta chunks then [DONE].
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            # First chunk: role announcement
            first_chunk = {
                "id": f"chatcmpl-mock-{MockUpstreamHandler.current_index}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": "gpt-4-mock",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": ""},
                        "finish_reason": None,
                    }
                ],
            }
            self.wfile.write(f"data: {json.dumps(first_chunk)}\n\n".encode("utf-8"))
            self.wfile.flush()

            # Content delta — split into ~50-char chunks to mimic real streaming
            chunk_size = 50
            for i in range(0, len(full_content), chunk_size):
                piece = full_content[i : i + chunk_size]
                delta = {
                    "id": f"chatcmpl-mock-{MockUpstreamHandler.current_index}",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": "gpt-4-mock",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": piece},
                            "finish_reason": None,
                        }
                    ],
                }
                self.wfile.write(f"data: {json.dumps(delta)}\n\n".encode("utf-8"))
                self.wfile.flush()

            # Final chunk: finish_reason
            final = {
                "id": f"chatcmpl-mock-{MockUpstreamHandler.current_index}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": "gpt-4-mock",
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "stop",
                    }
                ],
            }
            self.wfile.write(f"data: {json.dumps(final)}\n\n".encode("utf-8"))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            return

        # Non-streaming: OpenAI Chat Completions response format
        response_body = {
            "id": f"chatcmpl-mock-{MockUpstreamHandler.current_index}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gpt-4-mock",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": full_content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 50, "total_tokens": 60},
        }
        body_str = json.dumps(response_body)
        body_bytes = body_str.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


def start_mock_upstream(port: int, samples: list[dict]) -> HTTPServer:
    MockUpstreamHandler.samples = samples
    server = HTTPServer(("127.0.0.1", port), MockUpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def write_test_config(home_dir: Path, upstream_url: str, daemon_port: int):
    """Write a config that routes daemon to our mock upstream."""
    anubis_dir = home_dir / ".anubis"
    anubis_dir.mkdir(parents=True, exist_ok=True)

    # Minimal config — Custom routing mode pointing at mock upstream.
    config = {
        "proxy": {"host": "127.0.0.1", "port": daemon_port},
        "routing": {"mode": "Custom", "custom_url": upstream_url},
        "scanner": {"model": "glm-4.7", "base_url": "", "api_key": ""},
    }
    config_path = anubis_dir / "config.yaml"
    # serde_yaml accepts TOML-ish via serde_yaml::from_str — actually it's YAML.
    # Looking at config.rs: serde_yaml::from_str. So write YAML.
    config_yaml = (
        f"proxy:\n"
        f"  host: 127.0.0.1\n"
        f"  port: {daemon_port}\n"
        f"routing:\n"
        f"  mode: custom\n"
        f"  custom_url: {upstream_url}\n"
        f"scanner:\n"
        f"  model: glm-4.7\n"
        f"  base_url: ''\n"
        f"  api_key: ''\n"
    )
    config_path.write_text(config_yaml)
    return config_path


def wait_for_daemon(port: int, timeout: float = 30.0) -> bool:
    """Poll /__anubis/ping until daemon responds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/__anubis/ping", timeout=2
            ) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def send_request_through_proxy(
    proxy_port: int, content: str, stream: bool = True
) -> tuple[int, str]:
    """Send a chat-completion request through the daemon. Returns (status, content).
    For streaming: uses raw socket and reads until [DONE] marker, accumulating
    delta content + any synthetic warning chunks the daemon injects.
    """
    request_body = {
        "model": "gpt-4-mock",
        "messages": [{"role": "user", "content": content}],
        "stream": stream,
    }
    body_str = json.dumps(request_body)
    body_bytes = body_str.encode("utf-8")
    request_line = (
        f"POST /v1/chat/completions HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{proxy_port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Authorization: Bearer test-mock-key\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")

    # Raw socket — daemon holds the stream open during scan, so we need
    # to read until [DONE] marker appears (or connection closes).
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(120)  # generous timeout for FORGE scan completion
    sock.connect(("127.0.0.1", proxy_port))
    sock.sendall(request_line + body_bytes)

    # Read response — accumulate all bytes.
    raw = b""
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            raw += chunk
            # Stop early if we see [DONE] (daemon emits it last).
            if b"data: [DONE]" in raw:
                break
    finally:
        sock.close()

    # Parse the response — split headers and body.
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        return 0, raw.decode("utf-8", errors="replace")
    headers_raw = raw[:header_end].decode("iso-8859-1")
    body_raw = raw[header_end + 4 :]

    # Status line
    status_line = headers_raw.split("\r\n", 1)[0]
    try:
        status = int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError):
        status = 0

    body_str = body_raw.decode("utf-8", errors="replace")

    if not stream:
        # Non-streaming JSON response
        try:
            parsed = json.loads(body_str)
            return status, (
                parsed.get("choices", [{}])[0].get("message", {}).get("content", "")
            )
        except json.JSONDecodeError:
            return status, body_str

    # Streaming: walk SSE events, accumulate delta.content
    collected = []
    for line in body_str.split("\n"):
        line = line.strip()
        if not line.startswith("data: "):
            continue
        payload = line[6:]
        if payload == "[DONE]":
            continue
        try:
            evt = json.loads(payload)
        except json.JSONDecodeError:
            continue
        choices = evt.get("choices", [])
        if not choices:
            continue
        delta = choices[0].get("delta", {})
        if "content" in delta and delta["content"]:
            collected.append(delta["content"])

    return status, "".join(collected)


def run_test(
    binary: Path,
    samples: list[dict],
    verbose: bool = False,
) -> tuple[int, int, list[str]]:
    """Returns (success_count, total_count, failure_ids)."""
    upstream_port = find_free_port()
    daemon_port = find_free_port()
    upstream_url = f"http://127.0.0.1:{upstream_port}"

    # Start mock upstream
    upstream_server = start_mock_upstream(upstream_port, samples)
    print(f"[setup] Mock upstream on {upstream_url}")

    # Set up isolated home dir so we don't touch user's real config
    tmp_home = Path(tempfile.mkdtemp(prefix="anubis_test_"))
    config_path = write_test_config(tmp_home, upstream_url, daemon_port)
    print(f"[setup] Test home: {tmp_home}")
    print(f"[setup] Config: {config_path}")

    # Copy user's symbol cache so FORGE works (the cache is required for
    # detection — without it, samples won't get flagged)
    real_home = Path(os.environ.get("USERPROFILE", "")) / ".anubis"
    test_anubis = tmp_home / ".anubis"

    # Link license-meta.json, symbols/, docs/ from real home — needed for
    # license validation (tier state file) + symbol cache (FORGE detection).
    # Don't link config.yaml (we write our own) or proxy.jsonl (audit log).
    for item_name in ["license-meta.json", "symbols", "docs", "audit.db", "stats.db"]:
        src = real_home / item_name
        if src.exists():
            dst = test_anubis / item_name
            try:
                os.symlink(src, dst)
                print(f"[setup] Symlinked {item_name} from {src}")
            except OSError:
                if src.is_file():
                    shutil.copy2(src, dst)
                else:
                    shutil.copytree(src, dst)
                print(f"[setup] Copied {item_name} from {src}")
    if not (test_anubis / "license-meta.json").exists():
        print(f"[warn] No license-meta.json at {real_home} — daemon may refuse to start")
    if not (test_anubis / "symbols").exists():
        print(f"[warn] No symbol cache at {real_home} — FORGE detection will fail")

    # Start daemon binary with isolated home
    env = os.environ.copy()
    env["USERPROFILE"] = str(tmp_home)
    env["RUST_LOG"] = os.environ.get("ANUBIS_TEST_LOG", "info,scanner=debug,proxy=debug")

    daemon_proc = subprocess.Popen(
        [str(binary)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )

    # Start a thread to drain daemon output to a log file (so it doesn't
    # block on a full pipe).
    daemon_log_path = Path(tempfile.gettempdir()) / "anubis_test_daemon.log"
    daemon_log_path.unlink(missing_ok=True)
    def drain_to_log():
        with daemon_log_path.open("wb") as f:
            while True:
                byte = daemon_proc.stdout.read(1)
                if not byte:
                    break
                f.write(byte)
                f.flush()
    drain_thread = threading.Thread(target=drain_to_log, daemon=True)
    drain_thread.start()

    success_count = 0
    failure_ids = []

    try:
        # Wait for daemon to come up
        if not wait_for_daemon(daemon_port, timeout=15):
            print(f"[FAIL] Daemon didn't start. Daemon log:")
            if daemon_log_path.exists():
                log_text = daemon_log_path.read_text(encoding="utf-8", errors="replace")
                print(log_text[-2000:])
            return 0, len(samples), [s.get("benchmark_id", "?") for s in samples]

        # Read version
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon_port}/__anubis/ping", timeout=5
            ) as r:
                ping = json.loads(r.read())
                print(f"[setup] Daemon v{ping.get('version', '?')} on port {daemon_port}")
        except Exception as e:
            print(f"[warn] Couldn't read version: {e}")

        # Send each sample through the proxy
        # We need to send one request per sample and check the response for
        # injected warning footer. The mock upstream returns the hallucinated
        # content; daemon scans it and appends warning to choices[0].message.content.
        print(f"\n[run] Sending {len(samples)} samples through daemon proxy...\n")

        for i, sample in enumerate(samples, 1):
            sid = sample.get("benchmark_id", f"sample_{i}")
            lang = sample.get("language", "?")
            htype = sample.get("hallucination_type", "?")
            h_completion = sample.get("hallucinated_completion", "")

            # The mock upstream is round-robin — we need to ensure it returns
            # THIS sample's content. Restart the counter to match.
            with MockUpstreamHandler.lock:
                MockUpstreamHandler.current_index = i - 1

            status, content = send_request_through_proxy(
                daemon_port, f"Detect hallucination in this code: {h_completion}", stream=True
            )

            # Check daemon stats to see if request was processed
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{daemon_port}/__anubis/stats", timeout=5
                ) as sr:
                    stats = json.loads(sr.read())
                    total_reqs = stats.get("total_requests", "?")
                    scans_run = stats.get("scans", {}).get("total", "?")
                    if i == 1 or verbose:
                        print(f"    [stats] requests={total_reqs} scans={scans_run}")
            except Exception as e:
                if verbose:
                    print(f"    [stats] failed: {e}")

            if status != 200:
                print(f"  [{i:3d}/{len(samples)}] {sid:50s} HTTP {status} — FAIL")
                failure_ids.append(sid)
                continue

            # Check if a warning was injected. Daemon appends to content
            # (footer for non-streaming, synthetic SSE chunk for streaming).
            # Look for typical FORGE warning markers.
            warning_markers = [
                "hallucinated-",
                "did you mean",
                "not found in",
                "not a known",
                "not in module",
                "not in any cached",
                "bare-critical-call",
                "anubis",
                "⚠️",
            ]
            content_lower = content.lower()
            has_warning = any(marker.lower() in content_lower for marker in warning_markers)
            content_arrived = len(content) > 0

            if has_warning:
                success_count += 1
                marker = "PASS"
                if verbose:
                    # Show first matching warning substring
                    for m in warning_markers:
                        idx = content_lower.find(m.lower())
                        if idx >= 0:
                            snippet = content[max(0, idx - 10) : idx + 120]
                            print(f"    warning: ...{snippet}...")
                            break
            elif content_arrived:
                marker = "MISS"
                if verbose:
                    print(f"    content (last 200 chars): ...{content[-200:]}")
            else:
                marker = "EMPTY"
                failure_ids.append(sid)

            print(f"  [{i:3d}/{len(samples)}] {sid:50s} [{lang:6s}/{htype:18s}] {marker}")

    finally:
        # Cleanup
        daemon_proc.terminate()
        try:
            daemon_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon_proc.kill()
        upstream_server.shutdown()

        # Preserve test home if ANUBIS_TEST_PRESERVE=1 (useful for debugging
        # scanner state, audit logs, etc.). Otherwise clean up on success.
        preserve = os.environ.get("ANUBIS_TEST_PRESERVE", "0") == "1"
        if preserve or (success_count == 0 and not failure_ids):
            print(f"[debug] Preserving test home: {tmp_home}")
        else:
            try:
                shutil.rmtree(tmp_home, ignore_errors=True)
            except Exception:
                pass

    return success_count, len(samples), failure_ids


def main():
    parser = argparse.ArgumentParser(description="DELULU end-to-end test against built binary")
    parser.add_argument(
        "--binary",
        type=Path,
        default=DEFAULT_BINARY,
        help=f"Path to anubis-daemon binary (default: {DEFAULT_BINARY})",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=10,
        help="Number of DELULU samples to test (default: 10)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show warning text on each PASS",
    )
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"ERROR: Binary not found at {args.binary}")
        print("Build it first: cd packages\\daemon-rs && cargo build --release --bins")
        sys.exit(1)

    print(f"Binary: {args.binary}")
    print(f"DELULU fixture: {DELULU_FIXTURE}")

    samples = load_delulu_samples(limit=args.samples)
    print(f"Loaded {len(samples)} samples")

    success, total, failures = run_test(args.binary, samples, verbose=args.verbose)

    print(f"\n{'=' * 70}")
    print(f"DELULU Binary E2E Results")
    print(f"{'=' * 70}")
    print(f"Samples with warning injected: {success}/{total} ({success*100//total if total else 0}%)")
    if failures:
        print(f"Failures (no content arrived):")
        for fid in failures:
            print(f"  {fid}")
    print(f"{'=' * 70}")

    # Exit code: 0 if any sample got flagged (proves pipeline works)
    if success == 0:
        print("\nFAIL: No warnings injected. Either:")
        print("  - Symbol cache missing (run 'anubis symbols sync')")
        print("  - Daemon binary broken")
        print("  - Mock upstream didn't return expected content")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
