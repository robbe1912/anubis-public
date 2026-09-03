#!/usr/bin/env python3
"""
Focused Rust type + method fetcher.

Downloads crate source from crates.io, parses for the requested types only
(plus their pub fn methods inside impl blocks), and emits JSONL entries in
the symbol_bundle.jsonl schema:

  {"library": "rust.<crate>", "version": "bundled", "path": "TypeName", ...}
  {"library": "rust.<crate>", "version": "bundled", "path": "TypeName.method", ...}

Usage:
  python fetch_rust_types.py --target crates_and_types.json --output extra.jsonl
  python fetch_rust_types.py --crates tokio chrono --output extra.jsonl
        (without --types, fetches ALL types from each crate — large)

The merge step (appending extra.jsonl onto symbol_bundle.jsonl) is left to
the caller — this script only emits entries for requested (crate, type) pairs.
"""

import argparse
import io
import json
import re
import sys
import tarfile
import urllib.request
from collections import defaultdict


CRATES_IO_UA = "anubis-symbol-bundle-fetcher/1.0"


def fetch_latest_version(crate_name: str) -> str:
    req = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate_name}",
        headers={"User-Agent": CRATES_IO_UA},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read())
    return data["crate"]["max_stable_version"]


def fetch_source_tarball(crate_name: str, version: str) -> bytes:
    url = f"https://crates.io/api/v1/crates/{crate_name}/{version}/download"
    req = urllib.request.Request(url, headers={"User-Agent": CRATES_IO_UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def read_all_rust_source(tar_data: bytes) -> str:
    """Concatenate every .rs file inside the tarball into one string."""
    chunks = []
    with tarfile.open(fileobj=io.BytesIO(tar_data)) as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith(".rs"):
                try:
                    chunks.append(
                        tar.extractfile(member).read().decode("utf-8", errors="replace")
                    )
                except Exception:
                    continue
    return "\n".join(chunks)


# Strip line comments (`// ...`) — safe: always terminate at end of line.
# Block comments (`/* ... */`) are tricky in Rust source because regex
# patterns or string literals may contain an unmatched `/*`, which makes a
# naive non-greedy `/\*.*?\*/` eat live code. To stay safe we only strip
# block comments that close on the SAME line — multi-line block comments in
# Rust source are extremely rare outside of generated code, and doc comments
# (`///`) are already handled by the line-comment stripper below.
_BLOCK_COMMENT_RE = re.compile(r"/\*[^\n]*?\*/")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def strip_comments(src: str) -> str:
    src = _BLOCK_COMMENT_RE.sub("", src)
    src = _LINE_COMMENT_RE.sub("", src)
    return src


# Match any type declaration, with or without `pub`. Captures `pub(crate)`,
# `pub(super)`, `pub(self)`, `pub`, and bare `struct`/`enum`/etc.
# Without `pub`, we still capture private/internal types because the corpus
# tests hallucinations on those (RawTask, Idle, IoDriverMetrics, ...).
#
# Use MULTILINE so `^` matches at every line start, and consume from line
# start through the type name. Also handles `pub type Name = ...;` aliases
# and generic / lifetime parameters after the name.
_TYPE_DECL_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub\s*(?:\((?:crate|super|self|in\s+[^\)]+)\)\s*)?)?"
    r"(?:struct|enum|trait|union|type)\s+([A-Z]\w*)",
    re.MULTILINE,
)

# Match the head of an impl block and capture the implementing type name.
#
# Handles:
#   impl Foo {                       -> Foo
#   impl<T> Foo {                    -> Foo
#   impl<T> Foo<T> {                 -> Foo
#   impl Foo<T> {                    -> Foo
#   impl crate::mod::Foo {           -> Foo
#   impl<T> crate::Foo<T> {          -> Foo
#   impl<T> crate::Foo<T> for Bar<T> {   -> Bar (the "for" type)
#   impl Trait for Foo {             -> Foo
_IMPL_HEAD_RE = re.compile(
    r"\bimpl\s+"
    r"(?:<[^>]*>\s+)?"            # optional generics <T>
    r"(?:[\w_]+(?:::[\w_<>, \t]+)*::)?"  # optional module path `mod::`
    r"(?P<self_ty>[A-Z]\w*)"       # the type itself
    r"(?:\s*<[^>]*>)?"             # optional generic args after type
    r"(?:\s+for\s+"
    r"(?:[\w_]+(?:::[\w_<>, \t]+)*::)?"
    r"(?P<for_ty>[A-Z]\w*)"
    r"(?:\s*<[^>]*>)?"
    r")?"
)


def find_impl_block_end(src: str, open_brace_idx: int, hard_cap: int = 80000) -> int:
    """Return index of the matching closing brace for the brace at open_brace_idx."""
    depth = 0
    end = min(open_brace_idx + hard_cap, len(src))
    for i in range(open_brace_idx, end):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


# Inside an impl body, extract pub fn declarations.
# Matches `pub fn`, `pub async fn`, `pub const fn`, `pub(crate) fn`, etc.
_PUB_FN_RE = re.compile(
    r"\bpub\s+(?:\(crate\)\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+([a-z_]\w*)"
)

# For trait impls (`impl Trait for Foo`), the methods are not declared with
# `pub fn` — they're just `fn`. Capture those too so trait-impl methods show
# up under the implementing type.
_TRAIT_FN_RE = re.compile(
    r"\b(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+([a-z_]\w*)\s*\("
)


def parse_types_and_methods(src: str) -> dict:
    """Return {type_name: set_of_method_names} from the cleaned source."""
    src = strip_comments(src)
    types: dict = defaultdict(set)

    # 1. Type declarations (struct/enum/trait/union/type) — guarantees an entry
    #    exists even if no impl block follows.
    for m in _TYPE_DECL_RE.finditer(src):
        types[m.group(1)].add("__type_decl__")

    # 2. Walk every `impl ...` head and capture (a) the self type, and
    #    (b) the "for" type if present.
    for m in _IMPL_HEAD_RE.finditer(src):
        self_ty = m.group("self_ty")
        for_ty = m.group("for_ty")
        owner = for_ty if for_ty else self_ty
        # The opening brace is the next `{` after the match end.
        brace_idx = src.find("{", m.end())
        if brace_idx == -1:
            continue
        end_idx = find_impl_block_end(src, brace_idx)
        if end_idx == -1:
            continue
        body = src[brace_idx + 1:end_idx]

        # Prefer pub fn; for trait impls (no `pub`), fall back to plain `fn`.
        for fn_m in _PUB_FN_RE.finditer(body):
            name = fn_m.group(1)
            if not name.startswith("__"):
                types[owner].add(name)
        if for_ty:
            # Trait impl — methods are not `pub`. Capture them anyway so
            # `Foo` gets credit for the methods of the trait it implements.
            for fn_m in _TRAIT_FN_RE.finditer(body):
                name = fn_m.group(1)
                if name not in (
                    "if", "while", "for", "match", "let", "return", "loop",
                ) and not name.startswith("__"):
                    types[owner].add(name)

    # Drop the placeholder marker.
    for ty in list(types):
        types[ty].discard("__type_decl__")
    return types


# When a requested type isn't declared in the fetched crate source, fall
# back to a known alias type and clone its methods. Used for:
#   - anyhow::Report → Error (Report was added as alias for Error in
#     anyhow 1.0.86+; max_stable_version 1.0.104's source still uses Error).
ALIASES = {
    ("anyhow", "Report"): "Error",
}


def emit_jsonl(crate: str, types: dict, requested: set, out) -> dict:
    """Emit JSONL lines for requested types from a parsed crate. Returns stats."""
    extracted_at = 1785255905
    library = f"rust.{crate}"
    stats = {"types_emitted": 0, "methods_emitted": 0, "missing": []}

    for type_name in sorted(requested):
        methods = types.get(type_name)
        if methods is None:
            alias = ALIASES.get((crate, type_name))
            if alias and alias in types:
                methods = types[alias]
            if methods is None:
                stats["missing"].append(type_name)
                continue

        # Type entry.
        out.write(json.dumps({
            "library": library,
            "version": "bundled",
            "path": type_name,
            "name": type_name,
            "kind": "class",
            "signature": f"class {type_name}",
            "params_json": None,
            "return_type": None,
            "doc_text": None,
            "source_file": None,
            "visibility": "public",
            "is_deprecated": 0,
            "deprecated_message": None,
            "extracted_at": extracted_at,
        }, ensure_ascii=False) + "\n")
        stats["types_emitted"] += 1

        # Method entries.
        for method in sorted(methods):
            out.write(json.dumps({
                "library": library,
                "version": "bundled",
                "path": f"{type_name}.{method}",
                "name": method,
                "kind": "method",
                "signature": f"{method}()",
                "params_json": None,
                "return_type": None,
                "doc_text": None,
                "source_file": None,
                "visibility": "public",
                "is_deprecated": 0,
                "deprecated_message": None,
                "extracted_at": extracted_at,
            }, ensure_ascii=False) + "\n")
            stats["methods_emitted"] += 1

    return stats


# Crates whose types appear in delulu_v2_rust.jsonl, mapped to the specific
# types the corpus references. Sourced by parsing benchmark_id fields.
TARGETS = {
    "anyhow": {
        "Error", "NotBothDebug", "Point", "Report",
    },
    "chrono": {
        "Date", "DateTime", "Days", "FixedOffset", "IsoWeek", "LocalTimeType",
        "Mdf", "MilliSecondsTimestampVisitor", "NaiveDateTime", "NaiveTime",
        "NanoSecondsTimestampVisitor", "OffsetPrecision", "Parsed", "RuleDay",
        "SubsecRound", "TimeDelta", "TimeZone", "TimeZoneName", "TransitionRule",
        "TzDataIndexes", "TzInfo", "UtcDateTime", "Weekday", "WeekdaySet",
    },
    "rand": {
        "Alphabetic", "IndexedMutRandom", "OpenClosed01", "ReseedingCore",
        "StepRng", "UniformDuration", "UniformFloat",
    },
    "regex": {
        "Regex", "RegexBuilder", "RegexSet", "SetMatches",
    },
    "serde": {
        "AdjacentlyTaggedEnumVariantSeed", "ContentRefDeserializer", "DateTime",
        "Duration", "IgnoredAny", "InternallyTaggedUnitVisitor", "MapAccess",
        "MapAsEnum", "SeqDeserializer", "Serialize", "SerializeMap",
        "SerializeTupleVariantAsMapValue", "TagContentOtherFieldVisitor",
        "Timestamp",
    },
    "serde_json": {
        "AsPrimitive", "Entry", "Error", "ExtendedFloatArray", "IntoIter", "Map",
        "ModeratePathPowers", "Number", "NumberVisitor", "PrettyFormatter",
        "VacantEntry", "Value",
    },
    "tokio": {
        "AcquireError", "AssertDrop", "AsyncBufRead", "BacktraceFrame", "Barrier",
        "BiasedRotator", "BigNotify", "BlockingPool", "BlockingSchedule", "Buf",
        "Builder", "Child", "Command", "Config", "Context", "Core", "CtrlC",
        "CurrentThread", "DirEntry", "Direction", "Dump", "Error", "FastRand",
        "File", "Handle", "Header", "HistogramBatch", "HistogramConfiguration",
        "Idle", "Inner", "Instant", "Interval", "IoDriverMetrics", "JoinError",
        "Level", "LlFut", "LocalData", "LocalRuntime", "LocalSet", "LocalState",
        "LogHistogram", "MappedMutexGuard", "MetricAtomicU64", "MetricAtomicUsize",
        "MetricsBatch", "MissedTickBehavior", "MockWait", "NamedPipeClient",
        "NamedPipeServer", "NotDefinedHere", "Notified", "Notify", "OpenOptions",
        "Output", "OwnedReadHalf", "OwnedSemaphorePermit", "OwnedWriteHalf",
        "ParkThread", "Parker", "RawTask", "ReadDir", "ReadHalf", "ReadUntil",
        "Ready", "RegistrationSet", "Repeat", "ReuniteError", "RngSeedGenerator",
        "Runtime", "RwLockReadGuard", "ScheduledIo", "SchedulerMetrics",
        "Semaphore", "ServerOptions", "Shared", "SignalKind", "Sleep",
        "Snapshot", "SocketAddr", "SpawnLocation", "Spawner", "SpawnerMetrics",
        "State", "StaticAtomicU64", "Stats", "Task", "TcpSocket", "Timer",
        "TimerEntry", "TimerHandle", "TimerShared", "ToSocketAddrsPriv", "Trace",
        "Tree", "TryAcquireError", "TryCurrentError", "TryIoError",
        "UnixListener", "UnixStream", "VectoredWriteHarness", "WakeQueue",
        "WeakUnboundedSender", "Wheel", "Worker", "WriteHalf",
    },
    "uuid": {
        "Braced", "Builder", "Bytes", "ContextV7", "Hyphenated", "Precision",
        "Simple", "ThreadLocalContext", "Uuid",
    },
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True,
                    help="Output JSONL path (will be created/overwritten).")
    ap.add_argument("--crates", nargs="*", default=None,
                    help="Subset of crates to fetch (default: all in TARGETS).")
    args = ap.parse_args()

    targets = dict(TARGETS)
    if args.crates:
        unknown = set(args.crates) - set(targets)
        if unknown:
            print(f"ERROR: unknown crates: {sorted(unknown)}", file=sys.stderr)
            print(f"Valid: {sorted(targets)}", file=sys.stderr)
            sys.exit(2)
        targets = {k: v for k, v in targets.items() if k in set(args.crates)}

    grand_types = 0
    grand_methods = 0
    all_missing = {}

    with open(args.output, "w", encoding="utf-8", newline="\n") as out:
        for crate in sorted(targets):
            requested = targets[crate]
            print(f"[{crate}] fetching version...", file=sys.stderr, end=" ", flush=True)
            try:
                version = fetch_latest_version(crate)
            except Exception as e:
                print(f"FAILED: {e}", file=sys.stderr)
                continue
            print(f"{version}; downloading source...", file=sys.stderr, end=" ", flush=True)
            try:
                tar_data = fetch_source_tarball(crate, version)
            except Exception as e:
                print(f"FAILED: {e}", file=sys.stderr)
                continue
            print(f"{len(tar_data) // 1024} KB; parsing...", file=sys.stderr, end=" ", flush=True)
            try:
                src = read_all_rust_source(tar_data)
                types = parse_types_and_methods(src)
            except Exception as e:
                print(f"PARSE FAILED: {e}", file=sys.stderr)
                continue

            stats = emit_jsonl(crate, types, requested, out)
            grand_types += stats["types_emitted"]
            grand_methods += stats["methods_emitted"]
            if stats["missing"]:
                all_missing[crate] = stats["missing"]
            print(
                f"emitted {stats['types_emitted']}/{len(requested)} types, "
                f"{stats['methods_emitted']} methods"
                + (f" (missing {len(stats['missing'])})" if stats["missing"] else ""),
                file=sys.stderr,
            )

    print("", file=sys.stderr)
    print(f"TOTAL: {grand_types} types, {grand_methods} methods", file=sys.stderr)
    if all_missing:
        print("MISSING types (not found in crate source):", file=sys.stderr)
        for crate, miss in all_missing.items():
            print(f"  {crate}: {miss}", file=sys.stderr)
    print(f"Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
