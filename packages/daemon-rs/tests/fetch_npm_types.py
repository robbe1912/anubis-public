#!/usr/bin/env python3
"""Fetch TypeScript package exports from npm via jsDelivr CDN.

Downloads .d.ts files from jsDelivr (CDN-cached, 100-300ms) and extracts
export names using regex. Output is JSONL matching symbol_bundle.jsonl schema.

Usage:
    python fetch_npm_types.py --packages react zustand zod vitest axios \
        express @types/node @types/express @types/react \
        --output symbol_bundle_npm_extended.jsonl

Sources of truth: jsDelivr CDN (data.jsdelivr.com) + unpkg.com fallback.
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

CDN_BASE = "https://cdn.jsdelivr.net/npm"
META_BASE = "https://data.jsdelivr.com/v1/packages/npm"
REGISTRY = "https://registry.npmjs.org"
TIMEOUT = 15

# Pin versions for reproducibility. After a verified good bundle run,
# pin the versions here to lock the output. Packages NOT in this dict
# will use get_latest_version() (non-deterministic — package updates
# between runs produce different bundles).
PINNED_VERSIONS = {
    "react": "18.3.1",
    "zustand": "5.0.14",
    "zod": "3.25.76",
    "vitest": "1.6.1",
    "axios": "1.7.9",
    "@types/react": "18.3.18",
    "@types/express": "4.17.21",
    "@types/node": "20.17.0",
    "express": "4.21.0",
    "react-router-dom": "6.28.0",
    "@apollo/client": "3.12.0",
    "@testing-library/react": "14.1.2",
    "next": "14.2.21",
    "@prisma/client": "6.2.1",
    "prisma": "6.2.1",
    "swr": "2.2.5",
    "react-query": "3.39.3",
    "tailwindcss": "3.4.17",
    "lodash": "4.17.21",
    "date-fns": "4.1.0",
    "rxjs": "7.8.1",
}

# Regex to extract export names from .d.ts files.
# Matches: export const/function/class/interface/type/enum Name
EXPORT_RE = re.compile(
    r"export\s+(?:default\s+)?(?:const|function|class|interface|type|enum|abstract\s+class)\s+(\w+)"
)
# Also matches: export { Name1, Name2, Name3 }
EXPORT_LIST_RE = re.compile(r"export\s*\{([^}]+)\}")
# export declare function/class
DECLARE_RE = re.compile(
    r"(?:export\s+)?declare\s+(?:const|function|class|interface|type|enum)\s+(\w+)"
)


def fetch_json(url: str) -> dict:
    """Fetch JSON from URL with timeout."""
    req = Request(url, headers={"User-Agent": "anubis-daemon/fetch_npm_types"})
    with urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_text(url: str) -> str:
    """Fetch text content from URL."""
    req = Request(url, headers={"User-Agent": "anubis-daemon/fetch_npm_types"})
    with urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def get_latest_version(pkg: str) -> str | None:
    """Get latest version from npm registry (non-deterministic)."""
    try:
        url = f"{REGISTRY}/{pkg}"
        data = fetch_json(url)
        return data.get("dist-tags", {}).get("latest")
    except (HTTPError, URLError, json.JSONDecodeError, KeyError):
        return None


def resolve_version(pkg: str) -> str | None:
    """Resolve version: use pinned if available, else fall back to latest.
    
    Pinned versions ensure reproducible bundle output across runs.
    See PINNED_VERSIONS dict at top of file.
    """
    if pkg in PINNED_VERSIONS:
        print(f"  [pin] {pkg}@{PINNED_VERSIONS[pkg]}", file=sys.stderr)
        return PINNED_VERSIONS[pkg]
    return get_latest_version(pkg)


def find_dts_files(pkg: str, version: str) -> list[str]:
    """Find .d.ts files via jsDelivr API."""
    try:
        url = f"{META_BASE}/{pkg}@{version}"
        data = fetch_json(url)
        return _walk_files(data.get("files", []), "")
    except (HTTPError, URLError, json.JSONDecodeError):
        return []


def _walk_files(files: list, prefix: str) -> list[str]:
    """Recursively walk jsDelivr file tree."""
    result = []
    for entry in files:
        name = entry.get("name", "")
        if entry.get("type") == "file" and name.endswith(".d.ts"):
            result.append(f"{prefix}/{name}")
        elif entry.get("type") == "directory":
            result.extend(_walk_files(entry.get("files", []), f"{prefix}/{name}"))
    return result


def get_types_entry(pkg: str, version: str) -> str | None:
    """Get the types entry point from package.json."""
    try:
        url = f"{CDN_BASE}/{pkg}@{version}/package.json"
        data = fetch_json(url)
        return data.get("types") or data.get("typings")
    except (HTTPError, URLError, json.JSONDecodeError):
        return None


def extract_exports(dts_content: str) -> set[str]:
    """Extract export names from .d.ts content using regex."""
    exports = set()

    # Direct exports: export const/function/class/interface/type Name
    for m in EXPORT_RE.finditer(dts_content):
        exports.add(m.group(1))

    # Declare statements: declare function/class/interface Name
    for m in DECLARE_RE.finditer(dts_content):
        exports.add(m.group(1))

    # Export lists: export { Name1, Name2 }
    for m in EXPORT_LIST_RE.finditer(dts_content):
        for name in m.group(1).split(","):
            name = name.strip().split(" as ")[0].strip()
            if name and re.match(r"^\w+$", name):
                exports.add(name)

    return exports


def fetch_package_exports(pkg: str) -> list[dict]:
    """Fetch all exports for a package and return JSONL entries."""
    version = resolve_version(pkg)
    if not version:
        print(f"  SKIP {pkg}: version not found", file=sys.stderr)
        return []

    print(f"  {pkg}@{version}: ", end="", file=sys.stderr)

    # Try package.json types field first
    types_entry = get_types_entry(pkg, version)

    dts_files_to_fetch = []
    if types_entry:
        dts_files_to_fetch.append(types_entry.lstrip("/"))

    # ALWAYS fetch ALL .d.ts files (not just first 5) — modern packages
    # use `export * from` re-exports so index.d.ts has no real content.
    all_dts = find_dts_files(pkg, version)
    for dts in all_dts:
        dts_clean = dts.lstrip("/")
        if dts_clean not in dts_files_to_fetch:
            dts_files_to_fetch.append(dts_clean)

    # Cap at 30 files to avoid downloading huge packages like TypeScript
    dts_files_to_fetch = dts_files_to_fetch[:30]

    if not dts_files_to_fetch:
        # Try @types/{pkg} fallback
        if not pkg.startswith("@types/"):
            types_pkg = f"@types/{pkg.replace('@', '')}"
            print(f"trying {types_pkg}... ", end="", file=sys.stderr)
            return fetch_package_exports(types_pkg)
        print("no .d.ts files", file=sys.stderr)
        return []

    all_exports = set()
    for dts_path in dts_files_to_fetch:
        # Normalize: ensure no leading "./", ensure single "/" separator
        clean_path = dts_path.lstrip("./").lstrip("/")
        url = f"{CDN_BASE}/{pkg}@{version}/{clean_path}"
        try:
            content = fetch_text(url)
            exports = extract_exports(content)
            all_exports.update(exports)
        except (HTTPError, URLError):
            continue

    if not all_exports:
        print(f"0 exports from {len(dts_files_to_fetch)} files", file=sys.stderr)
        return []

    print(f"{len(all_exports)} exports from {len(dts_files_to_fetch)} .d.ts files", file=sys.stderr)

    # Emit JSONL entries matching symbol_bundle schema
    entries = []
    lib_name = f"npm.{pkg}"
    for name in sorted(all_exports):
        entries.append({
            "library": lib_name,
            "version": version,
            "path": f"{pkg}.{name}",
            "name": name,
            "kind": "Export",
            "signature": None,
            "params": [],
            "return_type": None,
            "doc_text": None,
            "source_file": None,
            "visibility": "Public",
            "is_deprecated": False,
            "deprecated_message": None,
            "extracted_at": int(time.time()),
        })

    return entries


def main():
    parser = argparse.ArgumentParser(
        description="Fetch npm package TypeScript exports for symbol bundle."
    )
    parser.add_argument(
        "--packages", nargs="+", required=True,
        help="npm package names (e.g., react zustand zod vitest axios)",
    )
    parser.add_argument(
        "--output", required=True,
        help="Output JSONL file path",
    )
    args = parser.parse_args()

    all_entries = []
    for pkg in args.packages:
        entries = fetch_package_exports(pkg)
        all_entries.extend(entries)

    # Write JSONL
    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        for entry in all_entries:
            f.write(json.dumps(entry) + "\n")

    print(f"\nWrote {len(all_entries)} entries to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
