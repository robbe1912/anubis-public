#!/usr/bin/env python3
"""Bootstrap script for fresh Anubis installation.

Runs symbol fetch scripts to populate symbol_bundle.jsonl from
authoritative sources. Only fetches symbols for languages you use.

Usage:
    cd packages/daemon-rs
    # Fetch everything (all languages)
    python tests/bootstrap_bundle.py

    # Fetch only specific languages (lean bundle for single-language projects)
    python tests/bootstrap_bundle.py --languages python
    python tests/bootstrap_bundle.py --languages rust,godot
    python tests/bootstrap_bundle.py --languages c,godot

    # Dry run (show what would be fetched without writing)
    python tests/bootstrap_bundle.py --languages python --dry-run

Available languages: python, rust, typescript (npm), go, godot, c, cpp, csharp, java

Note: Go/C/C++/C#/Java use runtime introspection or curated lists, not
pre-seeded bundles. Only python/rust/typescript/godot have fetch scripts.
Godot symbols (77K+) are pre-seeded in symbol_bundle_bulk.jsonl.
"""
import subprocess
import sys
import os
import argparse
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent
BUNDLE = SCRIPTS_DIR / "fixtures" / "symbol_bundle.jsonl"

LANG_FETCHERS = {
    "python": {
        "script": "fetch_python_classes.py",
        "args": [],
        "label": "Python class methods (pandas, numpy, sqlalchemy, etc.)",
        "requires": "Python packages installed (pip install pandas numpy sqlalchemy)",
    },
    "typescript": {
        "script": "fetch_npm_types.py",
        "args": [],
        "label": "npm TypeScript exports (react, zustand, zod, vitest, etc.)",
        "requires": "Internet access (jsDelivr CDN)",
    },
    "rust": {
        "script": "fetch_rust_types.py",
        "args": ["--all"],
        "label": "Rust types (tokio, chrono, serde, regex, rand, anyhow, uuid)",
        "requires": "Internet access (crates.io)",
    },
    # Godot: pre-seeded in symbol_bundle_bulk.jsonl, no fetch needed
    # Go/C/C++/C#/Java: runtime introspection, no pre-seeded bundle
}

def run_fetcher(lang_config, dry_run=False):
    """Run a single language fetcher and return success."""
    script = lang_config["script"]
    args = lang_config["args"]
    label = lang_config["label"]
    requires = lang_config.get("requires", "")

    print(f"\n{'='*60}")
    print(f"  {label}")
    if requires:
        print(f"  Requires: {requires}")
    print(f"{'='*60}")

    if dry_run:
        print("  [DRY RUN] Skipping actual fetch")
        return True

    path = SCRIPTS_DIR / script
    if not path.exists():
        print(f"  SKIP: {script} not found")
        return False

    result = subprocess.run(
        [sys.executable, str(path), *args],
        capture_output=True, text=True, cwd=str(SCRIPTS_DIR.parent)
    )
    if result.returncode != 0:
        print(f"  WARNING: {script} exited with code {result.returncode}")
        if result.stderr:
            print(f"  stderr (last 300): {result.stderr[-300:]}")
    else:
        # Append output to bundle
        with open(BUNDLE, "a", encoding="utf-8") as f:
            f.write(result.stdout)
        entries = result.stdout.count("\n")
        print(f"  Added {entries} entries to bundle")
    return result.returncode == 0

def main():
    parser = argparse.ArgumentParser(description="Bootstrap Anubis symbol bundle")
    parser.add_argument("--languages", "-l", type=str, default="all",
                        help="Comma-separated languages to fetch (default: all). "
                             "Available: python, rust, typescript, godot, go, c, cpp, csharp, java")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be fetched without writing")
    args = parser.parse_args()

    # Determine which languages to fetch
    if args.languages.lower() == "all":
        langs = list(LANG_FETCHERS.keys())
    else:
        langs = [l.strip().lower() for l in args.languages.split(",")]

    print(f"Bundle target: {BUNDLE}")
    print(f"Languages: {', '.join(langs)}")
    if args.dry_run:
        print("Mode: DRY RUN (no writes)")

    if BUNDLE.exists() and not args.dry_run:
        before = sum(1 for _ in open(BUNDLE, encoding="utf-8"))
        print(f"Current entries: {before}")
    elif not BUNDLE.exists():
        if not args.dry_run:
            BUNDLE.parent.mkdir(parents=True, exist_ok=True)
            BUNDLE.touch()
        print("Creating new bundle.")

    results = {}
    for lang in langs:
        if lang in LANG_FETCHERS:
            results[lang] = run_fetcher(LANG_FETCHERS[lang], args.dry_run)
        elif lang in ("godot", "go", "c", "cpp", "csharp", "java"):
            print(f"\n  {lang}: No fetch script needed (runtime introspection or pre-seeded)")
            results[lang] = True
        else:
            print(f"\n  WARNING: Unknown language '{lang}', skipping")
            results[lang] = False

    # Report
    print(f"\n{'='*60}")
    if not args.dry_run and BUNDLE.exists():
        after = sum(1 for _ in open(BUNDLE, encoding="utf-8"))
        print(f"  Bundle: {after} total entries at {BUNDLE}")
        # Copy to daemon's home directory so the daemon seeds its SQLite
        # cache on next startup. This is the production path the daemon
        # checks at boot (see src/bin/daemon.rs).
        anubis_home = Path.home() / ".anubis"
        anubis_home.mkdir(parents=True, exist_ok=True)
        prod_bundle = anubis_home / "symbol_bundle.jsonl"
        import shutil
        shutil.copy2(BUNDLE, prod_bundle)
        print(f"  Copied to daemon home: {prod_bundle}")
        print(f"  Daemon will seed {after} symbols on next startup.")
    print(f"  Results: {sum(1 for v in results.values() if v)}/{len(results)} languages succeeded")
    for lang, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"    {lang}: {status}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
