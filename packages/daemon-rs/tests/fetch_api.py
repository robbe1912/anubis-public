#!/usr/bin/env python3
"""
Dynamic API surface fetcher — downloads package source and extracts
public API surface for any language.

Python:   dir() runtime introspection
Rust:     crates.io source download → regex parse for pub fn/struct/enum/trait
TypeScript: npm registry tarball → .d.ts parse for exports

Usage:
  python fetch_api.py --lang rust --packages serde tokio clap --output api_rust.json
  python fetch_api.py --lang typescript --packages react zustand --output api_ts.json
  python fetch_api.py --lang python --packages pandas numpy --output api_python.json
"""

import argparse
import importlib
import inspect
import io
import json
import re
import sys
import tarfile
from typing import Any


# ─── Python: runtime introspection ────────────────────────────────────

def fetch_python_api(package_name: str) -> dict:
    """Extract public API surface via dir() introspection."""
    try:
        module = importlib.import_module(package_name)
    except ImportError as e:
        return {"error": str(e)}

    surface = {}
    for name in dir(module):
        if name.startswith('_'):
            continue
        try:
            obj = getattr(module, name)
        except Exception:
            continue

        if inspect.isclass(obj):
            methods = []
            params = {}
            for mname in dir(obj):
                if mname.startswith('_'):
                    continue
                try:
                    mobj = getattr(obj, mname)
                    if callable(mobj):
                        methods.append(mname)
                        try:
                            sig = inspect.signature(mobj)
                            params[f"{name}.{mname}"] = list(sig.parameters.keys())
                        except (ValueError, TypeError, RuntimeError):
                            pass
                except Exception:
                    continue
            surface[name] = {"type": "class", "methods": methods, "method_params": params}
        elif callable(obj):
            try:
                sig = inspect.signature(obj)
                surface[name] = {"type": "function", "params": list(sig.parameters.keys())}
            except (ValueError, TypeError, RuntimeError):
                surface[name] = {"type": "function", "params": []}

    return surface


# ─── Rust: crates.io source download + regex parse ────────────────────

def fetch_rust_api(crate_name: str) -> dict:
    """Download crate source from crates.io, parse for public API."""
    import urllib.request

    # 1. Get latest version
    try:
        req = urllib.request.Request(
            f"https://crates.io/api/v1/crates/{crate_name}",
            headers={"User-Agent": "delulu-v2-mutation-engine"}
        )
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        version = data["crate"]["max_stable_version"]
    except Exception as e:
        return {"error": f"crates.io fetch failed: {e}"}

    # 2. Download source tarball
    try:
        url = f"https://crates.io/api/v1/crates/{crate_name}/{version}/download"
        req = urllib.request.Request(url, headers={"User-Agent": "delulu-v2-mutation-engine"})
        resp = urllib.request.urlopen(req, timeout=30)
        tar_data = resp.read()
    except Exception as e:
        return {"error": f"source download failed: {e}"}

    # 3. Extract and parse .rs files
    surface = {}
    try:
        tar = tarfile.open(fileobj=io.BytesIO(tar_data))
    except Exception as e:
        return {"error": f"tarball extract failed: {e}"}

    # Collect all source first, then parse
    all_source = {}
    for member in tar.getmembers():
        if member.name.endswith('.rs') and member.isfile():
            try:
                content = tar.extractfile(member).read().decode('utf-8', errors='replace')
                all_source[member.name] = content
            except Exception:
                continue

    combined = "\n".join(all_source.values())

    # Parse pub struct/enum/trait/type declarations
    for match in re.finditer(r'\bpub\s+(?:struct|enum|trait|type)\s+(\w+)', combined):
        name = match.group(1)
        if name not in surface:
            surface[name] = {"type": "type", "methods": [], "params": {}}

    # Parse impl blocks: impl Type { pub fn method() {} }
    # Split by impl blocks
    impl_re = re.compile(r'\bimpl\s+(?:<[^>]+>\s+)?(?:\w+::)*(\w+)\s*(?:<[^>]+>)?\s*\{', re.DOTALL)
    for match in impl_re.finditer(combined):
        type_name = match.group(1)
        if type_name not in surface:
            surface[type_name] = {"type": "type", "methods": [], "params": {}}

        # Find the impl block body (match braces)
        start = match.end() - 1  # position of opening {
        depth = 0
        end = start
        for i in range(start, min(start + 50000, len(combined))):
            if combined[i] == '{':
                depth += 1
            elif combined[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break

        body = combined[start:end]

        # Extract pub fn names from impl body
        for fn_match in re.finditer(r'\bpub\s+(?:async\s+)?(?:const\s+)?fn\s+(\w+)', body):
            method = fn_match.group(1)
            if method not in surface[type_name]["methods"]:
                surface[type_name]["methods"].append(method)

        # Extract fn names (even non-pub, for trait impls)
        for fn_match in re.finditer(r'\b(?:async\s+)?(?:const\s+)?fn\s+(\w+)\s*\(', body):
            method = fn_match.group(1)
            if method not in surface[type_name]["methods"] and not method.startswith('_'):
                surface[type_name]["methods"].append(method)

    # Parse standalone pub fn (module-level functions)
    for match in re.finditer(r'\bpub\s+(?:async\s+)?(?:const\s+)?fn\s+(\w+)\s*\(', combined):
        name = match.group(1)
        if name not in surface:
            surface[name] = {"type": "function", "methods": [], "params": []}

    return surface


# ─── TypeScript: npm tarball + .d.ts parse ────────────────────────────

def fetch_ts_api(package_name: str) -> dict:
    """Download npm package tarball, parse .d.ts for exports."""
    import urllib.request

    # 1. Get latest version + tarball URL
    try:
        resp = urllib.request.urlopen(
            f"https://registry.npmjs.org/{package_name}/latest",
            timeout=15
        )
        data = json.loads(resp.read())
        tarball_url = data["dist"]["tarball"]
        version = data.get("version", "unknown")
    except Exception as e:
        return {"error": f"npm fetch failed: {e}"}

    # 2. Download tarball
    try:
        resp = urllib.request.urlopen(tarball_url, timeout=30)
        tar_data = resp.read()
    except Exception as e:
        return {"error": f"tarball download failed: {e}"}

    # 3. Extract .d.ts and .js files
    surface = {}
    try:
        tar = tarfile.open(fileobj=io.BytesIO(tar_data))
    except Exception as e:
        return {"error": f"tarball extract failed: {e}"}

    dts_source = []
    js_source = []

    for member in tar.getmembers():
        if member.isfile():
            if member.name.endswith('.d.ts'):
                try:
                    dts_source.append(tar.extractfile(member).read().decode('utf-8', errors='replace'))
                except Exception:
                    continue
            elif member.name.endswith('.js') and not member.name.endswith('.min.js'):
                try:
                    js_source.append(tar.extractfile(member).read().decode('utf-8', errors='replace'))
                except Exception:
                    continue

    combined_dts = "\n".join(dts_source)
    combined_js = "\n".join(js_source[:5])  # Limit JS to first 5 files

    # Parse .d.ts for exports
    # export function name()
    for match in re.finditer(r'export\s+(?:async\s+)?function\s+(\w+)', combined_dts):
        name = match.group(1)
        surface[name] = {"type": "function", "methods": [], "params": []}

    # export class Name { method() {} }
    class_re = re.compile(
        r'export\s+(?:abstract\s+)?class\s+(\w+)(?:\s+extends\s+\w+)?\s*(?:<[^>]+>)?\s*\{',
        re.DOTALL
    )
    for match in class_re.finditer(combined_dts):
        class_name = match.group(1)
        if class_name not in surface:
            surface[class_name] = {"type": "class", "methods": [], "params": {}}

        # Find class body (match braces)
        start = match.end() - 1
        depth = 0
        end = start
        for i in range(start, min(start + 30000, len(combined_dts))):
            if combined_dts[i] == '{':
                depth += 1
            elif combined_dts[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break

        body = combined_dts[start:end]

        # Extract method names
        for m in re.finditer(r'(?:public|private|protected|static|async|readonly|\s)+(\w+)\s*\(', body):
            method = m.group(1)
            if not method.startswith('_') and method not in ('constructor', 'if', 'for', 'while', 'switch', 'return'):
                if method not in surface[class_name]["methods"]:
                    surface[class_name]["methods"].append(method)

    # export const/let/var name
    for match in re.finditer(r'export\s+(?:const|let|var)\s+(\w+)', combined_dts):
        name = match.group(1)
        if name not in surface:
            surface[name] = {"type": "constant", "methods": [], "params": []}

    # export interface Name
    for match in re.finditer(r'export\s+interface\s+(\w+)', combined_dts):
        name = match.group(1)
        if name not in surface:
            surface[name] = {"type": "interface", "methods": [], "params": []}

    # export type Name
    for match in re.finditer(r'export\s+type\s+(\w+)', combined_dts):
        name = match.group(1)
        if name not in surface:
            surface[name] = {"type": "type", "methods": [], "params": []}

    # export { name1, name2 } — from re-exports
    for match in re.finditer(r'export\s+\{([^}]+)\}', combined_dts):
        for name in match.group(1).split(','):
            name = name.strip().split(' as ')[0].strip()
            if name and name not in surface:
                surface[name] = {"type": "export", "methods": [], "params": []}

    # Fallback: parse package.json exports field
    if not surface:
        try:
            pkg_json = tar.extractfile('package/package.json')
            if pkg_json:
                pkg = json.loads(pkg_json.read())
                exports = pkg.get('exports', pkg.get('main', ''))
                if isinstance(exports, dict):
                    for key in exports:
                        if key.startswith('.'):
                            surface[f"export:{key}"] = {"type": "module", "methods": [], "params": []}
        except Exception:
            pass

    return surface


# ─── Main ──────────────────────────────────────────────────────────────

FETCHERS = {
    "python": fetch_python_api,
    "rust": fetch_rust_api,
    "typescript": fetch_ts_api,
}

def main():
    parser = argparse.ArgumentParser(description="Dynamic API surface fetcher")
    parser.add_argument("--lang", required=True, choices=["python", "rust", "typescript"])
    parser.add_argument("--packages", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    fetcher = FETCHERS[args.lang]
    result = {}

    for pkg in args.packages:
        print(f"Fetching {pkg}...", file=sys.stderr)
        api = fetcher(pkg)
        if "error" in api:
            print(f"  ERROR: {api['error']}", file=sys.stderr)
            result[pkg] = api
        else:
            n_types = len(api)
            n_methods = sum(len(v.get("methods", [])) for v in api.values())
            print(f"  {n_types} symbols, {n_methods} methods", file=sys.stderr)
            result[pkg] = api

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"\nWrote {len(result)} packages to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
