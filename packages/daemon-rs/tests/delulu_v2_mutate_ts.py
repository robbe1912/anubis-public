#!/usr/bin/env python3
"""
DELULU v2 TypeScript Mutation Engine — DYNAMIC API surface fetching.

Downloads npm package tarballs, parses .d.ts declaration files for exports,
generates hallucinated variants, outputs DELULU-format JSONL.

Usage:
  python mutate_ts.py --packages react zustand @testing-library/react express zod \
    --output tests/fixtures/delulu_v2_ts.jsonl --count 300
"""

import argparse
import json
import random
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from fetch_api import fetch_ts_api

def char_transpose(name):
    results = []
    for i in range(len(name) - 1):
        chars = list(name)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        mutated = ''.join(chars)
        if mutated != name:
            results.append(mutated)
    return results

def char_delete(name):
    return [name[:i] + name[i+1:] for i in range(len(name)) if len(name) > 3]

def char_substitute(name):
    nearby = {
        'a': 'sq', 'b': 'vn', 'c': 'xv', 'd': 'sf', 'e': 'wr',
        'f': 'dg', 'g': 'fh', 'h': 'gj', 'i': 'uo', 'j': 'hk',
        'k': 'jl', 'l': 'k', 'm': 'n', 'n': 'bm', 'o': 'ip',
        'p': 'o', 'q': 'wa', 'r': 'et', 's': 'ad', 't': 'ry',
        'u': 'yi', 'v': 'cb', 'w': 'qe', 'x': 'zc', 'y': 'tu', 'z': 'x',
    }
    results = []
    for i, c in enumerate(name.lower()):
        if c in nearby:
            for sub in nearby[c]:
                mutated = name[:i] + sub + name[i+1:]
                if mutated != name:
                    results.append(mutated)
    return results

def wrong_suffix(name):
    suffix_mutations = [
        ('Component', 'Componant'), ('State', 'Store'), ('State', 'Status'),
        ('Effect', 'Affect'), ('Ref', 'Reference'), ('Ref', 'Var'),
        ('render', 'rnder'), ('mount', 'munt'), ('unmount', 'unmont'),
        ('useState', 'useStat'), ('useEffect', 'useAffect'),
        ('dispatch', 'dispath'), ('subscribe', 'subscibe'),
        ('create', 'creat'), ('update', 'updat'),
    ]
    return [name[:-len(old)] + new for old, new in suffix_mutations if name.endswith(old)]

def classify_mutation(original, mutated):
    if len(original) == len(mutated) + 1:
        return "char_delete"
    elif len(original) == len(mutated):
        diffs = sum(1 for a, b in zip(original, mutated) if a != b)
        return "char_transpose" if diffs == 2 else ("char_substitute" if diffs == 1 else "wrong_suffix")
    return "wrong_suffix"

def generate_ts_samples(packages, max_samples=300):
    samples = []

    for pkg in packages:
        print(f"  Fetching {pkg}...", file=sys.stderr)
        api = fetch_ts_api(pkg)

        if "error" in api:
            print(f"    SKIP: {api['error']}", file=sys.stderr)
            continue

        all_names = set(api.keys())
        for info in api.values():
            all_names.update(info.get("methods", []))

        print(f"    {len(api)} symbols", file=sys.stderr)

        for name, info in api.items():
            symbol_type = info.get("type", "export")
            methods = info.get("methods", [])

            # Method mutations on classes
            if symbol_type == "class":
                for method in methods:
                    if len(method) < 4 or method in ('constructor',):
                        continue

                    mutations = set()
                    mutations.update(char_transpose(method))
                    mutations.update(char_delete(method))
                    mutations.update(char_substitute(method)[:2])

                    for mutation in mutations:
                        if mutation in all_names:
                            continue

                        golden = f"{name}.{method}()"
                        hallucinated = f"{name}.{mutation}()"

                        samples.append({
                            "benchmark_id": f"v2-ts-method-{pkg}-{name}-{method}-{mutation}",
                            "language": "typescript",
                            "hallucination_type": "method",
                            "prompt": f"// Using {pkg}\nimport {{ {name} }} from '{pkg}';\n\n",
                            "suffix": "\n",
                            "hallucinated_completion": hallucinated,
                            "golden_completion": golden,
                            "package": pkg,
                            "mutation_strategy": classify_mutation(method, mutation),
                        })

            # Export-level mutations (wrong function/hook name)
            if symbol_type in ("function", "export", "constant") and len(name) >= 4:
                mutations = set()
                mutations.update(char_transpose(name))
                mutations.update(char_delete(name))
                mutations.update(char_substitute(name)[:2])
                mutations.update(wrong_suffix(name))

                for mutation in mutations:
                    if mutation in all_names:
                        continue

                    golden = f"{name}()"
                    hallucinated = f"{mutation}()"

                    samples.append({
                        "benchmark_id": f"v2-ts-function-{pkg}-{name}-{mutation}",
                        "language": "typescript",
                        "hallucination_type": "undefinedvariable",
                        "prompt": f"// Using {pkg}\nimport {{ {name} }} from '{pkg}';\n\n",
                        "suffix": "\n",
                        "hallucinated_completion": hallucinated,
                        "golden_completion": golden,
                        "package": pkg,
                        "mutation_strategy": classify_mutation(name, mutation),
                    })

    random.shuffle(samples)
    return samples[:max_samples]

def main():
    parser = argparse.ArgumentParser(description="DELULU v2 TS mutation engine (dynamic)")
    parser.add_argument("--packages", nargs="+",
                        default=["react", "zustand", "@testing-library/react", "express", "zod",
                                 "vitest", "@prisma/client", "react-router-dom", "axios", "lodash"])
    parser.add_argument("--output", default="tests/fixtures/delulu_v2_ts.jsonl")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    print(f"Fetching API surfaces for {len(args.packages)} packages...", file=sys.stderr)

    samples = generate_ts_samples(args.packages, max_samples=args.count)

    with open(args.output, 'w') as f:
        for s in samples:
            f.write(json.dumps(s) + '\n')

    print(f"\nWrote {len(samples)} samples to {args.output}", file=sys.stderr)

    by_type = {}
    by_pkg = {}
    by_strategy = {}
    for s in samples:
        by_type[s["hallucination_type"]] = by_type.get(s["hallucination_type"], 0) + 1
        by_pkg[s["package"]] = by_pkg.get(s["package"], 0) + 1
        by_strategy[s.get("mutation_strategy", "?")] = by_strategy.get(s.get("mutation_strategy", "?"), 0) + 1

    print("\nBy type:", file=sys.stderr)
    for k, v in sorted(by_type.items()):
        print(f"  {k}: {v}", file=sys.stderr)
    print("\nBy package:", file=sys.stderr)
    for k, v in sorted(by_pkg.items()):
        print(f"  {k}: {v}", file=sys.stderr)
    print("\nBy strategy:", file=sys.stderr)
    for k, v in sorted(by_strategy.items()):
        print(f"  {k}: {v}", file=sys.stderr)

if __name__ == "__main__":
    main()
