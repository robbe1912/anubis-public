#!/usr/bin/env python3
"""
DELULU v2 Rust Mutation Engine — DYNAMIC API surface fetching.

Downloads crate source from crates.io, parses for pub fn/struct/enum/trait/impl,
generates hallucinated variants, outputs DELULU-format JSONL.

No manual curation — works for ANY Rust crate, auto-updates with new versions.

Usage:
  python mutate_rust.py --crates serde clap tokio reqwest anyhow chrono \
    --output tests/fixtures/delulu_v2_rust.jsonl --count 300
"""

import argparse
import json
import random
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from fetch_api import fetch_rust_api

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
        ('from_str', 'from_string'), ('from_str', 'parse'),
        ('to_str', 'to_string'), ('to_str', 'as_str'),
        ('is_empty', 'is_blank'), ('is_empty', 'is_null'),
        ('new', 'create'), ('new', 'build'), ('new', 'make'),
        ('get', 'fetch'), ('get', 'retrieve'),
        ('set', 'update'), ('insert', 'add'), ('remove', 'delete'),
    ]
    results = []
    for old, new in suffix_mutations:
        if name.endswith(old):
            results.append(name[:-len(old)] + new)
    return results

def classify_mutation(original, mutated):
    if len(original) == len(mutated) + 1:
        return "char_delete"
    elif len(original) == len(mutated):
        diffs = sum(1 for a, b in zip(original, mutated) if a != b)
        return "char_transpose" if diffs == 2 else ("char_substitute" if diffs == 1 else "wrong_suffix")
    return "wrong_suffix"

def generate_rust_samples(crates, max_samples=300):
    samples = []

    for crate in crates:
        print(f"  Fetching {crate}...", file=sys.stderr)
        api = fetch_rust_api(crate)

        if "error" in api:
            print(f"    SKIP: {api['error']}", file=sys.stderr)
            continue

        all_names = set(api.keys())
        for info in api.values():
            all_names.update(info.get("methods", []))

        print(f"    {len(api)} symbols", file=sys.stderr)

        for type_name, info in api.items():
            methods = info.get("methods", [])
            symbol_type = info.get("type", "type")

            for method in methods:
                if len(method) < 4:
                    continue

                mutations = set()
                mutations.update(char_transpose(method))
                mutations.update(char_delete(method))
                mutations.update(char_substitute(method)[:2])
                mutations.update(wrong_suffix(method))

                for mutation in mutations:
                    if mutation in all_names:
                        continue

                    golden = f"{type_name}.{method}()"
                    hallucinated = f"{type_name}.{mutation}()"

                    samples.append({
                        "benchmark_id": f"v2-rust-method-{crate}-{type_name}-{method}-{mutation}",
                        "language": "rust",
                        "hallucination_type": "method",
                        "prompt": f"// Using {crate}\nuse {crate};\n\n",
                        "suffix": "\n",
                        "hallucinated_completion": hallucinated,
                        "golden_completion": golden,
                        "package": crate,
                        "mutation_strategy": classify_mutation(method, mutation),
                    })

            if symbol_type in ("type", "class") and len(type_name) >= 4:
                type_mutations = set()
                type_mutations.update(char_transpose(type_name))
                type_mutations.update(char_delete(type_name))
                type_mutations.update(char_substitute(type_name)[:2])

                for mutation in type_mutations:
                    if mutation in all_names:
                        continue

                    real_method = methods[0] if methods else "new"
                    golden = f"{type_name}.{real_method}()"
                    hallucinated = f"{mutation}.{real_method}()"

                    samples.append({
                        "benchmark_id": f"v2-rust-type-{crate}-{type_name}-{mutation}",
                        "language": "rust",
                        "hallucination_type": "undefinedvariable",
                        "prompt": f"// Using {crate}\nuse {crate};\n\n",
                        "suffix": "\n",
                        "hallucinated_completion": hallucinated,
                        "golden_completion": golden,
                        "package": crate,
                        "mutation_strategy": classify_mutation(type_name, mutation),
                    })

    random.shuffle(samples)
    return samples[:max_samples]

def main():
    parser = argparse.ArgumentParser(description="DELULU v2 Rust mutation engine (dynamic)")
    parser.add_argument("--crates", nargs="+",
                        default=["serde", "serde_json", "clap", "tokio", "reqwest",
                                 "anyhow", "chrono", "regex", "rand", "uuid"])
    parser.add_argument("--output", default="tests/fixtures/delulu_v2_rust.jsonl")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    print(f"Fetching API surfaces for {len(args.crates)} crates...", file=sys.stderr)

    samples = generate_rust_samples(args.crates, max_samples=args.count)

    with open(args.output, 'w') as f:
        for s in samples:
            f.write(json.dumps(s) + '\n')

    print(f"\nWrote {len(samples)} samples to {args.output}", file=sys.stderr)

    by_type = {}
    by_crate = {}
    by_strategy = {}
    for s in samples:
        by_type[s["hallucination_type"]] = by_type.get(s["hallucination_type"], 0) + 1
        by_crate[s["package"]] = by_crate.get(s["package"], 0) + 1
        by_strategy[s.get("mutation_strategy", "?")] = by_strategy.get(s.get("mutation_strategy", "?"), 0) + 1

    print("\nBy type:", file=sys.stderr)
    for k, v in sorted(by_type.items()):
        print(f"  {k}: {v}", file=sys.stderr)
    print("\nBy crate:", file=sys.stderr)
    for k, v in sorted(by_crate.items()):
        print(f"  {k}: {v}", file=sys.stderr)
    print("\nBy strategy:", file=sys.stderr)
    for k, v in sorted(by_strategy.items()):
        print(f"  {k}: {v}", file=sys.stderr)

if __name__ == "__main__":
    main()
