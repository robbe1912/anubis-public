#!/usr/bin/env python3
"""
DELULU v2 Mutation Engine — generates hallucination test samples from real APIs.

For each package:
1. Introspect public API surface (functions, classes, methods)
2. Generate plausible hallucinated variants
3. Verify each variant is ACTUALLY invalid (hasattr returns False)
4. Output DELULU-format JSONL with golden + hallucinated completions

Mutation types:
  - method: wrong method name (read_csv → read_cvs, read_excel)
  - parameter: wrong parameter name (nullable → nulleable)  
  - import: wrong module path (pandas.io.sql → pandas.io.db)
  - undefinedvariable: wrong variable name (df → dataframe)

Usage:
  python mutate.py --packages pandas numpy requests --output delulu_v2.jsonl --count 200
"""

import argparse
import importlib
import inspect
import json
import random
import sys
from typing import Any, Optional


# ─── Mutation strategies ───────────────────────────────────────────────

def char_transpose(name: str) -> list[str]:
    """Swap adjacent characters: read_csv → read_csv (same), raed_csv → read_csv"""
    results = []
    for i in range(len(name) - 1):
        chars = list(name)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        mutated = ''.join(chars)
        if mutated != name:
            results.append(mutated)
    return results

def char_delete(name: str) -> list[str]:
    """Delete one character: read_csv → ead_csv, red_csv, readcs"""
    return [name[:i] + name[i+1:] for i in range(len(name)) if len(name) > 3]

def char_substitute(name: str) -> list[str]:
    """Substitute one character with a nearby key: read_csv → raed_csv"""
    nearby = {
        'a': 'sq', 's': 'ad', 'd': 'sf', 'f': 'dg', 'g': 'fh',
        'h': 'gj', 'j': 'hk', 'k': 'jl', 'l': 'k',
        'q': 'wa', 'w': 'qe', 'e': 'wr', 'r': 'et', 't': 'ry',
        'y': 'tu', 'u': 'yi', 'i': 'uo', 'o': 'ip', 'p': 'o',
        'z': 'x', 'x': 'zc', 'c': 'xv', 'v': 'cb', 'b': 'vn',
        'n': 'bm', 'm': 'n',
    }
    results = []
    for i, c in enumerate(name.lower()):
        if c in nearby:
            for sub in nearby[c]:
                mutated = name[:i] + sub + name[i+1:]
                if mutated != name:
                    results.append(mutated)
    return results

def wrong_suffix(name: str) -> list[str]:
    """Change suffix: DataFrame → Dataframe, read_csv → read_tsv"""
    suffix_mutations = [
        ('csv', 'tsv'), ('csv', 'json'), ('csv', 'xml'),
        ('Frame', 'Table'), ('Frame', 'Set'), ('Frame', 'Array'),
        ('Series', 'Sequence'), ('Series', 'Array'),
        ('Array', 'List'), ('Array', 'Vector'),
        ('Reader', 'Loader'), ('Writer', 'Saver'),
        ('open', 'load'), ('open', 'read'),
        ('create', 'make'), ('create', 'build'),
        ('get', 'fetch'), ('get', 'retrieve'),
        ('set', 'update'), ('set', 'assign'),
        ('add', 'append'), ('add', 'insert'),
        ('delete', 'remove'), ('delete', 'drop'),
        ('execute', 'run'), ('execute', 'perform'),
    ]
    results = []
    for old, new in suffix_mutations:
        if name.lower().endswith(old.lower()):
            mutated = name[:-len(old)] + new
            results.append(mutated)
    return results

def semantic_confusion(name: str, siblings: list[str]) -> list[str]:
    """Replace with a semantically related but different function.
    E.g., read_csv → read_excel (same domain, different function)"""
    results = []
    for sib in siblings:
        if sib != name and len(sib) >= 3:
            # Check if they share a prefix (same domain)
            prefix_len = 0
            for a, b in zip(name, sib):
                if a == b:
                    prefix_len += 1
                else:
                    break
            if prefix_len >= 3:
                results.append(sib)
    return results[:3]  # Limit to 3 to avoid explosion


# ─── API surface extraction ────────────────────────────────────────────

def extract_api_surface(module: Any, prefix: str = "", depth: int = 0) -> dict[str, dict]:
    """Extract public API surface from a module.
    Returns {name: {type, params, methods}}"""
    if depth > 1:
        return {}
    
    surface = {}
    for name in dir(module):
        if name.startswith('_'):
            continue
        full_name = f"{prefix}.{name}" if prefix else name
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
            surface[full_name] = {
                "type": "class",
                "methods": methods,
                "method_params": params,
            }
        elif callable(obj):
            try:
                sig = inspect.signature(obj)
                surface[full_name] = {
                    "type": "function",
                    "params": list(sig.parameters.keys()),
                }
            except (ValueError, TypeError, RuntimeError):
                surface[full_name] = {"type": "function", "params": []}
    
    return surface


# ─── Sample generation ────────────────────────────────────────────────

def generate_method_samples(
    package_name: str,
    surface: dict,
    max_samples: int = 20,
) -> list[dict]:
    """Generate DELULU-format samples for method hallucinations."""
    samples = []
    
    # Collect all function/method names for semantic confusion
    all_names = []
    for full_name, info in surface.items():
        if info["type"] == "function":
            all_names.append(full_name.split('.')[-1])
        elif info["type"] == "class":
            all_names.extend(info.get("methods", []))
    all_names = list(set(all_names))
    
    for full_name, info in surface.items():
        if len(samples) >= max_samples:
            break
            
        if info["type"] == "function":
            func_name = full_name.split('.')[-1]
            mutations = set()
            mutations.update(char_transpose(func_name))
            mutations.update(char_delete(func_name))
            mutations.update(char_substitute(func_name)[:2])
            mutations.update(wrong_suffix(func_name))
            mutations.update(semantic_confusion(func_name, all_names))
            
            for mutation in mutations:
                if len(samples) >= max_samples:
                    break
                # Verify mutation doesn't exist
                if hasattr(module_obj, mutation) if module_obj else False:
                    continue
                
                golden = f"{full_name}()"
                hallucinated = f"{full_name.rsplit('.', 1)[0]}.{mutation}()" if '.' in full_name else f"{mutation}()"
                
                samples.append({
                    "benchmark_id": f"v2-python-method-{package_name}-{func_name}-{mutation}",
                    "language": "python",
                    "hallucination_type": "method",
                    "prompt": f"# Using {package_name}\nimport {package_name}\n\n",
                    "suffix": "\n",
                    "hallucinated_completion": hallucinated,
                    "golden_completion": golden,
                    "package": package_name,
                    "mutation_strategy": classify_mutation(func_name, mutation),
                })
        
        elif info["type"] == "class":
            for method in info.get("methods", []):
                if len(samples) >= max_samples:
                    break
                mutations = set()
                mutations.update(char_transpose(method))
                mutations.update(char_delete(method))
                mutations.update(wrong_suffix(method))
                mutations.update(semantic_confusion(method, info.get("methods", [])))
                
                for mutation in mutations:
                    if len(samples) >= max_samples:
                        break
                    # Verify mutation doesn't exist on the class
                    try:
                        cls = getattr(module_obj, full_name.split('.')[-1])
                        if hasattr(cls, mutation):
                            continue
                    except Exception:
                        continue
                    
                    class_name = full_name.split('.')[-1]
                    golden = f"{class_name}.{method}()"
                    hallucinated = f"{class_name}.{mutation}()"
                    
                    samples.append({
                        "benchmark_id": f"v2-python-method-{package_name}-{full_name}.{method}-{mutation}",
                        "language": "python",
                        "hallucination_type": "method",
                        "prompt": f"# Using {package_name}\nfrom {package_name} import {class_name}\n\n",
                        "suffix": "\n",
                        "hallucinated_completion": hallucinated,
                        "golden_completion": golden,
                        "package": package_name,
                        "mutation_strategy": classify_mutation(method, mutation),
                    })
    
    return samples


def generate_parameter_samples(
    package_name: str,
    surface: dict,
    max_samples: int = 10,
) -> list[dict]:
    """Generate DELULU-format samples for parameter hallucinations."""
    samples = []
    
    for full_name, info in surface.items():
        if len(samples) >= max_samples:
            break
        
        params = info.get("params") or info.get("method_params", {}).get(full_name.split('.')[-1], [])
        if not params or len(params) < 2:
            continue
        
        # Pick a parameter and mutate it
        for param in params:
            if param in ('self', 'cls', 'args', 'kwargs', '/'):
                continue
            if len(param) < 3:
                continue
            
            mutations = set()
            mutations.update(char_transpose(param))
            mutations.update(char_delete(param))
            
            for mutation in mutations:
                if mutation in params:
                    continue  # Don't use another real parameter
                
                golden = f"{full_name}({param}=value)"
                hallucinated = f"{full_name}({mutation}=value)"
                
                samples.append({
                    "benchmark_id": f"v2-python-parameter-{package_name}-{full_name}-{param}-{mutation}",
                    "language": "python",
                    "hallucination_type": "parameter",
                    "prompt": f"# Using {package_name}\nimport {package_name}\n\n",
                    "suffix": "\n",
                    "hallucinated_completion": hallucinated,
                    "golden_completion": golden,
                    "package": package_name,
                    "mutation_strategy": classify_mutation(param, mutation),
                })
                
                if len(samples) >= max_samples:
                    break
    
    return samples


def classify_mutation(original: str, mutated: str) -> str:
    """Classify the mutation strategy used."""
    if len(original) == len(mutated) + 1:
        return "char_delete"
    elif len(original) == len(mutated) - 1:
        return "char_insert"
    elif len(original) == len(mutated):
        # Check for transposition
        diffs = sum(1 for a, b in zip(original, mutated) if a != b)
        if diffs == 2:
            return "char_transpose"
        elif diffs == 1:
            return "char_substitute"
        else:
            return "wrong_suffix"
    else:
        return "semantic_confusion"


# ─── Main ──────────────────────────────────────────────────────────────

module_obj = None  # Global for hasattr checks

def main():
    parser = argparse.ArgumentParser(description="DELULU v2 mutation engine")
    parser.add_argument("--packages", nargs="+", default=["pandas", "numpy", "requests"],
                        help="Packages to introspect")
    parser.add_argument("--output", default="delulu_v2.jsonl",
                        help="Output JSONL file")
    parser.add_argument("--count", type=int, default=200,
                        help="Max samples to generate")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed")
    args = parser.parse_args()
    
    random.seed(args.seed)
    
    all_samples = []
    
    for pkg_name in args.packages:
        global module_obj
        print(f"Introspecting {pkg_name}...", file=sys.stderr)
        try:
            module_obj = importlib.import_module(pkg_name)
        except ImportError as e:
            print(f"  SKIP: {e}", file=sys.stderr)
            continue
        
        surface = extract_api_surface(module_obj)
        print(f"  Found {len(surface)} public symbols", file=sys.stderr)
        
        per_pkg = max(1, args.count // len(args.packages))
        
        method_samples = generate_method_samples(pkg_name, surface, max_samples=per_pkg * 2)
        param_samples = generate_parameter_samples(pkg_name, surface, max_samples=per_pkg // 2)
        
        all_samples.extend(method_samples)
        all_samples.extend(param_samples)
        print(f"  Generated {len(method_samples)} method + {len(param_samples)} parameter samples", file=sys.stderr)
    
    # Shuffle and cap
    random.shuffle(all_samples)
    all_samples = all_samples[:args.count]
    
    # Write JSONL
    with open(args.output, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\nWrote {len(all_samples)} samples to {args.output}", file=sys.stderr)
    
    # Stats
    by_type = {}
    by_strategy = {}
    by_package = {}
    for s in all_samples:
        by_type[s["hallucination_type"]] = by_type.get(s["hallucination_type"], 0) + 1
        by_strategy[s.get("mutation_strategy", "unknown")] = by_strategy.get(s.get("mutation_strategy", "unknown"), 0) + 1
        by_package[s["package"]] = by_package.get(s["package"], 0) + 1
    
    print("\nBy type:", file=sys.stderr)
    for k, v in sorted(by_type.items()):
        print(f"  {k}: {v}", file=sys.stderr)
    print("\nBy strategy:", file=sys.stderr)
    for k, v in sorted(by_strategy.items()):
        print(f"  {k}: {v}", file=sys.stderr)
    print("\nBy package:", file=sys.stderr)
    for k, v in sorted(by_package.items()):
        print(f"  {k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    main()
