"""Build a stratified DELULU subset for anubis tests.

Picks 2 samples per (language, hallucination_type) cell where possible.
Writes delulu_subset.jsonl alongside the full dataset.
"""
import os
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
FULL = os.path.join(HERE, "delulu_full.jsonl")
SUBSET = os.path.join(HERE, "delulu_subset.jsonl")

df = pd.read_json(FULL, lines=True)
full_mb = os.path.getsize(FULL) / 1024 / 1024
print(f"full: {len(df)} rows, {full_mb:.2f} MB")

# Stratified subset: 2 per (language, hallucination_type) cell
parts = []
for (lang, htype), group in df.groupby(["language", "hallucination_type"]):
    parts.append(group.sample(min(2, len(group)), random_state=42))
subset = pd.concat(parts).reset_index(drop=True)
print(f"subset: {len(subset)} rows")
counts = subset.groupby(["language", "hallucination_type"]).size()
print(counts.to_string())

# Keep only the columns the test harness needs.
cols = [
    "benchmark_id",
    "language",
    "file_path",
    "hallucination_type",
    "prompt",
    "suffix",
    "golden_completion",
    "hallucinated_completion",
    "error_message",
]
subset[cols].to_json(SUBSET, orient="records", lines=True)
size_kb = os.path.getsize(SUBSET) / 1024
print(f"subset size: {size_kb:.1f} KB -> {SUBSET}")
