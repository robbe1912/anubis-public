# Mutation L3-5: off-by-one in pandas iloc slicing.
# `df.iloc[1:-1]` drops BOTH first and last row. The LLM hallucinated
# that `iloc[1:-1]` was equivalent to `iloc[1:]` (drop first only) —
# but `-1` is interpreted as the last row, dropping it. No API error;
# the code runs but returns the wrong rows.
# Expected runtime: no error — silently returns wrong subset (semantic bug).
# Expected scanner layer: L3 (semantic).
import pandas as pd


def drop_first_row(df: pd.DataFrame) -> pd.DataFrame:
    return df.iloc[1:-1]
