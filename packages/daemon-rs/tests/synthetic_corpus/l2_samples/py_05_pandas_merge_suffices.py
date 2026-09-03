# Mutation M4: parameter hallucination on real pandas function.
# `pandas.merge` signature is `merge(left, right, how='inner', on=None,
# left_on=None, right_on=None, left_index=False, right_index=False,
# suffixes=('_x','_y'), ...)`. `suffices` is the singular typo — should
# be `suffixes` (plural). The LLM hallucinated singular form.
# Expected runtime: TypeError: pandas.merge() got an unexpected keyword argument 'suffices'.
# Expected scanner layer: L2 forge: hallucinated-parameter.
import pandas as pd


def join_frames(left: pd.DataFrame, right: pd.DataFrame) -> pd.DataFrame:
    return pd.merge(left, right, suffices=("_l", "_r"))
