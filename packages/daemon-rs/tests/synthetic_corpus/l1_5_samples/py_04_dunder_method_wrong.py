# Mutation M3: wrong kwarg on builtin dunders.
# `dict.fromkeys` signature is `fromkeys(iterable, value=None)`.
# `fill` is a hallucinated keyword argument.
# Expected runtime: TypeError: dict.fromkeys() got an unexpected keyword argument 'fill'.
# Expected scanner layer: L1.5 hallucinated-parameter OR forge: hallucinated-parameter.
def dedupe(seq):
    return dict.fromkeys(seq, fill=None)


print(dedupe(["a", "b", "a"]))
