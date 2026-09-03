# Mutation M5: method-on-wrong-type. `list.flatten()` does NOT exist;
# lists must be flattened manually or via itertools.chain.from_iterable.
# Expected runtime: AttributeError: 'list' object has no attribute 'flatten'.
# Expected scanner layer: L2 forge: hallucinated-method.
def flatten(nested):
    return nested.flatten()


print(flatten([[1, 2], [3, 4]]))
