# Mutation M5: method-on-wrong-type. str has no to_uppercase method.
# Real method is `str.upper()`. `to_uppercase` is borrowed from Rust's
# naming convention — fabricated in Python.
# Expected runtime: AttributeError: 'str' object has no attribute 'to_uppercase'.
# Expected scanner layer: L2 forge: hallucinated-method.
def shout(text: str) -> str:
    return text.to_uppercase()


print(shout("hello"))
