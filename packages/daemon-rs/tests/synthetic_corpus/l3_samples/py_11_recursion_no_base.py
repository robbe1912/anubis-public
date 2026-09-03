# Mutation L3-6: recursion without base case.
# factorial(n) calls factorial(n-1) with no termination; when n <= 0
# it recurses indefinitely (until Python's recursion limit → RecursionError).
# The LLM hallucinated the base case existed.
# Expected runtime: RecursionError: maximum recursion depth exceeded.
# Expected scanner layer: L3 (semantic logic reasoning).
def factorial(n: int) -> int:
    return n * factorial(n - 1)


print(factorial(5))
