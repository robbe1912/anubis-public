# Mutation L3-1: semantic await outside async function.
# `await` is a Python keyword valid only inside `async def`. The LLM
# hallucinated that the function was async, but the def keyword is
# missing `async`. SyntaxError at parse time.
# Expected runtime: SyntaxError: 'await' outside function.
# Expected scanner layer: L3 (semantic — no API hallucination).
def fetch_user(user_id: str):
    response = await fetch_from_api(user_id)
    return response


async def fetch_from_api(user_id: str):
    return {"id": user_id, "name": "Alice"}
