# Mutation M4: parameter hallucination on a function with explicit signature.
# `requests.adapters.HTTPAdapter.__init__` takes only pool_connections,
# pool_maxsize, max_retries, pool_block — NO **kwargs. `pool_sizemax=` is
# fabricated (real param is `pool_maxsize`).
# Expected runtime: TypeError: HTTPAdapter.__init__() got an unexpected keyword argument 'pool_sizemax'.
# Expected scanner layer: L2 forge: hallucinated-parameter.
import requests.adapters

adapter = requests.adapters.HTTPAdapter(pool_sizemax=20)
