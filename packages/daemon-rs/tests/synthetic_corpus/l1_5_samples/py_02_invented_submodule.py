# Mutation M2: invented submodule.
# `pydantic` is real; `pydantic.fields_extra` is fabricated (real submodules
# are `pydantic.fields`, `pydantic.main`, `pydantic.types`, `pydantic.v1`).
# Expected runtime: ModuleNotFoundError: No module named 'pydantic.fields_extra'.
# Expected scanner layer: L1.5 cached-hallucination OR hallucinated-import.
from pydantic.fields_extra import FieldSchema


class User:
    name: str
    schema: FieldSchema
