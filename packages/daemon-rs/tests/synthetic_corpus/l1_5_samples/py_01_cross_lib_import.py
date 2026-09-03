# Mutation M1: cross-lib import.
# Real package `flask_login` exists in symbol bundle, but `LoginMgr`
# is fabricated — the real exported class is `LoginManager`.
# Expected runtime: ImportError: cannot import name 'LoginMgr' from 'flask_login'.
# Expected scanner layer: L1.5 cached-hallucination OR hallucinated-import.
from flask_login import LoginMgr


def authenticate(username: str, password: str) -> bool:
    mgr = LoginMgr()
    return mgr.check_credentials(username, password)
