"""Custom exception class for handling extra arguments."""


from typing import Any, Dict, Optional


class SAMLAuthError(Exception):
    extra: Optional[Dict[str, Any]] = None

    def __init__(self, msg: str, extra: Optional[Dict[str, Any]] = None):
        self.message = msg
        self.extra = extra
