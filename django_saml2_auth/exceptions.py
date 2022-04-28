"""Custom exception class for handling extra arguments."""


from typing import Any, Dict, Optional


class SAMLAuthError(Exception):
    """Custom exception class for handling extra arguments."""

    extra: Optional[Dict[str, Any]] = None

    def __init__(self, msg: str, extra: Optional[Dict[str, Any]] = None):
        """Initialize exception class.

        Args:
            msg (str): Exception message.
            extra (Optional[Dict[str, Any]], optional): Extra arguments.
                Defaults to None.
        """
        self.message = msg
        self.extra = extra
