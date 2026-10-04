"""Explicit error types. Every error carries a stable code and a UI-safe message."""


class TracewrightError(Exception):
    """Base error with a machine-readable code and a message suitable for the UI."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class StartupCheckError(TracewrightError):
    """A process refused to start because a required precondition failed."""

    def __init__(self, message: str) -> None:
        super().__init__("STARTUP_CHECK_FAILED", message)
