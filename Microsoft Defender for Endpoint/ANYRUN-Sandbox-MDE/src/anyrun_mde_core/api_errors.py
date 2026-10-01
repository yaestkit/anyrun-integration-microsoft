"""Typed API outcomes; never infer HTTP codes by parsing exception text."""


class SandboxAPIError(RuntimeError):
    def __init__(self, status_code: int, description: str):
        self.status_code = status_code
        super().__init__(f'ANY.RUN HTTP {status_code}: {description}')


class SandboxTransportError(RuntimeError):
    """The request outcome is unknown (including a possibly accepted POST)."""


class SubmissionRejected(RuntimeError):
    """A confirmed permanent rejection; no ambiguous paid task to recover."""
