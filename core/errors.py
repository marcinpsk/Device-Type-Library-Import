"""Fatal errors shared by the command-line import workflow."""


class FatalError(Exception):
    """An error that stops the current import run."""

    def __init__(self, message: str, stack_trace=None):
        """Store the user-facing message and optional diagnostic detail."""
        super().__init__(message)
        self.stack_trace = stack_trace


class VendorSelectionError(FatalError):
    """A requested vendor selection that matches no source data."""


class UnknownError(FatalError):
    """An unexpected error with a stable user-facing category."""

    def __init__(self, context: str, stack_trace=None):
        """Describe an unexpected error in *context*."""
        super().__init__(f'An unknown error occurred: "{context}"', stack_trace)
