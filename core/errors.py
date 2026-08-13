"""Fatal errors shared by the command-line import workflow."""

import traceback


class FatalError(Exception):
    """An error that stops the current import run."""

    def __init__(self, message: str, *, cause=None, reason=None):
        """Store the user-facing message and format an optional exception cause."""
        if reason:
            message = f"{message} {reason.rstrip('.')}."
        super().__init__(message)
        self.formatted_traceback = "".join(traceback.format_exception(cause)) if cause is not None else None


class VendorSelectionError(FatalError):
    """A requested vendor selection that matches no source data."""


class UnknownError(FatalError):
    """An unexpected error with a stable user-facing category."""

    def __init__(self, context: str, cause=None):
        """Describe an unexpected error in *context*."""
        super().__init__(f'An unknown error occurred: "{context}"', cause=cause)
