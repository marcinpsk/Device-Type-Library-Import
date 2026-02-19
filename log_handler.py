from datetime import datetime
from sys import exit as system_exit


class LogHandler:
    """
    Handles logging and exception reporting for the device type import process.

    Provides timestamped logging methods, verbose mode support, and formatted
    error messages that terminate the program on critical failures.
    """

    def __init__(self, args):
        """
        Initialize the LogHandler with parsed arguments or a configuration object.

        Parameters:
            args: Parsed command-line arguments or a configuration object with at least a `verbose` attribute (bool);
                  stored on the instance as `self.args`.
        """
        self.args = args
        self.console = None
        self._defer_depth = 0
        self._deferred_messages = []

    def exception(self, exception_type, exception, stack_trace=None):
        """
        Handle an error by formatting a user-facing message and terminating the program.

        Parameters:
            exception_type (str): Key identifying the error category (expected keys include "EnvironmentError", "SSLError", "GitCommandError", "GitInvalidRepositoryError", "InvalidGitURL", "Exception").
            exception (str): Value used to populate the chosen error message (e.g., environment variable name, repo name, or raw error text).
            stack_trace (str | None): Optional stack trace or additional context. If provided and the instance was constructed with verbose enabled, the stack trace is printed.

        Raises:
            SystemExit: Exits the process with a formatted message corresponding to `exception_type`.
        """
        exception_dict = {
            "EnvironmentError": f'Environment variable "{exception}" is not set.',
            "SSLError": f"SSL verification failed. IGNORE_SSL_ERRORS is {exception}. Set IGNORE_SSL_ERRORS to True if you want to ignore this error. EXITING.",
            "GitCommandError": f'The repo "{exception}" is not a valid git repo.',
            "GitInvalidRepositoryError": f'The repo "{exception}" is not a valid git repo.',
            "InvalidGitURL": f"Invalid Git URL: {exception}. URL must use HTTPS or SSH protocol.",
            "Exception": f'An unknown error occurred: "{exception}"',
        }

        if self.args.verbose and stack_trace:
            print(stack_trace)

        # Raise SystemExit with the message, which will print to stderr and exit code 1
        system_exit(exception_dict[exception_type])

    def _timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def set_console(self, console):
        self.console = console

    def start_progress_group(self):
        self._defer_depth += 1

    def end_progress_group(self):
        if self._defer_depth == 0:
            return
        self._defer_depth -= 1
        if self._defer_depth == 0 and self._deferred_messages:
            for message in self._deferred_messages:
                if self.console is not None and hasattr(self.console, "print"):
                    self.console.print(message)
                else:
                    print(message)
            self._deferred_messages = []

    def _emit(self, message):
        if self._defer_depth > 0:
            self._deferred_messages.append(message)
        elif self.console is not None:
            self.console.print(message)
        else:
            print(message)

    def verbose_log(self, message):
        if self.args.verbose:
            self._emit(f"[{self._timestamp()}] {message}")

    def log(self, message):
        self._emit(f"[{self._timestamp()}] {message}")

    def log_device_ports_created(self, created_ports=None, port_type: str = "port"):
        if created_ports is None:
            created_ports = []
        for port in created_ports:
            self.verbose_log(
                f"{port_type} Template Created: {port.name} - "
                + f"{port.type if hasattr(port, 'type') else ''} - {port.device_type.id} - "
                + f"{port.id}"
            )
        return len(created_ports)

    def log_module_ports_created(self, created_ports=None, port_type: str = "port"):
        if created_ports is None:
            created_ports = []
        for port in created_ports:
            self.verbose_log(
                f"{port_type} Template Created: {port.name} - "
                + f"{port.type if hasattr(port, 'type') else ''} - {port.module_type.id} - "
                + f"{port.id}"
            )
        return len(created_ports)
