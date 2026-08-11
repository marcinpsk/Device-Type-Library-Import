"""Logging utilities for the Device Type Library Import tool."""

from datetime import datetime


class LogHandler:
    """Emit normal and verbose log messages for the device type import process."""

    def __init__(self, verbose: bool):
        """Initialize the sink with its verbose mode.

        Args:
            verbose: Emit verbose messages when True.
        """
        self.verbose = verbose
        self.console = None
        self._defer_depth = 0
        self._deferred_messages = []

    def _timestamp(self):
        """Return the current time formatted as HH:MM:SS."""
        return datetime.now().strftime("%H:%M:%S")

    def set_console(self, console):
        """Set the Rich Console instance used for output, or None to fall back to print()."""
        self.console = console

    def start_progress_group(self):
        """Begin a progress group that defers log output until the group ends."""
        self._defer_depth += 1

    def end_progress_group(self):
        """End the current progress group, flushing deferred messages when the depth returns to zero."""
        if self._defer_depth == 0:
            return
        self._defer_depth -= 1
        if self._defer_depth == 0 and self._deferred_messages:
            for message in self._deferred_messages:
                if self.console is not None and hasattr(self.console, "print"):
                    self.console.print(message, markup=False)
                else:
                    print(message)
            self._deferred_messages = []

    def _emit(self, message):
        """Emit *message* immediately, or defer it if inside a progress group."""
        if self._defer_depth > 0:
            self._deferred_messages.append(message)
        elif self.console is not None:
            self.console.print(message, markup=False)
        else:
            print(message)

    def verbose_log(self, message):
        """Log *message* only when verbose mode is enabled."""
        if self.verbose:
            self._emit(f"[{self._timestamp()}] {message}")

    def log(self, message):
        """Emit a timestamped log message unconditionally."""
        self._emit(f"[{self._timestamp()}] {message}")

    def log_ports_created(self, created_ports, parent_type: str, port_type: str = "port"):
        """Log creation of component templates for a device or module type.

        Args:
            created_ports (list): Port template records returned by the API.
            parent_type: ``"device"`` or ``"module"``.
            port_type (str): Human-readable port type label used in log messages.
        """
        parent_attribute = f"{parent_type}_type"
        for port in created_ports:
            self.verbose_log(
                f"{port_type} Template Created: {port.name} - "
                + f"{port.type if hasattr(port, 'type') else ''} - {getattr(port, parent_attribute).id} - "
                + f"{port.id}"
            )
