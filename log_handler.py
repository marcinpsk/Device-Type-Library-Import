from datetime import datetime
from sys import exit as system_exit


class LogHandler:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, args):
        self.args = args

    def exception(self, exception_type, exception, stack_trace=None):
        exception_dict = {
            "EnvironmentError": f'Environment variable "{exception}" is not set.',
            "SSLError": f"SSL verification failed. IGNORE_SSL_ERRORS is {exception}. Set IGNORE_SSL_ERRORS to True if you want to ignore this error. EXITING.",
            "GitCommandError": f'The repo "{exception}" is not a valid git repo.',
            "GitInvalidRepositoryError": f'The repo "{exception}" is not a valid git repo.',
            "InvalidGitURL": f'Invalid Git URL: {exception}. {stack_trace or "URL must use HTTPS or SSH protocol."}',
            "Exception": f'An unknown error occurred: "{exception}"',
        }

        if self.args.verbose and stack_trace:
            print(stack_trace)

        # Raise SystemExit with the message, which will print to stderr and exit code 1
        system_exit(exception_dict[exception_type])

    def _timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def verbose_log(self, message):
        if self.args.verbose:
            print(f"[{self._timestamp()}] {message}")

    def log(self, message):
        print(f"[{self._timestamp()}] {message}")

    def log_device_ports_created(self, created_ports: list = [], port_type: str = "port"):
        for port in created_ports:
            self.verbose_log(
                f"{port_type} Template Created: {port.name} - "
                + f'{port.type if hasattr(port, "type") else ""} - {port.device_type.id} - '
                + f"{port.id}"
            )
        return len(created_ports)

    def log_module_ports_created(self, created_ports: list = [], port_type: str = "port"):
        for port in created_ports:
            self.verbose_log(
                f"{port_type} Template Created: {port.name} - "
                + f'{port.type if hasattr(port, "type") else ""} - {port.module_type.id} - '
                + f"{port.id}"
            )
        return len(created_ports)
