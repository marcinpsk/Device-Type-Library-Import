import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.log_handler import LogHandler


class TestException:
    """Tests for TestException."""

    def test_environment_error_exits(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with pytest.raises(SystemExit) as exc_info:
            handle.exception("EnvironmentError", "NETBOX_URL")
        assert "NETBOX_URL" in str(exc_info.value)

    def test_ssl_error_exits(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with pytest.raises(SystemExit):
            handle.exception("SSLError", "False")

    def test_git_command_error_exits(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with pytest.raises(SystemExit):
            handle.exception("GitCommandError", "my-repo")

    def test_git_invalid_repo_exits(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with pytest.raises(SystemExit):
            handle.exception("GitInvalidRepositoryError", "my-repo")

    def test_invalid_git_url_exits(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with pytest.raises(SystemExit):
            handle.exception("InvalidGitURL", "ftp://bad")

    def test_generic_exception_exits(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with pytest.raises(SystemExit):
            handle.exception("Exception", "something bad")

    def test_verbose_prints_stack_trace(self):
        handle = LogHandler(SimpleNamespace(verbose=True))
        with patch("builtins.print") as mock_print, pytest.raises(SystemExit):
            handle.exception("Exception", "err", stack_trace="Traceback...")
        mock_print.assert_called_once_with("Traceback...")

    def test_verbose_false_does_not_print_stack_trace(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with patch("builtins.print") as mock_print, pytest.raises(SystemExit):
            handle.exception("Exception", "err", stack_trace="Traceback...")
        mock_print.assert_not_called()


class TestSetConsole:
    """Tests for TestSetConsole."""

    def test_set_console_stores_instance(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        console = MagicMock()
        handle.set_console(console)
        assert handle.console is console


class TestEmit:
    """Tests for TestEmit."""

    def test_emit_uses_console_print_when_set(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        console = MagicMock()
        handle.console = console
        with patch.object(handle, "_timestamp", return_value="00:00:00"):
            handle.log("test message")
        console.print.assert_called_once_with("[00:00:00] test message", markup=False)

    def test_emit_uses_builtin_print_when_no_console(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with patch.object(handle, "_timestamp", return_value="00:00:00"), patch("builtins.print") as mock_print:
            handle.log("test message")
        mock_print.assert_called_once_with("[00:00:00] test message")

    def test_emit_defers_when_in_progress_group(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        handle.start_progress_group()
        console = MagicMock()
        handle.console = console
        with patch.object(handle, "_timestamp", return_value="00:00:00"):
            handle.log("deferred")
        console.print.assert_not_called()

    def test_end_progress_group_uses_console(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        console = MagicMock()
        handle.console = console
        handle.start_progress_group()
        with patch.object(handle, "_timestamp", return_value="00:00:00"):
            handle.log("flushed via console")
            handle.end_progress_group()
        console.print.assert_called_once_with("[00:00:00] flushed via console", markup=False)


class TestEndProgressGroupEdgeCases:
    """Tests for TestEndProgressGroupEdgeCases."""

    def test_end_at_zero_depth_is_noop(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        handle.end_progress_group()
        assert handle._defer_depth == 0


class TestVerboseLog:
    """Tests for TestVerboseLog."""

    def test_verbose_logs_when_enabled(self):
        handle = LogHandler(SimpleNamespace(verbose=True))
        with patch.object(handle, "_timestamp", return_value="00:00:00"), patch("builtins.print") as mock_print:
            handle.verbose_log("verbose message")
        mock_print.assert_called_once_with("[00:00:00] verbose message")

    def test_verbose_does_not_log_when_disabled(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        with patch("builtins.print") as mock_print:
            handle.verbose_log("should not appear")
        mock_print.assert_not_called()


class TestLogDevicePortsCreated:
    """Tests for TestLogDevicePortsCreated."""

    def test_returns_count(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        ports = []
        for i in range(2):
            p = MagicMock()
            p.name = f"port{i}"
            p.device_type = MagicMock(id=1)
            p.id = i
            ports.append(p)
        result = handle.log_device_ports_created(ports, "Interface")
        assert result == 2

    def test_returns_zero_for_none(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        assert handle.log_device_ports_created(None) == 0

    def test_verbose_logs_each_port(self):
        handle = LogHandler(SimpleNamespace(verbose=True))
        port = MagicMock()
        port.name = "eth0"
        port.type = "virtual"
        port.device_type = MagicMock(id=5)
        port.id = 10
        with patch.object(handle, "_emit") as mock_emit:
            handle.log_device_ports_created([port], "Interface")
        assert mock_emit.called


class TestLogModulePortsCreated:
    """Tests for TestLogModulePortsCreated."""

    def test_returns_count(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        port = MagicMock()
        port.name = "port"
        port.module_type = MagicMock(id=1)
        port.id = 1
        result = handle.log_module_ports_created([port], "Interface")
        assert result == 1

    def test_returns_zero_for_none(self):
        handle = LogHandler(SimpleNamespace(verbose=False))
        assert handle.log_module_ports_created(None) == 0

    def test_verbose_logs_each_port(self):
        handle = LogHandler(SimpleNamespace(verbose=True))
        port = MagicMock()
        port.name = "xe-0/0/0"
        port.type = "10gbase-x-sfpp"
        port.module_type = MagicMock(id=3)
        port.id = 7
        with patch.object(handle, "_emit") as mock_emit:
            handle.log_module_ports_created([port], "Interface")
        assert mock_emit.called


def test_progress_group_buffers_logs_until_end():
    handle = LogHandler(SimpleNamespace(verbose=False))

    with patch.object(handle, "_timestamp", return_value="12:00:00"), patch("builtins.print") as print_mock:
        handle.start_progress_group()
        handle.log("Buffered message")
        print_mock.assert_not_called()

        handle.end_progress_group()

    print_mock.assert_called_once_with("[12:00:00] Buffered message")


def test_progress_group_supports_nested_blocks():
    handle = LogHandler(SimpleNamespace(verbose=False))

    with patch.object(handle, "_timestamp", return_value="12:00:00"), patch("builtins.print") as print_mock:
        handle.start_progress_group()
        handle.start_progress_group()
        handle.log("Nested message")

        handle.end_progress_group()
        print_mock.assert_not_called()

        handle.end_progress_group()

    print_mock.assert_called_once_with("[12:00:00] Nested message")
