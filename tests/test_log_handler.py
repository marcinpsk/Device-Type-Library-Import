from types import SimpleNamespace
from inspect import signature
from unittest.mock import MagicMock, patch

from core.log_handler import LogHandler
from core.graphql_client import NetBoxGraphQLClient
from core.netbox_api import DeviceTypes, NetBox
from core.repo import DTLRepo


class TestConfiguration:
    """Tests for the sink's explicit verbose flag."""

    def test_constructor_takes_a_plain_verbose_flag(self):
        handle = LogHandler(True)

        assert handle.verbose is True
        assert not hasattr(handle, "args")
        assert not hasattr(handle, "exception")

    def test_consumers_use_one_parameter_name_for_the_sink(self):
        assert list(signature(DTLRepo).parameters)[1] == "handle"
        assert list(signature(NetBox).parameters)[1] == "handle"
        assert list(signature(DeviceTypes).parameters)[1] == "handle"
        assert "handle" in signature(NetBoxGraphQLClient).parameters


class TestSetConsole:
    """Tests for TestSetConsole."""

    def test_set_console_stores_instance(self):
        handle = LogHandler(False)
        console = MagicMock()
        handle.set_console(console)
        assert handle.console is console


class TestEmit:
    """Tests for TestEmit."""

    def test_emit_uses_console_print_when_set(self):
        handle = LogHandler(False)
        console = MagicMock()
        handle.console = console
        with patch.object(handle, "_timestamp", return_value="00:00:00"):
            handle.log("test message")
        console.print.assert_called_once_with("[00:00:00] test message", markup=False)

    def test_emit_uses_builtin_print_when_no_console(self):
        handle = LogHandler(False)
        with (
            patch.object(handle, "_timestamp", return_value="00:00:00"),
            patch("builtins.print") as mock_print,
        ):
            handle.log("test message")
        mock_print.assert_called_once_with("[00:00:00] test message")

    def test_emit_defers_when_in_progress_group(self):
        handle = LogHandler(False)
        handle.start_progress_group()
        console = MagicMock()
        handle.console = console
        with patch.object(handle, "_timestamp", return_value="00:00:00"):
            handle.log("deferred")
        console.print.assert_not_called()

    def test_end_progress_group_uses_console(self):
        handle = LogHandler(False)
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
        handle = LogHandler(False)
        handle.end_progress_group()
        assert handle._defer_depth == 0


class TestVerboseLog:
    """Tests for TestVerboseLog."""

    def test_verbose_logs_when_enabled(self):
        handle = LogHandler(True)
        with (
            patch.object(handle, "_timestamp", return_value="00:00:00"),
            patch("builtins.print") as mock_print,
        ):
            handle.verbose_log("verbose message")
        mock_print.assert_called_once_with("[00:00:00] verbose message")

    def test_verbose_does_not_log_when_disabled(self):
        handle = LogHandler(False)
        with patch("builtins.print") as mock_print:
            handle.verbose_log("should not appear")
        mock_print.assert_not_called()


class TestLogPortsCreated:
    """Tests for logging created ports for either parent type."""

    def test_device_port_logging_does_not_return_a_count(self):
        handle = LogHandler(True)
        port = SimpleNamespace(name="eth0", type="virtual", device_type=SimpleNamespace(id=5), id=10)
        with patch.object(handle, "_emit") as mock_emit:
            result = handle.log_ports_created([port], "device", "Interface")

        assert result is None
        mock_emit.assert_called_once()

    def test_module_port_logging_uses_the_module_parent(self):
        handle = LogHandler(True)
        port = SimpleNamespace(name="xe-0/0/0", type="10gbase-x-sfpp", module_type=SimpleNamespace(id=3), id=7)
        with patch.object(handle, "_emit") as mock_emit:
            handle.log_ports_created([port], "module", "Interface")

        assert " - 3 - 7" in mock_emit.call_args.args[0]


def test_progress_group_buffers_logs_until_end():
    handle = LogHandler(False)

    with (
        patch.object(handle, "_timestamp", return_value="12:00:00"),
        patch("builtins.print") as print_mock,
    ):
        handle.start_progress_group()
        handle.log("Buffered message")
        print_mock.assert_not_called()

        handle.end_progress_group()

    print_mock.assert_called_once_with("[12:00:00] Buffered message")


def test_progress_group_supports_nested_blocks():
    handle = LogHandler(False)

    with (
        patch.object(handle, "_timestamp", return_value="12:00:00"),
        patch("builtins.print") as print_mock,
    ):
        handle.start_progress_group()
        handle.start_progress_group()
        handle.log("Nested message")

        handle.end_progress_group()
        print_mock.assert_not_called()

        handle.end_progress_group()

    print_mock.assert_called_once_with("[12:00:00] Nested message")
