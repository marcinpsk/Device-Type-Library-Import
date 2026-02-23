from types import SimpleNamespace
from unittest.mock import patch

from core.log_handler import LogHandler


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
