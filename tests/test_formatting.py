"""Tests for core/formatting.py."""

from core.formatting import _display, log_property_diffs


class TestDisplay:
    """Tests for _display() value normaliser."""

    def test_normal_string_returned_unchanged(self):
        assert _display("hello") == "hello"

    def test_whitespace_only_string_returns_None_str(self):
        assert _display("   ") == "None"

    def test_empty_string_returns_None_str(self):
        assert _display("") == "None"

    def test_none_value_returns_None_str(self):
        assert _display(None) == "None"

    def test_integer_value_returns_string(self):
        assert _display(42) == "42"

    def test_trailing_whitespace_is_stripped(self):
        assert _display("hello   ") == "hello"


class TestLogPropertyDiffs:
    """Tests for log_property_diffs()."""

    def test_emits_diff_lines_for_changes(self):
        log_fn = []
        log_property_diffs([("u_height", 1, 2)], log_fn.append)
        assert log_fn == [
            "      - u_height: 1",
            "      + u_height: 2",
        ]

    def test_empty_triples_emits_nothing(self):
        log_fn = []
        log_property_diffs([], log_fn.append)
        assert log_fn == []
