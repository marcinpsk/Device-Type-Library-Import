"""Tests for core.settings module."""

import os
import pytest
from unittest.mock import patch


class TestParsePositiveInt:
    """Tests for TestParsePositiveInt."""

    def test_returns_default_when_unset(self):
        from core.settings import _parse_positive_int

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TEST_VAR", None)
            result = _parse_positive_int("TEST_VAR", 42)
        assert result == 42

    def test_returns_parsed_value(self):
        from core.settings import _parse_positive_int

        with patch.dict(os.environ, {"TEST_VAR": "10"}):
            result = _parse_positive_int("TEST_VAR", 99)
        assert result == 10

    def test_raises_on_non_numeric(self):
        from core.settings import _parse_positive_int

        with patch.dict(os.environ, {"TEST_VAR": "abc"}):
            with pytest.raises(ValueError, match="must be a positive integer"):
                _parse_positive_int("TEST_VAR", 5)

    def test_raises_on_zero(self):
        from core.settings import _parse_positive_int

        with patch.dict(os.environ, {"TEST_VAR": "0"}):
            with pytest.raises(ValueError, match=">= 1"):
                _parse_positive_int("TEST_VAR", 5)

    def test_raises_on_negative(self):
        from core.settings import _parse_positive_int

        with patch.dict(os.environ, {"TEST_VAR": "-3"}):
            with pytest.raises(ValueError, match=">= 1"):
                _parse_positive_int("TEST_VAR", 5)
