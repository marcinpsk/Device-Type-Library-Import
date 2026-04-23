from unittest.mock import MagicMock

from core.normalization import normalize_values, values_equal


class TestNormalizeValues:
    """Tests for normalize_values."""

    def test_netbox_choice_object_reads_value(self):
        choice = MagicMock()
        choice.value = "1000base-t"
        y, n = normalize_values("1000base-t", choice)
        assert n == "1000base-t"

    def test_empty_string_normalized_to_none(self):
        y, n = normalize_values("", "")
        assert y is None
        assert n is None

    def test_whitespace_only_normalized_to_none(self):
        y, n = normalize_values("   ", "\t\n")
        assert y is None
        assert n is None

    def test_trailing_whitespace_stripped(self):
        y, n = normalize_values("hello  ", "world\n")
        assert y == "hello"
        assert n == "world"

    def test_trailing_spaces_stripped(self):
        y, n = normalize_values("abc   ", "def   ")
        assert y == "abc"
        assert n == "def"

    def test_numeric_yaml_coerces_string_netbox(self):
        y, n = normalize_values(1.0, "1.0")
        assert n == 1.0

    def test_numeric_netbox_coerces_string_yaml(self):
        y, n = normalize_values("2.5", 2.5)
        assert y == 2.5

    def test_int_yaml_preserves_int_type(self):
        """YAML int 166 vs NetBox '166.00' should normalize nb to int 166, not float 166.0."""
        y, n = normalize_values(166, "166.00")
        assert n == 166
        assert isinstance(n, int)

    def test_int_netbox_preserves_int_type(self):
        y, n = normalize_values("166", 166)
        assert y == 166
        assert isinstance(y, int)

    def test_float_yaml_stays_float(self):
        y, n = normalize_values(26.1, "26.10")
        assert n == 26.1

    def test_bool_not_coerced(self):
        y, n = normalize_values(True, "1")
        assert y is True
        assert n == "1"

    def test_bool_as_int_trap(self):
        """is_full_depth=True must never compare equal to numeric string '1' or '1.0'."""
        y, n = normalize_values(True, "1.0")
        assert y is True
        assert n == "1.0"

    def test_non_numeric_string_netbox_stays_string(self):
        y, n = normalize_values(1.0, "notanumber")
        assert n == "notanumber"

    def test_non_numeric_string_yaml_stays_string(self):
        y, n = normalize_values("notanumber", 1.0)
        assert y == "notanumber"


class TestValuesEqual:
    """Tests for values_equal."""

    def test_equal_strings(self):
        assert values_equal("abc", "abc")

    def test_unequal_strings(self):
        assert not values_equal("abc", "xyz")

    def test_none_vs_empty_string(self):
        assert values_equal(None, "")

    def test_empty_string_vs_none(self):
        assert values_equal("", None)

    def test_int_vs_float_string(self):
        """NetBox returns weight as '166.00'; YAML has int 166."""
        assert values_equal(166, "166.00")

    def test_float_vs_float_string(self):
        assert values_equal(26.1, "26.10")

    def test_int_vs_float_string_different(self):
        assert not values_equal(166, "167.00")

    def test_yaml_literal_block_trailing_newline(self):
        """YAML '|' blocks append a trailing newline; NetBox strips it."""
        assert values_equal("line1\nline2\n", "line1\nline2")

    def test_both_have_trailing_newline(self):
        assert values_equal("line1\n", "line1\n")

    def test_bool_not_coerced(self):
        assert values_equal(True, True)
        assert not values_equal(True, False)

    def test_bool_as_int_trap(self):
        """Regression: True must not equal '1' or '1.0'."""
        assert not values_equal(True, "1")
        assert not values_equal(True, "1.0")

    def test_type_error_in_coercion_is_swallowed(self):
        """TypeError from float() during coercion is caught; values compare unequal."""

        class BadStr(str):
            """str subclass whose __float__ raises TypeError."""

            def __float__(self):
                raise TypeError("cannot convert")

        # yaml side is numeric, nb side is a str subclass — triggers the coercion
        # branch and calls float(nb_val), which invokes BadStr.__float__.
        assert values_equal(1, BadStr("bad")) is False
        assert values_equal(1.0, BadStr("bad")) is False
        # Sanity: normal numeric-vs-string coercion still works
        assert values_equal(1, "1") is True
        assert values_equal(1, "1.5") is False

    def test_netbox_choice_object(self):
        choice = MagicMock()
        choice.value = "kg"
        assert values_equal("kg", choice)
        choice.value = "lb"
        assert not values_equal("kg", choice)
