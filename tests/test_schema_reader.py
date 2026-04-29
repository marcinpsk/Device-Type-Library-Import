"""Tests for core/schema_reader.py."""

import json

import pytest

from core.schema_reader import load_properties_for_type, load_scalar_properties


class TestLoadScalarProperties:
    """Tests for load_scalar_properties()."""

    def test_invalid_json_raises_value_error(self, tmp_path):
        schema_file = tmp_path / "bad.json"
        schema_file.write_text("not valid json {{{")

        with pytest.raises(ValueError, match="Invalid JSON"):
            load_scalar_properties(str(schema_file))

    def test_missing_properties_key_raises_value_error(self, tmp_path):
        schema_file = tmp_path / "noprops.json"
        schema_file.write_text('{"title": "MySchema"}')

        with pytest.raises(ValueError, match="no 'properties'"):
            load_scalar_properties(str(schema_file))

    def test_excludes_named_properties(self, tmp_path):
        schema = {
            "properties": {
                "name": {"type": "string"},
                "manufacturer": {"type": "string"},
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file), exclude={"manufacturer"})

        assert "manufacturer" not in result
        assert "name" in result

    def test_skips_array_and_object_types(self, tmp_path):
        schema = {
            "properties": {
                "tags": {"type": "array"},
                "custom_fields": {"type": "object"},
                "part_number": {"type": "string"},
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file))

        assert "tags" not in result
        assert "custom_fields" not in result
        assert "part_number" in result

    def test_includes_ref_and_scalar_properties(self, tmp_path):
        schema = {
            "properties": {
                "device_type": {"$ref": "#/definitions/DeviceType"},
                "u_height": {"type": "integer"},
                "is_full_depth": {"type": "boolean"},
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file))

        assert "device_type" in result
        assert "u_height" in result
        assert "is_full_depth" in result


class TestLoadPropertiesForType:
    """Tests for load_properties_for_type()."""

    def test_returns_empty_list_on_missing_file(self):
        result = load_properties_for_type("/nonexistent/path/to/schema", "devicetype")
        assert result == []

    def test_returns_empty_list_on_invalid_json(self, tmp_path):
        schema_file = tmp_path / "devicetype.json"
        schema_file.write_text("invalid json !!!")

        result = load_properties_for_type(str(tmp_path), "devicetype")

        assert result == []

    def test_returns_scalar_properties_from_valid_schema(self, tmp_path):
        schema = {
            "properties": {
                "part_number": {"type": "string"},
                "u_height": {"type": "integer"},
                "tags": {"type": "array"},
            }
        }
        schema_file = tmp_path / "devicetype.json"
        schema_file.write_text(json.dumps(schema))

        result = load_properties_for_type(str(tmp_path), "devicetype")

        assert "part_number" in result
        assert "u_height" in result
        assert "tags" not in result
