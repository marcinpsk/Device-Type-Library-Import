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

    def test_non_object_schema_root_raises_value_error(self, tmp_path):
        """A JSON array or scalar at the schema root must raise ValueError."""
        schema_file = tmp_path / "array_root.json"
        schema_file.write_text('[{"type": "string"}]')

        with pytest.raises(ValueError, match="root is not a JSON object"):
            load_scalar_properties(str(schema_file))

    def test_non_dict_property_entry_is_skipped(self, tmp_path):
        """Malformed property entries (non-dict) must be silently skipped."""
        schema = {
            "properties": {
                "valid_prop": {"type": "string"},
                "broken_prop": None,
                "also_broken": "shorthand",
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file))

        assert "valid_prop" in result
        assert "broken_prop" not in result
        assert "also_broken" not in result

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

    def test_skips_property_with_no_type_and_no_ref(self, tmp_path):
        """Properties with no recognisable type (no $ref, no 'type' key) are excluded."""
        schema = {
            "properties": {
                "weird_prop": {"description": "no type at all"},
                "part_number": {"type": "string"},
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file))

        assert "weird_prop" not in result
        assert "part_number" in result

    def test_skips_anyof_and_oneof_properties(self, tmp_path):
        """anyOf/oneOf properties are excluded — their resolved type is unpredictable."""
        schema = {
            "properties": {
                "poly_prop": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                "union_prop": {"oneOf": [{"type": "integer"}, {"$ref": "#/defs/X"}]},
                "model": {"type": "string"},
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file))

        assert "poly_prop" not in result
        assert "union_prop" not in result
        assert "model" in result

    def test_includes_nullable_scalar_union_type(self, tmp_path):
        """A 'type' list whose members are all scalar types is included."""
        schema = {
            "properties": {
                "weight": {"type": ["number", "null"]},
                "label": {"type": ["string", "null"]},
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file))

        assert "weight" in result
        assert "label" in result

    def test_skips_type_union_containing_array_or_object(self, tmp_path):
        """A 'type' list that mixes scalars with array/object is excluded."""
        schema = {
            "properties": {
                "mixed": {"type": ["string", "array"]},
                "obj_or_null": {"type": ["object", "null"]},
                "valid": {"type": "string"},
            }
        }
        schema_file = tmp_path / "schema.json"
        schema_file.write_text(json.dumps(schema))

        result = load_scalar_properties(str(schema_file))

        assert "mixed" not in result
        assert "obj_or_null" not in result
        assert "valid" in result


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
