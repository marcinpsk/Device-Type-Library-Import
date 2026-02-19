import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _dt_sort_key(d):
    return (d["manufacturer"]["slug"], d["model"], d["slug"])


@pytest.fixture(scope="module")
def nb_dt_import():
    module_path = Path(__file__).resolve().parents[1] / "nb-dt-import.py"
    spec = importlib.util.spec_from_file_location("nb_dt_import", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nb_dt_import"] = module
    spec.loader.exec_module(module)
    return module


def test_filter_vendors_for_parsed_types_uses_parsed_subset(nb_dt_import):

    discovered_vendors = [
        {"name": "Cisco", "slug": "cisco"},
        {"name": "Juniper", "slug": "juniper"},
    ]
    parsed_types = [
        {"manufacturer": {"slug": "juniper"}, "model": "EX4300"},
    ]

    vendors, selected_slugs = nb_dt_import.filter_vendors_for_parsed_types(discovered_vendors, parsed_types)

    assert vendors == [{"name": "Juniper", "slug": "juniper"}]
    assert selected_slugs == {"juniper"}


def test_log_run_mode_reports_default_non_update_behavior(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=False, update=False, remove_components=False)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--update not set" in message for message in messages)
    # remove-components guidance is only shown when --update is active
    assert not any("remove-components" in message for message in messages)


def test_log_run_mode_reports_update_and_remove_enabled(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=False, update=True, remove_components=True)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--update enabled" in message for message in messages)
    assert any("--remove-components enabled" in message for message in messages)


def test_log_run_mode_reports_update_without_remove_components(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=False, update=True, remove_components=False)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--update enabled" in message for message in messages)
    assert any("will not remove components" in message for message in messages)


def test_log_run_mode_reports_only_new_enabled(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=True, update=False, remove_components=False)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--only-new enabled" in message for message in messages)


def test_should_only_create_new_modules_default_mode(nb_dt_import):
    args = SimpleNamespace(only_new=False, update=False)
    assert nb_dt_import.should_only_create_new_modules(args)


def test_should_only_create_new_modules_update_mode(nb_dt_import):
    args = SimpleNamespace(only_new=False, update=True)
    assert not nb_dt_import.should_only_create_new_modules(args)


def test_should_only_create_new_modules_only_new_flag(nb_dt_import):
    args = SimpleNamespace(only_new=True, update=True)
    assert nb_dt_import.should_only_create_new_modules(args)


def test_filter_new_device_types_by_model_and_slug(nb_dt_import):

    device_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c-renamed"},
    ]
    existing_by_model = {("cisco", "A"): object()}
    existing_by_slug = {("juniper", "c-renamed"): object()}

    filtered = nb_dt_import.filter_new_device_types(device_types, existing_by_model, existing_by_slug)

    assert filtered == [{"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"}]


def test_has_missing_device_images_detects_image_changes(nb_dt_import):

    image_change = SimpleNamespace(property_name="front_image")
    non_image_change = SimpleNamespace(property_name="part_number")
    report = SimpleNamespace(
        modified_device_types=[
            SimpleNamespace(property_changes=[non_image_change]),
            SimpleNamespace(property_changes=[image_change]),
        ]
    )

    assert nb_dt_import.has_missing_device_images(report)


def test_has_missing_device_images_returns_false_for_none_report(nb_dt_import):
    assert not nb_dt_import.has_missing_device_images(None)


def test_has_missing_device_images_returns_false_when_no_image_changes(nb_dt_import):
    report = SimpleNamespace(
        modified_device_types=[
            SimpleNamespace(property_changes=[SimpleNamespace(property_name="part_number")]),
            SimpleNamespace(property_changes=[SimpleNamespace(property_name="u_height")]),
        ]
    )

    assert not nb_dt_import.has_missing_device_images(report)


def test_select_device_types_for_default_mode_scopes_to_new_and_missing_images(nb_dt_import):
    device_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    change_report = SimpleNamespace(
        new_device_types=[
            SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a"),
        ],
        modified_device_types=[
            SimpleNamespace(
                manufacturer_slug="juniper",
                model="C",
                slug="c",
                property_changes=[SimpleNamespace(property_name="front_image")],
            ),
            SimpleNamespace(
                manufacturer_slug="cisco",
                model="B",
                slug="b",
                property_changes=[SimpleNamespace(property_name="part_number")],
            ),
        ],
    )

    selected = nb_dt_import.select_device_types_for_default_mode(device_types, change_report)

    expected = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    key = _dt_sort_key
    assert sorted(selected, key=key) == sorted(expected, key=key)


def test_select_device_types_for_update_mode_scopes_to_new_and_modified(nb_dt_import):
    device_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    change_report = SimpleNamespace(
        new_device_types=[
            SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a"),
        ],
        modified_device_types=[
            SimpleNamespace(
                manufacturer_slug="juniper",
                model="C",
                slug="c",
                property_changes=[SimpleNamespace(property_name="part_number")],
            ),
        ],
    )

    selected = nb_dt_import.select_device_types_for_update_mode(device_types, change_report)

    expected = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    key = _dt_sort_key
    assert sorted(selected, key=key) == sorted(expected, key=key)


def test_items_per_second_column_handles_empty_speed(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(SimpleNamespace(finished=False, speed=None))

    assert str(rendered) == "- it/s"


def test_items_per_second_column_renders_speed_value(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(SimpleNamespace(finished=False, speed=12.34))

    assert str(rendered) == "12.3 it/s"


def test_items_per_second_column_uses_elapsed_fallback(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(
        SimpleNamespace(
            finished=False,
            speed=None,
            completed=120,
            elapsed=10,
        )
    )

    assert str(rendered) == "12.0 it/s"


def test_items_per_second_column_uses_finished_speed_when_available(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(SimpleNamespace(finished=True, speed=None, finished_speed=5.0))

    assert str(rendered) == "5.0 it/s"


def test_items_per_second_column_uses_elapsed_fallback_when_finished_speed_missing(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(
        SimpleNamespace(
            finished=True,
            speed=None,
            finished_speed=None,
            completed=200,
            elapsed=25,
        )
    )

    assert str(rendered) == "8.0 it/s"
