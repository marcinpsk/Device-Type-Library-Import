#!/usr/bin/env python3
"""Entry-point script for importing NetBox device and module types from the community library."""

from datetime import datetime
import os
from argparse import ArgumentParser
from contextlib import contextmanager

from core import settings
from core.netbox_api import NetBox, _fmt_connection_error
from core.log_handler import LogHandler
from core.repo import DTLRepo
from core.change_detector import ChangeDetector, ChangeType, IMAGE_PROPERTIES
from core.graphql_client import GraphQLError
from pynetbox.core.query import RequestError as NetBoxRequestError
import re
import requests


import sys
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    ProgressBar,
    ProgressColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text


_PROGRESS_DESC_WIDTH = 28  # Longest: "Caching Console Server Ports"


class NoPulseBarColumn(BarColumn):
    """BarColumn that never pulses — shows a static empty bar when total is unknown.

    Rich's default BarColumn sets ``pulse=True`` whenever ``task.total is None``,
    which produces a scrolling rainbow-gradient animation.  That causes a
    continuous stream of ANSI color codes on every render frame, creating a
    distracting "disco" effect on the terminal.  This subclass always passes
    ``pulse=False`` so the bar stays static when total is unknown.
    """

    def render(self, task):
        """Render a static progress bar (no pulsing gradient).

        Rich's ProgressBar triggers pulse when ``total is None`` regardless of
        the ``pulse`` flag (``should_pulse = self.pulse or self.total is None``).
        When total is unknown we substitute total=1, completed=0 to get a plain
        static empty bar instead of the scrolling rainbow gradient.
        """
        if task.total is None:
            total: float = 1.0
            completed: float = 0.0
        else:
            total = max(0.0, task.total)
            completed = max(0.0, task.completed)
        return ProgressBar(
            total=total,
            completed=completed,
            width=None if self.bar_width is None else max(1, self.bar_width),
            pulse=False,
            animation_time=task.get_time(),
            style=self.style,
            complete_style=self.complete_style,
            finished_style=self.finished_style,
            pulse_style=self.pulse_style,
        )


class MyProgress(Progress):
    """Rich Progress subclass that renders each task table inside a bordered Panel."""

    def get_renderables(self):
        """Yield a Panel wrapping the tasks table for display inside a bordered box."""
        yield Panel(self.make_tasks_table(self.tasks))


class ItemsPerSecondColumn(ProgressColumn):
    """Custom Rich ProgressColumn that displays processing speed in items per second."""

    @staticmethod
    def _effective_speed(task, primary_attr):
        """Return the effective speed for *task*, falling back to elapsed/completed if *primary_attr* is unavailable."""
        speed = getattr(task, primary_attr, None)
        if speed is not None:
            return speed
        elapsed = getattr(task, "elapsed", None)
        completed = getattr(task, "completed", 0)
        if elapsed and completed:
            return completed / elapsed
        return None

    def render(self, task):
        """Render the current or finished speed as a ``Text`` object (e.g. ``"12.3 it/s"``)."""
        if task.finished:
            speed = self._effective_speed(task, "finished_speed")
        else:
            speed = self._effective_speed(task, "speed")
        if speed is None:
            return Text("- it/s")
        return Text(f"{speed:.1f} it/s")


@contextmanager
def get_progress_panel(show_remaining_time=False):
    """Context manager that yields a MyProgress instance when stdout is a TTY, otherwise yields None.

    Args:
        show_remaining_time (bool): If True, appends a TimeRemainingColumn to the progress bar.

    Yields:
        MyProgress | None: Progress instance for TTY contexts; None for non-TTY (e.g. piped output).
    """
    if not sys.stdout.isatty():
        yield None
        return

    columns = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        NoPulseBarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        ItemsPerSecondColumn(),
    ]
    if show_remaining_time:
        columns.append(TimeRemainingColumn())

    with MyProgress(
        *columns,
        refresh_per_second=4,
    ) as progress:
        yield progress


def get_progress_wrapper(progress, iterable, desc=None, total=None, on_step=None, task_registry=None):
    """Wrap *iterable* with a Rich progress task if *progress* is provided, otherwise return *iterable* unchanged.

    Args:
        progress: A MyProgress instance (or compatible), or None to disable tracking.
        iterable: The iterable to wrap.
        desc (str | None): Task description shown in the progress bar.
        total (int | None): Total number of items; inferred from ``len(iterable)`` if omitted.
        on_step (callable | None): Optional callback invoked after each item and at the end.
        task_registry (dict | None): When provided, tasks are created once per description and
            reused across calls — counts accumulate rather than resetting per vendor. The caller
            is responsible for stopping/removing tasks at the end of the run.

    Returns:
        The original iterable if *progress* is None, otherwise a generator that advances
        the progress task as items are consumed.
    """
    if progress is None:
        return iterable

    description = (desc or "").ljust(_PROGRESS_DESC_WIDTH)
    if total is None:
        try:
            total = len(iterable)
        except TypeError:
            total = None

    if task_registry is not None:
        # Cumulative mode: create the task once, reuse it across vendors.
        # NOTE: `total` is intentionally ignored here — the final count is
        # unknown at task-creation time and is resolved during finalization.
        if description not in task_registry:
            task_registry[description] = progress.add_task(description, total=None)
        task_id = task_registry[description]
    else:
        task_id = progress.add_task(description, total=total)

    def iterator():
        """Yield items from *iterable* while advancing the progress task."""
        count = 0
        try:
            for item in iterable:
                yield item
                count += 1
                progress.advance(task_id)
                if on_step:
                    on_step()
        finally:
            if task_registry is None:
                # Non-cumulative: finalize and clean up this vendor's task.
                if total is None:
                    progress.update(task_id, total=max(count, 1), completed=count)
                progress.stop_task(task_id)
                progress.remove_task(task_id)
            if on_step:
                on_step()

    return iterator()


def filter_new_device_types(device_types, existing_by_model, existing_by_slug):
    """Return device types that do not already exist in NetBox.

    Looks up each device type by ``(manufacturer_slug, model)`` first, then by
    ``(manufacturer_slug, slug)`` as a fallback.

    Args:
        device_types (list[dict]): Parsed YAML device-type dicts to filter.
        existing_by_model (dict): Mapping of ``(manufacturer_slug, model)`` -> NetBox record.
        existing_by_slug (dict): Mapping of ``(manufacturer_slug, slug)`` -> NetBox record.

    Returns:
        list[dict]: Device types not found in either lookup.
    """
    new_device_types = []
    for device_type in device_types:
        manufacturer_slug = device_type["manufacturer"]["slug"]
        model = device_type["model"]
        slug = device_type.get("slug", "")

        existing = existing_by_model.get((manufacturer_slug, model))
        if existing is None and slug:
            existing = existing_by_slug.get((manufacturer_slug, slug))

        if existing is None:
            new_device_types.append(device_type)

    return new_device_types


def _device_type_change_key(manufacturer_slug, model, slug):
    """Build a canonical change-detection key tuple from individual components."""
    return manufacturer_slug, model, slug or ""


def device_type_key(device_type):
    """Extract the change-detection key from a parsed device-type dict."""
    return _device_type_change_key(
        device_type["manufacturer"]["slug"],
        device_type["model"],
        device_type.get("slug", ""),
    )


def change_entry_key(change_entry):
    """Extract the change-detection key from a DeviceTypeChange entry."""
    return _device_type_change_key(
        change_entry.manufacturer_slug,
        change_entry.model,
        change_entry.slug,
    )


def filter_device_types_by_change_keys(device_types, change_keys):
    """Return only those *device_types* whose key is present in *change_keys*.

    Args:
        device_types (list[dict]): Parsed device-type dicts to filter.
        change_keys (set): Set of change-detection keys to match against.

    Returns:
        list[dict]: Subset of device_types whose key appears in change_keys.
    """
    if not change_keys:
        return []
    return [device_type for device_type in device_types if device_type_key(device_type) in change_keys]


def _device_types_with_images_keys(device_types):
    """Return the set of change-detection keys for device types that declare images in their YAML.

    Used by ``--verify-images`` to ensure image-bearing device types are processed even
    when the change detector reports them as unchanged (e.g. image exists in the DB but the
    physical file is gone from the server).

    Args:
        device_types (list[dict]): All parsed device-type dicts.

    Returns:
        set: Keys of device types that have ``front_image`` or ``rear_image`` set to True.
    """
    return {device_type_key(dt) for dt in device_types if dt.get("front_image") or dt.get("rear_image")}


def select_device_types_for_default_mode(device_types, change_report, verify_images=False):
    """Select device types to process in default (non-update) mode.

    Includes newly discovered device types and existing ones with missing images.
    When *verify_images* is True, also includes all device types that declare images
    so their physical presence can be verified.

    Args:
        device_types (list[dict]): All parsed device-type dicts.
        change_report (ChangeReport | None): Change detection results; if None returns [].
        verify_images (bool): When True, include image-bearing device types for physical
            verification even if no DB-level change is detected.

    Returns:
        list[dict]: Device types that are new or have missing images.
    """
    if not change_report:
        return []

    new_keys = {change_entry_key(change) for change in change_report.new_device_types}
    image_change_keys = {
        change_entry_key(change)
        for change in change_report.modified_device_types
        if any(property_change.property_name in IMAGE_PROPERTIES for property_change in change.property_changes)
    }
    all_keys = new_keys | image_change_keys
    if verify_images:
        all_keys |= _device_types_with_images_keys(device_types)
    return filter_device_types_by_change_keys(device_types, all_keys)


def select_device_types_for_update_mode(device_types, change_report, verify_images=False):
    """Select device types to process in update (``--update``) mode.

    Includes all new and modified device types.  When *verify_images* is True, also
    includes device types that declare images so their physical presence can be checked.

    Args:
        device_types (list[dict]): All parsed device-type dicts.
        change_report (ChangeReport | None): Change detection results; if None returns [].
        verify_images (bool): When True, include image-bearing device types for physical
            verification even if no DB-level change is detected.

    Returns:
        list[dict]: Device types that are either new or have detected changes.
    """
    if not change_report:
        return []

    actionable_keys = {change_entry_key(change) for change in change_report.new_device_types}
    actionable_keys.update(change_entry_key(change) for change in change_report.modified_device_types)
    if verify_images:
        actionable_keys |= _device_types_with_images_keys(device_types)
    return filter_device_types_by_change_keys(device_types, actionable_keys)


def has_missing_device_images(change_report):
    """Return True if any modified device type has at least one missing image.

    Args:
        change_report (ChangeReport | None): Change detection results.

    Returns:
        bool: True if there is at least one image-related property change; False otherwise.
    """
    if not change_report:
        return False
    for device_change in change_report.modified_device_types:
        if any(pc.property_name in IMAGE_PROPERTIES for pc in device_change.property_changes):
            return True
    return False


def log_run_mode(handle, args):
    """Log a human-readable summary of the active run-mode flags to *handle*.

    Args:
        handle (LogHandler): Logging handler used to emit messages.
        args: Parsed CLI arguments; inspects ``only_new``, ``update``, and ``remove_components``.
    """
    if args.only_new:
        handle.log("Mode: --only-new enabled; existing device types and components will not be modified.")
    elif args.update:
        handle.log("Mode: --update enabled; changed properties and components on existing models will be updated.")
        if args.remove_components:
            handle.log("Mode: --remove-components enabled; missing components will be removed from existing models.")
            if getattr(args, "remove_unmanaged_types", False):
                handle.log(
                    "Mode: --remove-unmanaged-types enabled; components whose entire YAML section is missing "
                    "will also be removed from existing models."
                )
        else:
            handle.log(
                "Mode: will not remove components from existing models; use --remove-components with "
                "--update to change this."
            )
        if getattr(args, "force_resolve_conflicts", False):
            handle.log(
                "Mode: --force-resolve-conflicts enabled; constraint failures will trigger destructive "
                "remediation when no live device references the affected type."
            )
    else:
        handle.log("Mode: --update not set; changed properties/components will not be applied (use --update).")
    if getattr(args, "verify_images", False):
        handle.log(
            "Mode: --verify-images enabled; images already recorded in NetBox will be verified via HTTP "
            "and re-uploaded if missing or content has changed."
        )


def should_only_create_new_modules(args):
    """Return True if module processing should only create new entries and skip updates."""
    return args.only_new or not args.update


@contextmanager
def _image_progress_scope(progress, device_types, total=0):
    """Context manager that wires up image-upload progress tracking.

    Creates a progress task (if *progress* is not None and *total* > 0),
    assigns the advance callback to ``device_types._image_progress``, and
    always resets it to ``None`` on exit — even on exception.  The task is
    removed from the progress display on exit so completed upload bars do not
    accumulate when multiple vendors are processed in sequence.

    Args:
        progress: Rich Progress instance, or None.
        device_types: ``DeviceTypes`` helper whose ``_image_progress`` callback is set.
        total (int): Pre-counted number of images to upload. If 0, no progress bar is shown.
    """
    _img_task = None
    if progress is not None and total > 0:
        _img_task = progress.add_task("Uploading Images", total=total)

        def _adv_img(count=1):
            """Advance the image-upload progress task by *count* steps."""
            progress.update(_img_task, advance=count)

        device_types._image_progress = _adv_img
    try:
        yield
    finally:
        device_types._image_progress = None
        if progress is not None and _img_task is not None:
            progress.stop_task(_img_task)
            progress.remove_task(_img_task)


def _check_env_vars(handle):
    """Validate that all mandatory environment variables are set.

    Calls ``handle.exception`` (which exits) for the first missing variable.

    Args:
        handle (LogHandler): Logging handler used to report and exit on error.
    """
    for var in settings.MANDATORY_ENV_VARS:
        if not os.environ.get(var, "").strip():
            handle.exception(
                "EnvironmentError",
                var,
                f'Environment variable "{var}" is not set or is empty.'
                f"\n\nMANDATORY_ENV_VARS: {str(settings.MANDATORY_ENV_VARS)}\n",
            )


def _log_import_filters(handle, args):
    """Log active vendor and slug filter choices to *handle*.

    Args:
        handle (LogHandler): Logging handler used to emit filter messages.
        args: Parsed CLI arguments; inspects ``vendors`` and ``slugs``.
    """
    if args.vendors:
        handle.log(f"Importing vendors: {', '.join(args.vendors)}")
    if args.slugs:
        handle.log(f"Filtering by slugs: {', '.join(args.slugs)}")


def _process_device_types(
    args,
    netbox,
    handle,
    progress,
    device_types,
    cache_preload_job,
    vendor_slug=None,
    task_registry=None,
):
    """Process device types according to the active run mode.

    Handles *only_new*, *update*, and default mode device-type processing,
    including cache preloading, change detection, and NetBox API calls.

    Args:
        args: Parsed CLI arguments; inspects ``only_new``, ``update``, and
            ``remove_components``.
        netbox (NetBox): NetBox API wrapper instance.
        handle (LogHandler): Logging handler used to emit progress messages.
        progress: Rich Progress instance for progress display, or None.
        device_types (list[dict]): Parsed device-type dicts to process.
        cache_preload_job: Background component-cache preload job, or None.
        vendor_slug (str | None): Manufacturer slug for scoped integrity checks.
        task_registry (dict | None): Shared cumulative progress task registry.

    Returns:
        The updated *cache_preload_job*: ``None`` if the job was consumed by
        ``preload_all_components``; otherwise the original value.
    """
    if args.only_new:
        new_device_types = filter_new_device_types(
            device_types,
            netbox.device_types.existing_device_types,
            netbox.device_types.existing_device_types_by_slug,
        )
        if new_device_types:
            image_total = netbox.count_device_type_images(new_device_types)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    new_device_types,
                    progress=get_progress_wrapper(
                        progress,
                        new_device_types,
                        desc="Creating Device Types",
                        task_registry=task_registry,
                    ),
                    only_new=True,
                )
        else:
            handle.verbose_log("No new device types to create.")
        return cache_preload_job

    # Non-only_new path: always consume the preload job if one was started.
    # This is required even when device_types is empty (e.g. module-type-only vendor)
    # so that _global_preload_done is set before _process_module_types runs.
    if cache_preload_job is not None:
        handle.verbose_log("Caching NetBox data for comparison (concurrent API requests started after parsing)...")
        netbox.device_types.preload_all_components(
            progress=progress,
            preload_job=cache_preload_job,
            manufacturer_slug=vendor_slug,
            task_registry=task_registry,
        )
        cache_preload_job = None

    if not device_types:
        handle.verbose_log("No device types matched filters.")

    detector = ChangeDetector(
        netbox.device_types,
        handle,
        remove_unmanaged_types=args.remove_unmanaged_types,
    )
    change_report = detector.detect_changes(
        device_types,
        progress=get_progress_wrapper(progress, device_types, desc="Detecting Changes", task_registry=task_registry),
    )
    detector.log_change_report(change_report)

    if args.update:
        device_types_to_process = select_device_types_for_update_mode(
            device_types, change_report, verify_images=getattr(args, "verify_images", False)
        )
        if device_types_to_process:
            image_total = netbox.count_device_type_images(device_types_to_process)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    device_types_to_process,
                    progress=get_progress_wrapper(
                        progress,
                        device_types_to_process,
                        desc="Processing Device Types",
                        task_registry=task_registry,
                    ),
                    only_new=False,
                    update=True,
                    change_report=change_report,
                    remove_components=args.remove_components,
                )
        else:
            handle.verbose_log("No device type changes to process.")
    else:
        device_types_to_process = select_device_types_for_default_mode(
            device_types, change_report, verify_images=getattr(args, "verify_images", False)
        )
        if device_types_to_process:
            image_total = netbox.count_device_type_images(device_types_to_process)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    device_types_to_process,
                    progress=get_progress_wrapper(
                        progress,
                        device_types_to_process,
                        desc="Creating Device Types",
                        task_registry=task_registry,
                    ),
                    only_new=True,
                )
        else:
            handle.verbose_log("No new device types or missing images to process.")

    return cache_preload_job


def _process_module_types(args, netbox, handle, progress, module_types, task_registry=None):
    """Process module types for a single vendor.

    Args:
        args: Parsed CLI arguments; inspects ``only_new``, ``update``, and
            ``remove_components``.
        netbox (NetBox): NetBox API wrapper instance.
        handle (LogHandler): Logging handler used to emit progress messages.
        progress: Rich Progress instance for progress display, or None.
        module_types (list[dict]): Pre-parsed module-type dicts for this vendor.
        task_registry (dict | None): Shared cumulative progress task registry.
    """
    if not module_types:
        return

    handle.verbose_log(f"{len(module_types)} Module-Types Found")

    module_only_new = should_only_create_new_modules(args)
    existing_module_types = netbox.get_existing_module_types()
    # Always run full change detection (unless --only-new is explicitly set) so that
    # modified module types are reported even without --update.
    module_types_to_process, module_type_existing_images, changed_property_log = netbox.filter_actionable_module_types(
        module_types,
        existing_module_types,
        only_new=args.only_new,
    )

    new_module_count = len(NetBox.filter_new_module_types(module_types, existing_module_types))
    # Count modules whose only diff is REMOVED components — they will require
    # --remove-components to converge.  We count groups that have at least one removed
    # component change; the advisory is informational so over-counting modules that also
    # have other changes is fine.
    pending_removal_modules = 0
    pending_removal_components = 0
    for _slug, _model, fields_info, comp_changes in changed_property_log:
        removed_in_group = [
            c for c in (comp_changes or []) if getattr(c, "change_type", None) == ChangeType.COMPONENT_REMOVED
        ]
        if removed_in_group:
            pending_removal_modules += 1
            pending_removal_components += len(removed_in_group)

    module_changed_count = len(changed_property_log)
    module_unchanged_count = len(module_types) - len(module_types_to_process) if not args.only_new else 0

    has_module_changes = new_module_count > 0 or module_changed_count > 0 or pending_removal_modules > 0
    if has_module_changes:
        handle.log("============================================================")
        handle.log("MODULE TYPE CHANGE DETECTION")
        handle.log("============================================================")
        if args.only_new:
            handle.log(f"New module types: {new_module_count}")
        else:
            # Modules with only missing image attachments — handled in default mode, so
            # they are NOT included in the "modified" count and do NOT trigger the
            # `--update` hint.
            image_only_count = max(0, len(module_types_to_process) - new_module_count - module_changed_count)
            handle.log(f"New module types:       {new_module_count}")
            handle.log(f"Unchanged module types: {module_unchanged_count}")
            handle.log(f"Modified module types:  {module_changed_count}")
            if image_only_count:
                handle.log(f"Image-only updates:     {image_only_count}")
            if module_changed_count and not args.update:
                handle.log("  (Run with --update to apply changes to existing module types)")
            if pending_removal_modules and not args.remove_components:
                remove_hint = "--remove-components" if args.update else "--update --remove-components"
                handle.log(
                    f"  (Run with {remove_hint} to remove {pending_removal_components} stale "
                    f"component(s) across {pending_removal_modules} module type(s))"
                )
        handle.log("------------------------------------------------------------")
        netbox.log_module_type_changes(changed_property_log)
    elif module_unchanged_count:
        handle.verbose_log(f"No module type changes ({module_unchanged_count} unchanged).")

    if module_types_to_process:
        module_image_total = netbox.count_module_type_images(
            module_types_to_process, existing_module_types, module_type_existing_images
        )
        with _image_progress_scope(progress, netbox.device_types, total=module_image_total):
            netbox.create_module_types(
                module_types_to_process,
                progress=get_progress_wrapper(
                    progress,
                    module_types_to_process,
                    desc="Processing Module Types",
                    task_registry=task_registry,
                ),
                only_new=module_only_new,
                all_module_types=existing_module_types,
                module_type_existing_images=module_type_existing_images,
                remove_components=args.remove_components,
            )
    else:
        handle.verbose_log("No module type changes to process.")


def _process_rack_types(args, netbox, handle, progress, rack_types, task_registry=None):
    """Process rack types for a single vendor.

    Soft-skips with a warning when the connected NetBox instance is older than 4.1.

    Args:
        args: Parsed CLI arguments; inspects ``only_new``.
        netbox (NetBox): NetBox API wrapper instance.
        handle (LogHandler): Logging handler used to emit progress messages.
        progress: Rich Progress instance for progress display, or None.
        rack_types (list[dict]): Pre-parsed rack-type dicts for this vendor.
        task_registry (dict | None): Shared cumulative progress task registry.
    """
    if not rack_types:
        return

    if not netbox.rack_types:
        handle.log("Rack types require NetBox >= 4.1. Skipping rack type import.")
        return

    handle.verbose_log(f"{len(rack_types)} Rack-Types Found")

    all_rack_types = netbox.get_existing_rack_types()
    new_count = sum(
        1
        for rt in rack_types
        if all_rack_types.get(rt.get("manufacturer", {}).get("slug", ""), {}).get(rt.get("model")) is None
    )
    existing_count = len(rack_types) - new_count

    if new_count == 0:
        handle.verbose_log(f"No new rack types ({existing_count} unchanged).")
    else:
        handle.log("============================================================")
        handle.log(f"New rack types:       {new_count}")
        handle.log(f"Existing rack types:  {existing_count}")
        handle.log("============================================================")

    if rack_types:
        netbox.create_rack_types(
            rack_types,
            progress=get_progress_wrapper(
                progress,
                rack_types,
                desc="Processing Rack Types",
                task_registry=task_registry,
            ),
            only_new=args.only_new,
            all_rack_types=all_rack_types,
        )


def _log_run_summary(handle, netbox, start_time, dtl_repo=None):
    """Log the final import summary counters to *handle*.

    Args:
        handle (LogHandler): Logging handler for output.
        netbox (NetBox): NetBox API wrapper whose ``counter`` is read.
        start_time (datetime): Timestamp from the start of the run for elapsed-time reporting.
        dtl_repo (DTLRepo, optional): Repository helper; if provided, any duplicate
            ``(manufacturer, model)`` definitions detected during YAML parsing are listed
            so the user can fix them upstream.
    """
    handle.log("---")
    handle.verbose_log(f"Script took {(datetime.now() - start_time)} to run")
    handle.log(f"{netbox.counter['added']} device types created")
    handle.log(f"{netbox.counter['properties_updated']} device types updated")
    component_updates = netbox.counter.get("device_types_component_updates", 0)
    if component_updates:
        handle.log(f"{component_updates} device types had component-only updates")
    failed = netbox.counter.get("device_types_failed", 0)
    if failed:
        handle.log(f"{failed} device types FAILED to update (see error log above)")
    handle.log(f"{netbox.counter['components_updated']} components updated")
    handle.log(f"{netbox.counter['components_added']} components added")
    handle.log(f"{netbox.counter['components_removed']} components removed")
    handle.verbose_log(f"{netbox.counter['images']} images uploaded")
    handle.log(f"{netbox.counter['manufacturer']} manufacturers created")
    if netbox.modules:
        handle.log(f"{netbox.counter['module_added']} modules created")
        handle.log(f"{netbox.counter['module_updated']} modules updated")
        if netbox.counter["module_update_failed"]:
            handle.log(f"{netbox.counter['module_update_failed']} modules failed to update")
        if netbox.counter["module_partial_update"]:
            handle.log(f"{netbox.counter['module_partial_update']} modules partially updated")
    if netbox.rack_types:
        handle.log(f"{netbox.counter['rack_type_added']} rack types created")
        handle.log(f"{netbox.counter['rack_type_updated']} rack types updated")

    # Structured failure / partial-update report (replaces the "see error log
    # above" hand-wave with itemised per-entity context).
    failure_lines = netbox.outcomes.render_failure_report()
    for line in failure_lines:
        handle.log(line)

    if dtl_repo is not None and dtl_repo.duplicate_definitions:
        handle.log("---")
        handle.log(
            f"WARNING: {len(dtl_repo.duplicate_definitions)} duplicate "
            "(manufacturer, model) definition(s) detected in the source repository:"
        )
        for dup in dtl_repo.duplicate_definitions:
            handle.log(f"  {dup['manufacturer']}/{dup['model']}")
            handle.log(f"    kept:    {dup['kept']}")
            for ignored in dup["ignored"]:
                handle.log(f"    ignored: {ignored}")
        handle.log("These duplicates would otherwise oscillate on every run. Please report/fix them upstream.")


def _parse_vendor_racks(dtl_repo, racks_path, vendor_name, slugs):
    """Parse rack-type YAML files for *vendor_name*, returning an empty list when *racks_path* is absent.

    Args:
        dtl_repo (DTLRepo): Repository helper used for file discovery and parsing.
        racks_path (str): Base path for rack-type YAML files.
        vendor_name (str): Vendor directory name to filter files by.
        slugs (list[str]): Optional rack-type slug filter.

    Returns:
        list[dict]: Parsed rack-type records (may be empty).
    """
    if not os.path.isdir(racks_path):
        return []
    rack_files, _ = dtl_repo.get_devices(racks_path, [vendor_name.casefold()])
    return dtl_repo.parse_files(rack_files, slugs=slugs)


def _finalize_task_registry(progress, task_registry):
    """Resolve unknown totals and stop spinners for all cumulative registry tasks.

    Args:
        progress: Rich Progress instance, or None.
        task_registry (dict | None): Mapping of description → task ID.
    """
    if not progress or not task_registry:
        return
    for task_id in task_registry.values():
        task = next((t for t in progress.tasks if t.id == task_id), None)
        if task is None:
            continue
        if task.total is None:
            progress.update(task_id, total=max(task.completed, 0))
        progress.stop_task(task_id)


def _validate_argument_combinations(parser, args):
    """Apply mutual-dependency checks for CLI flags and exit via parser.error on violation."""
    if args.export_diff and (args.update or args.only_new):
        parser.error("--export-diff cannot be used with --update or --only-new")
    if args.export_diff and args.remove_components:
        parser.error("--export-diff cannot be used with --remove-components")
    if args.export_diff and getattr(args, "remove_unmanaged_types", False):
        parser.error("--remove-unmanaged-types is an import-only flag and cannot be used with --export-diff")
    if args.export_diff and getattr(args, "slugs", None):
        parser.error("--slugs is an import-only flag and cannot be used with --export-diff")
    if args.export_diff and getattr(args, "verify_images", False):
        parser.error("--verify-images is an import-only flag and cannot be used with --export-diff")
    if args.export_diff and getattr(args, "force_resolve_conflicts", False):
        parser.error("--force-resolve-conflicts is an import-only flag and cannot be used with --export-diff")
    if args.remove_components and not args.update:
        parser.error("--remove-components requires --update")
    if args.remove_unmanaged_types and not args.remove_components:
        parser.error("--remove-unmanaged-types requires --remove-components")
    if args.force_resolve_conflicts and not args.update:
        parser.error("--force-resolve-conflicts requires --update")


def _apply_slug_fast_path(dtl_repo, args, vendors_to_process, handle):
    """Use upstream pickle indexes to pre-resolve files and narrow the vendor list.

    When ``args.slugs`` is set and the DTL pickle files are present, resolves
    exactly which device-type files match the requested slugs and restricts
    ``vendors_to_process`` to only those vendors.  Returns a ``(vendors, resolved)``
    pair where *resolved* is the dict returned by :meth:`DTLRepo.resolve_slug_files`
    (or ``None`` when the pickle is absent/unavailable).
    """
    if not args.slugs:
        return vendors_to_process, None

    slug_resolved = dtl_repo.resolve_slug_files(args.slugs)
    if slug_resolved is None:
        handle.verbose_log("Slug pickle unavailable; falling back to full file scan.")
        return vendors_to_process, None

    matched_vendor_slugs = (
        set(slug_resolved["device_files"])
        | (slug_resolved["module_vendors"] or set())
        | (slug_resolved["rack_vendors"] or set())
    )
    if not matched_vendor_slugs:
        handle.verbose_log("Slug pickle returned no matches; falling back to full file scan.")
        return vendors_to_process, None
    narrowed = [v for v in vendors_to_process if v["slug"] in matched_vendor_slugs]
    handle.verbose_log(
        f"Slug pickle resolved {sum(len(f) for f in slug_resolved['device_files'].values())} "
        f"device file(s) across {len(matched_vendor_slugs)} vendor(s)."
    )
    return narrowed, slug_resolved


def _run_export_diff(settings, handle, args):
    """Run the export-diff pipeline and return."""
    from core.export import Exporter

    exporter = Exporter(
        settings=settings,
        handle=handle,
        export_dir=args.export_diff_dir,
        force_overwrite=args.force_export_overwrite,
        vendor_slugs=args.vendors if args.vendors else None,
    )
    with get_progress_panel(args.show_remaining_time) as progress:
        if progress is not None:
            handle.set_console(progress.console)
        exporter.run(progress=progress)


def _build_argument_parser() -> ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = ArgumentParser(description="Import Netbox Device Types", allow_abbrev=False)
    parser.add_argument(
        "--vendors",
        nargs="+",
        default=settings.VENDORS,
        help="List of vendors to import eg. apc cisco",
    )
    parser.add_argument(
        "--url",
        "--git",
        default=settings.REPO_URL,
        help="Git URL with valid Device Type YAML files",
    )
    parser.add_argument(
        "--slugs",
        nargs="+",
        default=settings.SLUGS,
        help="List of device-type slugs to import eg. ap4431 ws-c3850-24t-l",
    )
    parser.add_argument("--branch", default=settings.REPO_BRANCH, help="Git branch to use from repo")
    parser.add_argument("--verbose", action="store_true", default=False, help="Print verbose output")
    parser.add_argument(
        "--show-remaining-time",
        action="store_true",
        default=False,
        help="Show estimated remaining time in progress output",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--only-new",
        action="store_true",
        default=False,
        help="Only create new devices, skip existing ones",
    )
    mode_group.add_argument(
        "--update",
        action="store_true",
        default=False,
        help="Update existing device types with changes from repository (add missing components, modify "
        "changed properties)",
    )
    parser.add_argument(
        "--remove-components",
        action="store_true",
        default=False,
        help="Remove components from NetBox that no longer exist in YAML (use with --update). "
        "WARNING: May affect existing device instances.",
    )
    parser.add_argument(
        "--remove-unmanaged-types",
        action="store_true",
        default=False,
        help=(
            "Also remove components whose entire YAML section is missing (e.g. NetBox has interfaces "
            "but the YAML defines no 'interfaces:' key at all). Requires --remove-components. "
            "WARNING: Aggressive; will delete components on every type whose YAML omits that section."
        ),
    )
    parser.add_argument(
        "--force-resolve-conflicts",
        action="store_true",
        default=False,
        help=(
            "Allow destructive remediation when a NetBox business-logic constraint blocks an update "
            "(e.g. delete blocking device-bay templates before a subdevice_role parent->child flip). "
            "Only applied when no live device references the type. WARNING: Destructive."
        ),
    )
    parser.add_argument(
        "--verify-images",
        action="store_true",
        default=False,
        help=(
            "Verify that images recorded in the NetBox database are physically present on the server. "
            "Uses an HTTP presence check per image and a local SHA-256 cache to detect local file "
            "changes (does not hash or download the remote file). Re-uploads any image that is "
            "missing on the server or whose local file has changed since the last upload. "
            "Useful after recreating a devcontainer (media files gone but DB intact) or "
            "when local image files have been updated. NOTE: Makes an HTTP request per image — "
            "avoid using this in bulk runs unless necessary."
        ),
    )
    parser.add_argument(
        "--export-diff",
        action="store_true",
        default=False,
        help=(
            "Export device/module/rack types from NetBox that are absent from or differ vs. "
            "the local repo/ directory. Writes DTL-compatible YAML files and images to the "
            "export directory. Does not run the import pipeline."
        ),
    )
    parser.add_argument(
        "--export-diff-dir",
        default="extra/",
        metavar="PATH",
        help="Directory to write exported files to (default: extra/).",
    )
    parser.add_argument(
        "--force-export-overwrite",
        action="store_true",
        default=False,
        help=(
            "Overwrite files in the export directory that differ from what would be "
            "generated from NetBox. Without this flag, changed files are skipped with a warning."
        ),
    )
    return parser


def _parse_vendor_types(dtl_repo, netbox, args, vendor, devices_path, modules_path, racks_path, slug_resolved):
    """Parse device-type, module-type, and rack-type YAML files for a single vendor.

    Returns a 3-tuple: (parsed_device_types, parsed_module_types, parsed_rack_types).
    """
    if slug_resolved is not None:
        device_files = slug_resolved["device_files"].get(vendor["slug"], [])
        parsed_device_types = dtl_repo.parse_files(device_files) if device_files else []
    else:
        device_files, _ = dtl_repo.get_devices(devices_path, [vendor["name"].casefold()])
        parsed_device_types = dtl_repo.parse_files(device_files, slugs=args.slugs or [])

    if netbox.modules:
        module_hint = slug_resolved["module_vendors"] if slug_resolved is not None else None
        if module_hint is not None and vendor["slug"] not in module_hint:
            parsed_module_types = []
        else:
            module_files, _ = dtl_repo.get_devices(modules_path, [vendor["name"].casefold()])
            parsed_module_types = dtl_repo.parse_files(module_files, slugs=args.slugs or [])
    else:
        parsed_module_types = []

    if netbox.rack_types:
        rack_hint = slug_resolved["rack_vendors"] if slug_resolved is not None else None
        if rack_hint is not None and vendor["slug"] not in rack_hint:
            parsed_rack_types = []
        else:
            parsed_rack_types = _parse_vendor_racks(dtl_repo, racks_path, vendor["name"], args.slugs or [])
    else:
        parsed_rack_types = []

    return parsed_device_types, parsed_module_types, parsed_rack_types


def _run_vendor_loop(
    dtl_repo,
    netbox,
    args,
    handle,
    vendors_to_process,
    devices_path,
    modules_path,
    racks_path,
    slug_resolved,
    progress,
    task_registry,
    vendor_task_id,
) -> None:
    """Process all selected vendors and finalize preload/progress teardown."""
    cache_preload_job = None
    try:
        for vendor in vendors_to_process:
            parsed_device_types, parsed_module_types, parsed_rack_types = _parse_vendor_types(
                dtl_repo, netbox, args, vendor, devices_path, modules_path, racks_path, slug_resolved
            )

            if not parsed_device_types and not parsed_module_types and not parsed_rack_types:
                if vendor_task_id is not None:
                    progress.advance(vendor_task_id)
                continue

            netbox.load_vendor(vendor["slug"])
            cache_preload_job = None

            if (parsed_device_types or parsed_module_types) and not args.only_new:
                cache_preload_job = netbox.device_types.start_component_preload(
                    manufacturer_slug=vendor["slug"],
                    progress=progress,
                    task_registry=task_registry,
                )

            def _pump():
                if cache_preload_job and progress is not None:
                    netbox.device_types.pump_preload_progress(cache_preload_job, progress)

            handle.verbose_log(f"{len(parsed_device_types)} Device-Types Found")
            _pump()
            netbox.create_manufacturers([vendor])
            _pump()

            cache_preload_job = _process_device_types(
                args,
                netbox,
                handle,
                progress,
                parsed_device_types,
                cache_preload_job,
                vendor_slug=vendor["slug"],
                task_registry=task_registry,
            )
            _pump()

            if netbox.modules:
                _process_module_types(
                    args,
                    netbox,
                    handle,
                    progress,
                    parsed_module_types,
                    task_registry=task_registry,
                )
                _pump()

            _process_rack_types(
                args,
                netbox,
                handle,
                progress,
                parsed_rack_types,
                task_registry=task_registry,
            )
            _pump()

            if cache_preload_job:
                netbox.device_types.stop_component_preload(cache_preload_job, progress=progress)
                cache_preload_job = None

            if vendor_task_id is not None:
                progress.advance(vendor_task_id)
    finally:
        if cache_preload_job:
            netbox.device_types.stop_component_preload(cache_preload_job, progress=progress)
        _finalize_task_registry(progress, task_registry)
        handle.set_console(None)


def main():
    """Orchestrate importing device- and module-types from a Git repository into NetBox.

    Parses CLI arguments, validates environment variables, clones/pulls the DTL repo,
    parses YAML files, and creates manufacturers, device types, and module types in NetBox.
    Reports progress and summary counters.
    """
    startTime = datetime.now()

    parser = _build_argument_parser()

    args = parser.parse_args()

    _validate_argument_combinations(parser, args)

    # Normalize arguments
    args.vendors = [
        re.sub(r"\W+", "-", v.strip().casefold()) for vendor in args.vendors for v in vendor.split(",") if v.strip()
    ]
    args.slugs = [s.strip() for slug in args.slugs for s in slug.split(",") if s.strip()]

    handle = LogHandler(args)

    _check_env_vars(handle)

    if args.export_diff:
        _run_export_diff(settings, handle, args)
        return

    dtl_repo = DTLRepo(args, settings.REPO_PATH, handle)

    # Instantiate NetBox with all required dependencies
    # We pass settings for constants, but ideally we should pass individual config items
    # For now, we will update NetBox to verify compatibility with this new setup
    netbox = NetBox(settings, handle)  # handle passed explicitly
    netbox.force_resolve_conflicts = args.force_resolve_conflicts
    netbox.remove_unmanaged_types = args.remove_unmanaged_types
    netbox.verify_images = args.verify_images

    # Confirm effective run behavior right after compatibility checks.
    log_run_mode(handle, args)
    _log_import_filters(handle, args)

    devices_path = dtl_repo.get_devices_path()
    modules_path = dtl_repo.get_modules_path()
    racks_path = dtl_repo.get_racks_path()

    # Discover all vendors present in the repo across all three type directories.
    all_vendors = dtl_repo.discover_vendors(devices_path, modules_path, racks_path)

    # Filter to the requested vendors when --vendor args are provided.
    if args.vendors:
        vendor_slug_filter = {v.lower() for v in args.vendors}
        vendors_to_process = [v for v in all_vendors if v["slug"] in vendor_slug_filter]
        if not vendors_to_process:
            handle.log(
                f"No vendors matched --vendors: {', '.join(args.vendors)}. "
                f"Available: {', '.join(v['slug'] for v in all_vendors[:10])}"
                f"{'...' if len(all_vendors) > 10 else ''}"
            )
            raise SystemExit(1)
    else:
        vendors_to_process = all_vendors

    vendors_to_process, slug_resolved = _apply_slug_fast_path(dtl_repo, args, vendors_to_process, handle)

    if args.vendors and not vendors_to_process:
        handle.log(f"No vendors matched the combination of --vendors and --slugs: {', '.join(args.vendors)}")
        raise SystemExit(1)

    with get_progress_panel(args.show_remaining_time) as progress:
        if progress is not None:
            handle.set_console(progress.console)
        # Shared task registry for cumulative progress bars across all vendors.
        task_registry = {} if progress is not None else None
        vendor_task_id = None
        if progress is not None and vendors_to_process:
            _vdesc = "Vendors".ljust(_PROGRESS_DESC_WIDTH)
            vendor_task_id = progress.add_task(_vdesc, total=len(vendors_to_process))
        _run_vendor_loop(
            dtl_repo=dtl_repo,
            netbox=netbox,
            args=args,
            handle=handle,
            vendors_to_process=vendors_to_process,
            devices_path=devices_path,
            modules_path=modules_path,
            racks_path=racks_path,
            slug_resolved=slug_resolved,
            progress=progress,
            task_registry=task_registry,
            vendor_task_id=vendor_task_id,
        )

    _log_run_summary(handle, netbox, startTime, dtl_repo=dtl_repo)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Interrupted by user (Ctrl-C). Exiting.")
        raise SystemExit(130)
    except GraphQLError as exc:
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] Error: NetBox GraphQL request failed — {exc}\n"
            f"[{datetime.now().strftime('%H:%M:%S')}] This may be a temporary connectivity issue. "
            "Check that NetBox is reachable and try again.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except NetBoxRequestError as exc:
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] Error: NetBox REST API request failed — {exc}\n"
            f"[{datetime.now().strftime('%H:%M:%S')}] Check that NetBox is reachable and"
            " the API token has the required permissions.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except requests.exceptions.ConnectionError as exc:
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] Error: {_fmt_connection_error(settings.NETBOX_URL, exc)}",
            file=sys.stderr,
        )
        raise SystemExit(1)
