#!/usr/bin/env python3
from datetime import datetime
import concurrent.futures
import os
from argparse import ArgumentParser
from contextlib import contextmanager

from core import settings
from core.netbox_api import NetBox
from core.log_handler import LogHandler
from core.repo import DTLRepo
from core.change_detector import ChangeDetector, IMAGE_PROPERTIES


import sys
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text


_PROGRESS_DESC_WIDTH = 28  # Longest: "Caching Console Server Ports"


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
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        ItemsPerSecondColumn(),
    ]
    if show_remaining_time:
        columns.append(TimeRemainingColumn())

    with MyProgress(
        *columns,
    ) as progress:
        yield progress


def get_progress_wrapper(progress, iterable, desc=None, total=None, on_step=None):
    """Wrap *iterable* with a Rich progress task if *progress* is provided, otherwise return *iterable* unchanged.

    Args:
        progress: A MyProgress instance (or compatible), or None to disable tracking.
        iterable: The iterable to wrap.
        desc (str | None): Task description shown in the progress bar.
        total (int | None): Total number of items; inferred from ``len(iterable)`` if omitted.
        on_step (callable | None): Optional callback invoked after each item and at the end.

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

    task_id = progress.add_task(description, total=total)

    def iterator():
        count = 0
        try:
            for item in iterable:
                yield item
                count += 1
                progress.advance(task_id)
                if on_step:
                    on_step()
        finally:
            if total is None:
                progress.update(task_id, total=max(count, 1), completed=count)
            progress.stop_task(task_id)
            if on_step:
                on_step()

    return iterator()


def filter_vendors_for_parsed_types(discovered_vendors, parsed_types):
    """Return only the vendors referenced in *parsed_types* and the set of their slugs.

    Args:
        discovered_vendors (list[dict]): All vendors discovered in the repo (each has a "slug" key).
        parsed_types (list[dict]): Parsed device-type dicts; each must have a ``manufacturer.slug`` entry.

    Returns:
        tuple[list[dict], set[str]]: Filtered vendor list and the corresponding slug set.
    """
    selected_vendor_slugs = {item["manufacturer"]["slug"] for item in parsed_types}
    filtered_vendors = [vendor for vendor in discovered_vendors if vendor["slug"] in selected_vendor_slugs]
    return filtered_vendors, selected_vendor_slugs


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


def select_device_types_for_default_mode(device_types, change_report):
    """Select device types to process in default (non-update) mode.

    Includes newly discovered device types and existing ones with missing images.

    Args:
        device_types (list[dict]): All parsed device-type dicts.
        change_report (ChangeReport | None): Change detection results; if None returns [].

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
    return filter_device_types_by_change_keys(device_types, new_keys | image_change_keys)


def select_device_types_for_update_mode(device_types, change_report):
    """Select device types to process in update (``--update``) mode.

    Includes all new and modified device types.

    Args:
        device_types (list[dict]): All parsed device-type dicts.
        change_report (ChangeReport | None): Change detection results; if None returns [].

    Returns:
        list[dict]: Device types that are either new or have detected changes.
    """
    if not change_report:
        return []

    actionable_keys = {change_entry_key(change) for change in change_report.new_device_types}
    actionable_keys.update(change_entry_key(change) for change in change_report.modified_device_types)
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
        else:
            handle.log(
                "Mode: will not remove components from existing models; use --remove-components with "
                "--update to change this."
            )
    else:
        handle.log("Mode: --update not set; changed properties/components will not be applied (use --update).")


def should_only_create_new_modules(args):
    """Return True if module processing should only create new entries and skip updates."""
    return args.only_new or not args.update


@contextmanager
def _image_progress_scope(progress, device_types, total=0):
    """Context manager that wires up image-upload progress tracking.

    Creates a progress task (if *progress* is not None and *total* > 0),
    assigns the advance callback to ``device_types._image_progress``, and
    always resets it to ``None`` on exit — even on exception.

    Args:
        progress: Rich Progress instance, or None.
        device_types: ``DeviceTypes`` helper whose ``_image_progress`` callback is set.
        total (int): Pre-counted number of images to upload. If 0, no progress bar is shown.
    """
    if progress is not None and total > 0:
        _img_task = progress.add_task("Uploading Images", total=total)

        def _adv_img(count=1):
            progress.update(_img_task, advance=count)

        device_types._image_progress = _adv_img
    try:
        yield
    finally:
        device_types._image_progress = None


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


def _bg_parse_module_types(dtl_repo, module_vendor_filter, slugs):
    """Discover and parse module-type YAML files; designed for background execution.

    Args:
        dtl_repo (DTLRepo): Repository helper for file discovery and YAML parsing.
        module_vendor_filter (list[str]): Vendor slugs used to scope file discovery.
        slugs (list[str]): Device-type slug filters passed to ``parse_files``.

    Returns:
        tuple[list, list, list]: ``(files, discovered_vendors, module_types)``.
            *module_types* is an empty list when no files are discovered.
    """
    bg_files, bg_vendors = dtl_repo.get_devices(dtl_repo.get_modules_path(), module_vendor_filter)
    if not bg_files:
        return [], bg_vendors, []
    bg_module_types = dtl_repo.parse_files(bg_files, slugs=slugs)
    return bg_files, bg_vendors, bg_module_types


def _process_device_types(args, netbox, handle, progress, device_types, cache_preload_job):
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
                    progress=get_progress_wrapper(progress, new_device_types, desc="Creating Device Types"),
                    only_new=True,
                )
        else:
            handle.verbose_log("No new device types to create.")
        return cache_preload_job

    # Non-only_new path: preload cache then detect changes.
    if device_types:
        handle.verbose_log("Caching NetBox data for comparison (concurrent API requests started during parsing)...")
        netbox.device_types.preload_all_components(
            progress=progress,
            preload_job=cache_preload_job,
        )
        cache_preload_job = None
    else:
        handle.log("No device types matched filters. Skipping NetBox cache preload.")

    detector = ChangeDetector(netbox.device_types, handle)
    change_report = detector.detect_changes(
        device_types,
        progress=get_progress_wrapper(progress, device_types, desc="Detecting Changes"),
    )
    detector.log_change_report(change_report)

    if args.update:
        device_types_to_process = select_device_types_for_update_mode(device_types, change_report)
        if device_types_to_process:
            image_total = netbox.count_device_type_images(device_types_to_process)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    device_types_to_process,
                    progress=get_progress_wrapper(progress, device_types_to_process, desc="Processing Device Types"),
                    only_new=False,
                    update=True,
                    change_report=change_report,
                    remove_components=args.remove_components,
                )
        else:
            handle.verbose_log("No device type changes to process.")
    else:
        device_types_to_process = select_device_types_for_default_mode(device_types, change_report)
        if device_types_to_process:
            image_total = netbox.count_device_type_images(device_types_to_process)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    device_types_to_process,
                    progress=get_progress_wrapper(progress, device_types_to_process, desc="Creating Device Types"),
                    only_new=True,
                )
        else:
            handle.verbose_log("No new device types or missing images to process.")

    return cache_preload_job


def _process_module_types(
    args,
    netbox,
    dtl_repo,
    handle,
    progress,
    selected_vendor_slugs,
    *,
    module_parse_future=None,
    module_parse_executor=None,
):
    """Process module types, retrieving data from a background future or parsing synchronously.

    Args:
        args: Parsed CLI arguments; inspects ``vendors``, ``slugs``, ``only_new``,
            and ``update``.
        netbox (NetBox): NetBox API wrapper instance.
        dtl_repo (DTLRepo): Repository helper for file discovery and YAML parsing;
            used only when *module_parse_future* is ``None``.
        handle (LogHandler): Logging handler used to emit progress messages.
        progress: Rich Progress instance for progress display, or None.
        selected_vendor_slugs (set[str]): Vendor slugs derived from parsed device
            types, used to scope module discovery when ``--slugs`` is set.
        module_parse_future: Background ``concurrent.futures.Future`` that returns
            ``(files, vendors, module_types)``, or ``None`` for synchronous parsing.
        module_parse_executor: ``ThreadPoolExecutor`` used to start the background
            parse; shut down after result retrieval.  Ignored when
            *module_parse_future* is ``None``.
    """
    if module_parse_future is not None:
        module_files, discovered_module_vendors, module_types = module_parse_future.result()
        if module_parse_executor is not None:
            module_parse_executor.shutdown(wait=False)
        if not module_files:
            module_types = []
    else:
        module_vendor_filter = args.vendors
        if args.slugs and not args.vendors:
            module_vendor_filter = sorted(selected_vendor_slugs)
        module_files, discovered_module_vendors = dtl_repo.get_devices(
            dtl_repo.get_modules_path(), module_vendor_filter
        )
        if not module_files:
            module_types = []
        else:
            module_parse_progress = get_progress_wrapper(progress, module_files, desc="Parsing Module Types")
            module_types = dtl_repo.parse_files(module_files, slugs=args.slugs, progress=module_parse_progress)

    module_vendors, _ = filter_vendors_for_parsed_types(discovered_module_vendors, module_types)
    handle.verbose_log(f"{len(module_vendors)} Module Vendors Found")
    handle.verbose_log(f"{len(module_types)} Module-Types Found")

    module_only_new = should_only_create_new_modules(args)
    existing_module_types = netbox.get_existing_module_types()
    module_types_to_process, module_type_existing_images = netbox.filter_actionable_module_types(
        module_types,
        existing_module_types,
        only_new=module_only_new,
    )

    new_module_count = len(NetBox.filter_new_module_types(module_types, existing_module_types))
    if module_only_new:
        handle.log("============================================================")
        handle.log(f"New module types: {new_module_count}")
        handle.log("============================================================")
    else:
        module_changed_count = len(module_types_to_process) - new_module_count
        module_unchanged_count = len(module_types) - len(module_types_to_process)
        handle.log("============================================================")
        handle.log("MODULE TYPE CHANGE DETECTION")
        handle.log("============================================================")
        handle.log(f"New module types:       {new_module_count}")
        handle.log(f"Unchanged module types: {module_unchanged_count}")
        handle.log(f"Modified module types:  {module_changed_count}")
        handle.log("------------------------------------------------------------")

    if module_types_to_process:
        netbox.create_manufacturers(module_vendors)
        module_image_total = netbox.count_module_type_images(
            module_types_to_process, existing_module_types, module_type_existing_images
        )
        with _image_progress_scope(progress, netbox.device_types, total=module_image_total):
            netbox.create_module_types(
                module_types_to_process,
                progress=get_progress_wrapper(progress, module_types_to_process, desc="Processing Module Types"),
                only_new=module_only_new,
                all_module_types=existing_module_types,
                module_type_existing_images=module_type_existing_images,
            )
    else:
        handle.verbose_log("No module type changes to process.")


def _process_rack_types(args, netbox, dtl_repo, handle, progress, selected_vendor_slugs):
    """Discover, parse, and import rack types from the repository into NetBox.

    Soft-skips with a warning when the connected NetBox instance is older than 4.1.
    Honors ``--vendors`` and ``--slugs`` filters.

    Args:
        args: Parsed CLI arguments; inspects ``vendors``, ``slugs``, and ``only_new``.
        netbox (NetBox): NetBox API wrapper instance.
        dtl_repo (DTLRepo): Repository helper for file discovery and YAML parsing.
        handle (LogHandler): Logging handler used to emit progress messages.
        progress: Rich Progress instance for progress display, or None.
        selected_vendor_slugs (set[str]): Vendor slugs derived from parsed device
            types, used to scope rack-type discovery when ``--slugs`` is set.
    """
    if not netbox.rack_types:
        handle.log("Rack types require NetBox >= 4.1. Skipping rack type import.")
        return

    racks_path = dtl_repo.get_racks_path()
    if not os.path.isdir(racks_path):
        handle.verbose_log("No rack-types directory found in repository. Skipping.")
        return

    rack_vendor_filter = args.vendors
    if args.slugs and not args.vendors:
        rack_vendor_filter = sorted(selected_vendor_slugs)

    rack_files, discovered_rack_vendors = dtl_repo.get_devices(racks_path, rack_vendor_filter)
    if not rack_files:
        handle.verbose_log("No rack-type files found for the selected vendors/slugs.")
        return

    rack_parse_progress = get_progress_wrapper(progress, rack_files, desc="Parsing Rack Types")
    rack_types = dtl_repo.parse_files(rack_files, slugs=args.slugs, progress=rack_parse_progress)

    rack_vendors, _ = filter_vendors_for_parsed_types(discovered_rack_vendors, rack_types)
    handle.verbose_log(f"{len(rack_vendors)} Rack Vendors Found")
    handle.verbose_log(f"{len(rack_types)} Rack-Types Found")

    all_rack_types = netbox.get_existing_rack_types()
    new_count = sum(
        1
        for rt in rack_types
        if all_rack_types.get(rt.get("manufacturer", {}).get("slug", ""), {}).get(rt.get("model")) is None
    )
    existing_count = len(rack_types) - new_count

    handle.log("============================================================")
    handle.log(f"New rack types:       {new_count}")
    handle.log(f"Existing rack types:  {existing_count}")
    handle.log("============================================================")

    if rack_types:
        netbox.create_manufacturers(rack_vendors)
        netbox.create_rack_types(
            rack_types,
            progress=get_progress_wrapper(progress, rack_types, desc="Processing Rack Types"),
            only_new=args.only_new,
            all_rack_types=all_rack_types,
        )


def _log_run_summary(handle, netbox, start_time):
    """Log the final import summary counters to *handle*.

    Args:
        handle (LogHandler): Logging handler for output.
        netbox (NetBox): NetBox API wrapper whose ``counter`` is read.
        start_time (datetime): Timestamp from the start of the run for elapsed-time reporting.
    """
    handle.log("---")
    handle.verbose_log(f"Script took {(datetime.now() - start_time)} to run")
    handle.log(f"{netbox.counter['added']} device types created")
    handle.log(f"{netbox.counter['properties_updated']} device types updated")
    handle.log(f"{netbox.counter['components_updated']} components updated")
    handle.log(f"{netbox.counter['components_added']} components added")
    handle.log(f"{netbox.counter['components_removed']} components removed")
    handle.verbose_log(f"{netbox.counter['images']} images uploaded")
    handle.log(f"{netbox.counter['manufacturer']} manufacturers created")
    if settings.NETBOX_FEATURES["modules"]:
        handle.log(f"{netbox.counter['module_added']} modules created")
    if netbox.rack_types:
        handle.log(f"{netbox.counter['rack_type_added']} rack types created")
        handle.log(f"{netbox.counter['rack_type_updated']} rack types updated")


def main():
    """Orchestrate importing device- and module-types from a Git repository into NetBox.

    Parses CLI arguments, validates environment variables, clones/pulls the DTL repo,
    parses YAML files, and creates manufacturers, device types, and module types in NetBox.
    Reports progress and summary counters.
    """
    startTime = datetime.now()

    parser = ArgumentParser(description="Import Netbox Device Types")
    parser.add_argument(
        "--vendors", nargs="+", default=settings.VENDORS, help="List of vendors to import eg. apc cisco"
    )
    parser.add_argument("--url", "--git", default=settings.REPO_URL, help="Git URL with valid Device Type YAML files")
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
        "--only-new", action="store_true", default=False, help="Only create new devices, skip existing ones"
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

    args = parser.parse_args()

    if args.remove_components and not args.update:
        parser.error("--remove-components requires --update")

    # Normalize arguments
    args.vendors = [v.casefold() for vendor in args.vendors for v in vendor.split(",") if v.strip()]
    args.slugs = [s for slug in args.slugs for s in slug.split(",") if s.strip()]

    handle = LogHandler(args)

    _check_env_vars(handle)

    dtl_repo = DTLRepo(args, settings.REPO_PATH, handle)

    # Instantiate NetBox with all required dependencies
    # We pass settings for constants, but ideally we should pass individual config items
    # For now, we will update NetBox to verify compatibility with this new setup
    netbox = NetBox(settings, handle)  # handle passed explicitly

    # Confirm effective run behavior right after compatibility checks.
    log_run_mode(handle, args)
    _log_import_filters(handle, args)

    files, discovered_vendors = dtl_repo.get_devices(dtl_repo.get_devices_path(), args.vendors)
    cache_preload_job = None
    _module_parse_executor = None
    _module_parse_future = None

    with get_progress_panel(args.show_remaining_time) as progress:
        if progress is not None:
            handle.set_console(progress.console)
        try:
            parse_fn = None

            def on_parse_step():
                if parse_fn is not None:
                    parse_fn()

            parse_progress = get_progress_wrapper(progress, files, desc="Parsing Device Types", on_step=on_parse_step)

            if not args.only_new:
                cache_preload_job = netbox.device_types.start_component_preload(
                    progress=progress,
                )
                if progress is not None:

                    def pump_preload():
                        netbox.device_types.pump_preload_progress(cache_preload_job, progress)

                    parse_fn = pump_preload

            device_types = dtl_repo.parse_files(
                files,
                slugs=args.slugs,
                progress=parse_progress,
            )
            on_parse_step()
            vendors, selected_vendor_slugs = filter_vendors_for_parsed_types(discovered_vendors, device_types)

            handle.verbose_log(f"{len(vendors)} Vendors Found")
            handle.verbose_log(f"{len(device_types)} Device-Types Found")

            # Start module type file discovery and YAML parsing in a background thread
            # so it overlaps with device type processing (which can take minutes).
            if netbox.modules:
                _module_vendor_filter = args.vendors
                if args.slugs and not args.vendors:
                    _module_vendor_filter = sorted(selected_vendor_slugs)
                _module_parse_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                _module_parse_future = _module_parse_executor.submit(
                    _bg_parse_module_types, dtl_repo, _module_vendor_filter, args.slugs
                )

            netbox.create_manufacturers(vendors)

            cache_preload_job = _process_device_types(args, netbox, handle, progress, device_types, cache_preload_job)

            if netbox.modules:
                _process_module_types(
                    args,
                    netbox,
                    dtl_repo,
                    handle,
                    progress,
                    selected_vendor_slugs,
                    module_parse_future=_module_parse_future,
                    module_parse_executor=_module_parse_executor,
                )
                _module_parse_future = None
                _module_parse_executor = None
            _process_rack_types(args, netbox, dtl_repo, handle, progress, selected_vendor_slugs)
        finally:
            if cache_preload_job:
                netbox.device_types.stop_component_preload(cache_preload_job)
            if _module_parse_future is not None and not _module_parse_future.done():
                _module_parse_future.cancel()
            if _module_parse_executor is not None:
                _module_parse_executor.shutdown(wait=False, cancel_futures=True)
            handle.set_console(None)

    _log_run_summary(handle, netbox, startTime)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Interrupted by user (Ctrl-C). Exiting.")
        raise SystemExit(130)
