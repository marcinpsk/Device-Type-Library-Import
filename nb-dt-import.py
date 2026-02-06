#!/usr/bin/env python3
from datetime import datetime
import os
from argparse import ArgumentParser

import settings
from netbox_api import NetBox
from log_handler import LogHandler
from repo import DTLRepo
from change_detector import ChangeDetector


import sys
from tqdm import tqdm


def get_progress_wrapper(iterable, desc=None, **kwargs):
    if sys.stdout.isatty():
        return tqdm(iterable, desc=desc, unit="item", **kwargs)
    return iterable


def main():
    """
    Orchestrate importing device- and module-types from a Git repository into NetBox.

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

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--only-new", action="store_true", default=False, help="Only create new devices, skip existing ones"
    )
    mode_group.add_argument(
        "--update",
        action="store_true",
        default=False,
        help="Update existing device types with changes from repository (add missing components, modify changed properties)",
    )
    parser.add_argument(
        "--remove-components",
        action="store_true",
        default=False,
        help="Remove components from NetBox that no longer exist in YAML (use with --update). WARNING: May affect existing device instances.",
    )

    args = parser.parse_args()

    if args.remove_components and not args.update:
        parser.error("--remove-components requires --update")

    # Normalize arguments
    args.vendors = [v.casefold() for vendor in args.vendors for v in vendor.split(",") if v.strip()]
    args.slugs = [s for slug in args.slugs for s in slug.split(",") if s.strip()]

    handle = LogHandler(args)

    # Evaluate environment variables and exit if one of the mandatory ones are not set
    for var in settings.MANDATORY_ENV_VARS:
        if var not in os.environ:
            handle.exception(
                "EnvironmentError",
                var,
                f'Environment variable "{var}" is not set.\n\nMANDATORY_ENV_VARS: {str(settings.MANDATORY_ENV_VARS)}\n',
            )

    dtl_repo = DTLRepo(args, settings.REPO_PATH, handle)

    # Instantiate NetBox with all required dependencies
    # We pass settings for constants, but ideally we should pass individual config items
    # For now, we will update NetBox to verify compatibility with this new setup
    netbox = NetBox(settings, handle)  # handle passed explicitly

    # Print what will be imported based on CLI arguments
    if args.vendors:
        handle.log(f"Importing vendors: {', '.join(args.vendors)}")
    if args.slugs:
        handle.log(f"Filtering by slugs: {', '.join(args.slugs)}")

    files, vendors = dtl_repo.get_devices(f"{dtl_repo.repo_path}/device-types/", args.vendors)

    handle.log(f"{len(vendors)} Vendors Found")
    device_types = dtl_repo.parse_files(
        files, slugs=args.slugs, progress=get_progress_wrapper(files, desc="Parsing Files")
    )
    handle.log(f"{len(device_types)} Device-Types Found")

    netbox.create_manufacturers(vendors)

    # Determine processing mode
    change_report = None

    if args.only_new:
        # Skip caching and change detection - just create new devices
        handle.log("Mode: Only creating new device types (--only-new)")
        netbox.create_device_types(
            device_types,
            progress=get_progress_wrapper(device_types, desc="Creating Device Types"),
            only_new=True,
        )
    else:
        # Cache NetBox data for comparison (separate step with visible progress)
        handle.log("Caching NetBox data for comparison...")
        netbox.device_types.preload_all_components(progress_wrapper=get_progress_wrapper)

        # Detect changes between YAML and NetBox
        detector = ChangeDetector(netbox.device_types, handle)
        change_report = detector.detect_changes(device_types)
        detector.log_change_report(change_report)

        if args.update:
            # Update mode: create new + update existing
            handle.log("Mode: Creating new and updating existing device types (--update)")
            if args.remove_components:
                handle.log(
                    "  Component removal enabled: Will delete components missing from YAML (--remove-components)"
                )
            netbox.create_device_types(
                device_types,
                progress=get_progress_wrapper(device_types, desc="Processing Device Types"),
                only_new=False,
                update=True,
                change_report=change_report,
                remove_components=args.remove_components,
            )
        else:
            # Default mode: only create new, log what would change
            handle.log("Mode: Creating new device types only (use --update to apply modifications)")
            netbox.create_device_types(
                device_types,
                progress=get_progress_wrapper(device_types, desc="Creating Device Types"),
                only_new=True,  # Skip existing devices in default mode
                update=False,
                change_report=change_report,
            )

    if netbox.modules:
        handle.log("Modules Enabled. Creating Modules...")
        files, vendors = dtl_repo.get_devices(f"{dtl_repo.repo_path}/module-types/", args.vendors)
        handle.log(f"{len(vendors)} Module Vendors Found")
        module_types = dtl_repo.parse_files(
            files, slugs=args.slugs, progress=get_progress_wrapper(files, desc="Parsing Modules")
        )
        handle.log(f"{len(module_types)} Module-Types Found")
        netbox.create_manufacturers(vendors)
        netbox.create_module_types(
            module_types,
            progress=get_progress_wrapper(module_types, desc="Creating Module Types"),
            only_new=args.only_new,
        )

    handle.log("---")
    handle.verbose_log(f"Script took {(datetime.now() - startTime)} to run")
    handle.log(f"{netbox.counter['added']} device types created")
    handle.log(f"{netbox.counter['properties_updated']} device types updated")
    handle.log(f"{netbox.counter['components_updated']} components updated")
    handle.log(f"{netbox.counter['components_added']} components added")
    handle.log(f"{netbox.counter['components_removed']} components removed")
    handle.log(f"{netbox.counter['images']} images uploaded")
    handle.log(f"{netbox.counter['manufacturer']} manufacturers created")
    if settings.NETBOX_FEATURES["modules"]:
        handle.log(f"{netbox.counter['module_added']} modules created")
        handle.log(f"{netbox.counter['module_port_added']} module interface / ports created")


if __name__ == "__main__":
    main()
