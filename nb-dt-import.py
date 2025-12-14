#!/usr/bin/env python3
from datetime import datetime
import os
from argparse import ArgumentParser

import settings
from netbox_api import NetBox
from log_handler import LogHandler
from repo import DTLRepo


import sys
from tqdm import tqdm


def get_progress_wrapper(iterable, desc=None, **kwargs):
    if sys.stdout.isatty():
        return tqdm(iterable, desc=desc, unit="item", **kwargs)
    return iterable


def main():
    """
    Orchestrates importing device- and module-types from a Git repository into NetBox.
    
    Parses command-line arguments (vendors, repo URL/branch, slugs, verbosity, and only-new flag), normalizes them, validates mandatory environment variables (logging an EnvironmentError if any are missing), clones/reads device- and module-type files via DTLRepo, parses those files into objects, and creates manufacturers, device types, and — if enabled — module types in NetBox while reporting progress and summary counters via the LogHandler.
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
        "--only-new", action="store_true", default=False, help="Only create new devices, skip existing ones"
    )

    args = parser.parse_args()

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

    files, vendors = dtl_repo.get_devices(f"{dtl_repo.repo_path}/device-types/", args.vendors)

    handle.log(f"{len(vendors)} Vendors Found")
    device_types = dtl_repo.parse_files(
        files, slugs=args.slugs, progress=get_progress_wrapper(files, desc="Parsing Files")
    )
    handle.log(f"{len(device_types)} Device-Types Found")

    netbox.create_manufacturers(vendors)
    netbox.create_device_types(
        device_types,
        progress=get_progress_wrapper(device_types, desc="Creating Device Types"),
        only_new=args.only_new,
        progress_wrapper=get_progress_wrapper,
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
    handle.log(f'{netbox.counter["added"]} devices created')
    handle.log(f'{netbox.counter["images"]} images uploaded')
    handle.log(f'{netbox.counter["updated"]} interfaces/ports updated')
    handle.log(f'{netbox.counter["manufacturer"]} manufacturers created')
    if settings.NETBOX_FEATURES["modules"]:
        handle.log(f'{netbox.counter["module_added"]} modules created')
        handle.log(f'{netbox.counter["module_port_added"]} module interface / ports created')


if __name__ == "__main__":
    main()