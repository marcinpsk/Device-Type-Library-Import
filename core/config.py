"""Resolution of one run's configuration from the command line and the environment."""

import os
import re
from argparse import ArgumentParser
from dataclasses import dataclass, field

from dotenv import load_dotenv

from core.errors import FatalError

DEFAULT_REPO_URL = "https://github.com/netbox-community/devicetype-library.git"
DEFAULT_REPO_BRANCH = "master"
# REPO_URL value that reads REPO_PATH as it stands, with no git operation at all.
LOCAL_REPO_URL = "local"
DEFAULT_GRAPHQL_PAGE_SIZE = 5000
DEFAULT_PRELOAD_THREADS = 8

# Variables with no default, so a run cannot start without them.
REQUIRED_ENV_VARS = ("NETBOX_URL", "NETBOX_TOKEN")

_DEFAULT_REPO_PATH = f"{os.path.dirname(os.path.dirname(os.path.realpath(__file__)))}/repo"


def is_local_repo_url(url):
    """Return True when *url* is the sentinel that turns off every git operation."""
    return str(url or "").strip().casefold() == LOCAL_REPO_URL


class ConfigError(FatalError):
    """A configuration value the run cannot start with, phrased for the person who set it."""


class EnvironmentVariableError(ConfigError):
    """A required environment variable that is not set."""

    def __init__(self, names):
        """Name the required environment variables."""
        names = (names,) if isinstance(names, str) else tuple(names)
        message = "\n".join(f'Environment variable "{name}" is not set.' for name in names)
        message += f"\n\nRequired: {', '.join(REQUIRED_ENV_VARS)}"
        super().__init__(message)


@dataclass(frozen=True)
class RunConfig:
    """Everything one run needs, resolved once from argv and the environment."""

    netbox_url: str
    netbox_token: str
    ignore_ssl_errors: bool
    graphql_page_size: int
    preload_threads: int

    repo_url: str
    repo_branch: str
    repo_path: str

    vendors: tuple = ()
    slugs: tuple = ()

    export_diff: bool = False
    export_diff_dir: str = "extra/"
    force_export_overwrite: bool = False

    update: bool = False
    only_new: bool = False
    remove_components: bool = False
    remove_unmanaged_types: bool = False
    force_resolve_conflicts: bool = False
    verify_images: bool = False

    verbose: bool = False
    show_remaining_time: bool = False

    # Resolution decisions worth telling the user about, logged once the handler exists.
    notices: tuple = field(default_factory=tuple)


def _text(env, name, default=None):
    """Return a non-blank environment value, or *default*. Blank counts as unset."""
    return env.get(name, "").strip() or default


def _positive_int(env, name, default):
    """Return a positive integer environment value, or *default* when it is unset."""
    raw = _text(env, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a positive integer, got {raw!r}") from None
    if value < 1:
        raise ConfigError(f"{name} must be >= 1, got {value}")
    return value


def build_argument_parser(env):
    """Build the CLI parser, taking the defaults that the environment is allowed to set."""
    parser = ArgumentParser(description="Import Netbox Device Types", allow_abbrev=False)
    parser.add_argument(
        "--vendors",
        nargs="+",
        default=list(filter(None, env.get("VENDORS", "").split(","))),
        help="List of vendors to import eg. apc cisco",
    )
    parser.add_argument(
        "--url",
        "--git",
        default=_text(env, "REPO_URL", DEFAULT_REPO_URL),
        help=f'Git URL with valid Device Type YAML files, or "{LOCAL_REPO_URL}" to read REPO_PATH with no git',
    )
    parser.add_argument(
        "--slugs",
        nargs="+",
        # None distinguishes "not passed" from an env-provided default, which export mode ignores.
        default=None,
        help="List of device-type slugs to import eg. ap4431 ws-c3850-24t-l",
    )
    parser.add_argument(
        "--branch",
        default=_text(env, "REPO_BRANCH", DEFAULT_REPO_BRANCH),
        help="Git branch to use from repo",
    )
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


def _validate_flag_combinations(parser, args):
    """Reject flag combinations through the parser, which exits with argparse's usage message."""
    if args.export_diff and (args.update or args.only_new):
        parser.error("--export-diff cannot be used with --update or --only-new")
    if args.export_diff and args.remove_components:
        parser.error("--export-diff cannot be used with --remove-components")
    if args.export_diff and args.remove_unmanaged_types:
        parser.error("--remove-unmanaged-types is an import-only flag and cannot be used with --export-diff")
    if args.export_diff and args.slugs:
        parser.error("--slugs is an import-only flag and cannot be used with --export-diff")
    if args.export_diff and args.verify_images:
        parser.error("--verify-images is an import-only flag and cannot be used with --export-diff")
    if args.export_diff and args.force_resolve_conflicts:
        parser.error("--force-resolve-conflicts is an import-only flag and cannot be used with --export-diff")
    if args.remove_components and not args.update:
        parser.error("--remove-components requires --update")
    if args.remove_unmanaged_types and not args.remove_components:
        parser.error("--remove-unmanaged-types requires --remove-components")
    if args.force_resolve_conflicts and not args.update:
        parser.error("--force-resolve-conflicts requires --update")


def _split_vendors(values):
    """Split comma-joined vendor arguments and reduce each to its slug form."""
    return tuple(re.sub(r"\W+", "-", v.strip().casefold()) for vendor in values for v in vendor.split(",") if v.strip())


def _split_slugs(values):
    """Split comma-joined slug arguments, dropping blanks."""
    return tuple(s.strip() for slug in values for s in slug.split(",") if s.strip())


def resolve_run_config(argv=None, env=None):
    """Resolve *argv* and *env* into one RunConfig, or raise ConfigError.

    Reads argv before the environment, so ``--help`` answers without an environment
    value being able to fail it. Loads a .env file only when *env* is not supplied.
    """
    if env is None:
        load_dotenv()
        env = os.environ

    parser = build_argument_parser(env)
    args = parser.parse_args(argv)
    _validate_flag_combinations(parser, args)

    missing = [name for name in REQUIRED_ENV_VARS if _text(env, name) is None]
    if missing:
        raise EnvironmentVariableError(missing)

    slug_values = env.get("SLUGS", "").split() if args.slugs is None else args.slugs
    slugs = _split_slugs(slug_values)
    notices = []
    if args.export_diff and slugs:
        # Only the environment can reach here: an explicit --slugs is rejected above.
        notices.append("Ignoring SLUGS from the environment: --export-diff does not filter by slug.")
        slugs = ()
    if is_local_repo_url(args.url) and args.branch != DEFAULT_REPO_BRANCH:
        notices.append(
            f"Ignoring REPO_BRANCH={args.branch}: REPO_URL={LOCAL_REPO_URL} reads REPO_PATH as it stands "
            "and checks out no branch."
        )

    return RunConfig(
        netbox_url=_text(env, "NETBOX_URL"),
        netbox_token=_text(env, "NETBOX_TOKEN"),
        ignore_ssl_errors=(_text(env, "IGNORE_SSL_ERRORS", "False") or "False").casefold() in {"true", "1", "yes"},
        graphql_page_size=_positive_int(env, "GRAPHQL_PAGE_SIZE", DEFAULT_GRAPHQL_PAGE_SIZE),
        preload_threads=_positive_int(env, "PRELOAD_THREADS", DEFAULT_PRELOAD_THREADS),
        repo_url=args.url,
        repo_branch=args.branch,
        repo_path=_text(env, "REPO_PATH", _DEFAULT_REPO_PATH),
        vendors=_split_vendors(args.vendors),
        slugs=slugs,
        export_diff=args.export_diff,
        export_diff_dir=args.export_diff_dir,
        force_export_overwrite=args.force_export_overwrite,
        update=args.update,
        only_new=args.only_new,
        remove_components=args.remove_components,
        remove_unmanaged_types=args.remove_unmanaged_types,
        force_resolve_conflicts=args.force_resolve_conflicts,
        verify_images=args.verify_images,
        verbose=args.verbose,
        show_remaining_time=args.show_remaining_time,
        notices=tuple(notices),
    )
