"""NetBox REST and GraphQL API client for importing device and module type libraries."""

from collections import Counter
import concurrent.futures
from functools import lru_cache
import hashlib
import itertools
import json
import queue
import re
import tempfile
import time
import pynetbox
import requests
import os
from sys import exit as system_exit
import glob
from pathlib import Path

from core.change_detector import ChangeDetector, ChangeType
from core.compat import (
    device_type_filter_key,
    device_type_filter_kwargs,
    module_type_filter_key,
    module_type_filter_kwargs,
)
from core.formatting import log_property_diffs
from core.graphql_client import GraphQLCountMismatchError, GraphQLError, NetBoxGraphQLClient
from core.normalization import values_equal
from core.outcomes import EntityKind, Outcome, OutcomeRegistry
from core.schema_reader import load_properties_for_type
from core.update_failure_resolver import (
    FailureKind,
    classify_device_type_update_failure,
)


def _build_auth_header(token):
    """Return the Authorization header value for the given API token."""
    scheme = "Bearer" if token.startswith("nbt_") else "Token"
    return f"{scheme} {token}"


def _fmt_connection_error(url: str, exc: Exception) -> str:
    """Return a human-friendly message for a connection-level network error.

    Used wherever a ``requests.exceptions.ConnectionError`` (which wraps
    ``urllib3`` ``ProtocolError`` / ``RemoteDisconnected`` etc.) is caught, so
    that the message format is consistent across all call sites.

    Args:
        url: The NetBox base URL that was being contacted.
        exc: The caught exception.

    Returns:
        A single multi-line string suitable for printing to stderr or a log.
    """
    return (
        f"Connection error while contacting NetBox at {url}: {exc}\n"
        "The remote end closed the connection unexpectedly. "
        "Verify that NetBox is running, reachable, and not being restarted."
    )


# Transient connection errors that warrant a retry
_RETRYABLE_EXCEPTIONS = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)

_MAX_RETRIES = 3
_RETRY_BACKOFF = (2, 5, 10)  # seconds to wait before each retry attempt

# Sentinel used when a YAML record has no "src" key (e.g. synthesised entries).
# _image_dir_for_yaml treats this value as "no path known" and returns None.
_UNKNOWN_SRC = "Unknown"


def _check_image_url(
    base_url: str,
    image_url_path: str,
    ignore_ssl: bool,
    token: str = "",
    log_fn=None,
) -> str:
    """Check whether a remote image URL is physically accessible.

    Issues an authenticated HTTP GET and reports whether the image exists on the server.
    Content/byte comparison is intentionally omitted: NetBox re-encodes images on
    upload so remote bytes never match the originals.  Use
    :func:`_is_image_hash_changed` for local-file change detection instead.

    Returns "ok" only when the server returns a 2xx response *and* the Content-Type
    indicates an actual image.  A 2xx with a non-image Content-Type (e.g. ``text/html``
    from a login-redirect) is treated as "missing" so that files absent from the
    filesystem but still recorded in the database are re-uploaded.

    Returns:
        "missing": the server returned a non-2xx response, or a 2xx but with a
                   non-image Content-Type (image not physically present / auth redirect)
        "ok":      image exists (2xx with image Content-Type) or a network error
                   occurred (conservative — avoids spurious re-uploads on transient
                   failures; network error is logged at verbose level when *log_fn*
                   is provided so operators can spot degraded runs)

    Args:
        base_url: NetBox base URL (e.g. "https://netbox.example.com").
        image_url_path: Relative path from NetBox (e.g. "/media/devicetype-images/foo.png")
            or a full URL starting with "http".
        ignore_ssl: When True, SSL certificate verification is skipped.
        token: NetBox API token.  When non-empty, sent using the same
            ``Authorization`` scheme as ``_build_auth_header`` (``Bearer`` for
            ``nbt_…`` tokens, ``Token`` otherwise) to support all NetBox token
            types.  Auth is only sent when the URL resolves to the same host as
            *base_url*, preventing credential leakage to off-host URLs.
        log_fn: Optional callable ``(msg: str) -> None`` invoked at verbose level
            when a network error is swallowed.  Pass ``handle.verbose_log``.
    """
    full_url = image_url_path if image_url_path.startswith("http") else base_url.rstrip("/") + image_url_path
    headers = {}
    if token:
        # Only send auth header when the effective URL is on the same host as base_url.
        from urllib.parse import urlparse

        base_host = urlparse(base_url).netloc
        target_host = urlparse(full_url).netloc
        if base_host == target_host:
            headers["Authorization"] = _build_auth_header(token)
    try:
        response = requests.get(full_url, headers=headers, verify=(not ignore_ssl), timeout=30)
    except requests.RequestException as exc:
        if log_fn is not None:
            log_fn(
                f"[yellow]Network error checking image {full_url}: {exc} "
                f"— treating as present to avoid spurious re-upload[/yellow]"
            )
        return "ok"
    if not response.ok:
        return "missing"
    content_type = response.headers.get("Content-Type", "")
    if content_type.startswith("text/") or content_type.startswith("application/json"):
        return "missing"
    return "ok"


def _is_image_hash_changed(local_path: str, hash_cache: dict) -> bool:
    """Return True if the local file's SHA-256 hash differs from the cached value.

    The cache maps local file paths to the SHA-256 hex-digest recorded at the time
    the file was last uploaded.  Comparing local-to-local (rather than local-to-remote)
    avoids the unreliability caused by NetBox re-encoding images on upload.

    Returns False when *local_path* is absent from *hash_cache* (conservative: avoids
    re-uploading images that have never been tracked).

    Args:
        local_path: Absolute filesystem path to the local image file.
        hash_cache: Dict mapping local path strings to SHA-256 hex-digests.
    """
    cached = hash_cache.get(local_path)
    if cached is None:
        return False
    try:
        with open(local_path, "rb") as fh:
            current = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return False
    return current != cached


def _load_image_hash_cache(path: str) -> dict:
    """Load the image-hash cache from *path* (JSON).  Returns an empty dict on any error."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_image_hash_cache(path: str, cache: dict) -> bool:
    """Persist *cache* to *path* as a JSON file, written atomically.

    Writes to a temporary file in the same directory, fsyncs it, then
    replaces *path* with ``os.replace`` so callers never see a truncated file.

    Returns True on success, False on I/O failure.  Callers should warn when
    False is returned: a missing cache entry causes ``_is_image_hash_changed``
    to report "unchanged", which would suppress re-uploads for locally edited
    images on the next run.
    """
    dir_ = os.path.dirname(os.path.abspath(path))
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        tmp_path = None  # successfully replaced; skip cleanup
        return True
    except Exception:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return False


def _store_image_hashes(cache: dict, images: dict) -> None:
    """Compute and store SHA-256 hashes for each local image path in *images*.

    *images* maps arbitrary string keys to local file paths.  Entries that cannot
    be read are silently skipped.  Updates *cache* in-place.
    """
    for path in images.values():
        try:
            with open(path, "rb") as fh:
                cache[path] = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            pass


def _delete_image_attachment(base_url: str, token: str, att_id: int, ignore_ssl: bool, handle) -> bool:
    """Delete a NetBox image attachment by ID via DELETE /api/extras/image-attachments/{id}/.

    Args:
        base_url: NetBox base URL.
        token: API token used for the Authorization header.
        att_id: Numeric ID of the image attachment to delete.
        ignore_ssl: When True, skip SSL certificate verification.
        handle: Log handler with a ``log`` method for error reporting.

    Returns:
        bool: True on success, False on any HTTP or network error.
    """
    url = f"{base_url}/api/extras/image-attachments/{att_id}/"
    headers = {"Authorization": _build_auth_header(token)}
    try:
        response = requests.delete(url, headers=headers, verify=(not ignore_ssl), timeout=30)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        handle.log(f"Error deleting image attachment {att_id}: {e}")
        return False


def _retry_on_connection_error(func, *args, **kwargs):
    """Call *func* with retries on transient connection errors.

    Retries up to ``_MAX_RETRIES`` times with exponential-ish backoff
    for ``ConnectionError`` and ``Timeout`` from requests/urllib3.
    Non-retryable exceptions propagate immediately.
    """
    for attempt in range(_MAX_RETRIES + 1):
        try:
            return func(*args, **kwargs)
        except _RETRYABLE_EXCEPTIONS:
            if attempt >= _MAX_RETRIES:
                raise
            wait = _RETRY_BACKOFF[attempt] if attempt < len(_RETRY_BACKOFF) else _RETRY_BACKOFF[-1]
            time.sleep(wait)


# Module type scalar properties that can be compared and updated.
# Loaded from the cloned devicetype-library schema at runtime; the list below
# serves as a fallback when the schema is not yet available (e.g. before the
# first repo clone).  Identity fields (manufacturer, model) and complex objects
# (attribute_data) are excluded by the schema reader.
_MODULE_TYPE_PROPERTIES_FALLBACK = [
    "part_number",
    "description",
    "comments",
    "airflow",
    "weight",
    "weight_unit",
]

_MODULE_TYPE_SCHEMA_EXCLUDE = {"manufacturer", "model", "attribute_data", "profile"}


@lru_cache(maxsize=1)
def _load_module_type_properties():
    """Load module type scalar properties from the schema, falling back to hardcoded list.

    The result is cached after the first call, which happens after the repo checkout
    so the schema files are available.
    """
    try:
        from core import settings as _settings

        props = load_properties_for_type(
            os.path.join(_settings.REPO_PATH, "schema"),
            "moduletype",
            exclude=_MODULE_TYPE_SCHEMA_EXCLUDE,
        )
        return props if props else list(_MODULE_TYPE_PROPERTIES_FALLBACK)
    except (ImportError, AttributeError):
        return list(_MODULE_TYPE_PROPERTIES_FALLBACK)


# Sentinel used to distinguish "attribute missing from record" from a genuine
# None/null value returned by NetBox.  When a property is in the schema-derived
# comparison list but was not fetched by the GraphQL query, getattr returns this
# sentinel and the property is skipped to avoid false-positive change detection.
_MISSING = object()

# Supported image file extensions for module-type image uploads
IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
    ".tif",
    ".tiff",
    ".svg",
}

# Maximum number of IDs per endpoint.filter() call to avoid excessively long URLs.
FILTER_CHUNK_SIZE = 200


def _chunked(iterable, size):
    """Yield successive *size*-length chunks from *iterable*.

    Accepts any iterable; does not require a Sequence.
    """
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk


def _image_dir_for_yaml(src_file: str, src_segment: str, dst_segment: str) -> "Path | None":
    """Derive an image directory path from a YAML source file path.

    Replaces the last occurrence of *src_segment* in the parent-directory parts of
    *src_file* with *dst_segment* and returns the resulting Path.  Returns None when
    *src_file* is empty, equals ``_UNKNOWN_SRC``, or does not contain *src_segment*.
    """
    if not src_file or src_file == _UNKNOWN_SRC:
        return None
    parts = list(Path(src_file).parent.parts)
    try:
        idx = len(parts) - 1 - parts[::-1].index(src_segment)
    except ValueError:
        return None
    parts[idx] = dst_segment
    return Path(*parts)


# from pynetbox import RequestError as APIRequestError


def _count_actionable_component_changes(changes, remove_components):
    """Return the count of changes in *changes* that will issue an API call.

    Non-removal changes always qualify; removal changes only qualify when
    *remove_components* is enabled.  Removal-only diffs with the flag off
    issue zero API calls and must not be treated as attempted.
    """
    return sum(
        1
        for c in changes
        if c.change_type in (ChangeType.COMPONENT_CHANGED, ChangeType.COMPONENT_ADDED)
        or (remove_components and c.change_type == ChangeType.COMPONENT_REMOVED)
    )


class NetBox:
    """Interface to the NetBox API for importing device and module types."""

    def __init__(self, settings, handle):
        """Initialize NetBox API connection, verify version compatibility, and load manufacturers/device types.

        Args:
            settings: Settings module with NETBOX_URL, NETBOX_TOKEN, IGNORE_SSL_ERRORS, and NETBOX_FEATURES.
            handle (LogHandler): Logging handler for progress and error messages.
        """
        self.counter = Counter(
            added=0,
            components_added=0,
            manufacturer=0,
            module_added=0,
            module_updated=0,
            module_update_failed=0,
            module_partial_update=0,
            rack_type_added=0,
            rack_type_updated=0,
            images=0,
            properties_updated=0,
            components_updated=0,
            components_removed=0,
            device_types_failed=0,
        )
        self.outcomes = OutcomeRegistry()
        self.url = settings.NETBOX_URL
        self.token = settings.NETBOX_TOKEN
        self.handle = handle
        self.netbox = None
        self.ignore_ssl = settings.IGNORE_SSL_ERRORS
        self.modules = False
        self.new_filters = False
        self.m2m_front_ports = False  # True for NetBox >= 4.5 (M2M port mappings)
        self.rack_types = False
        self.force_resolve_conflicts = False
        self.remove_unmanaged_types = False
        self.verify_images = False
        self._module_image_details: dict = {}  # populated by _fetch_module_type_existing_images in verify mode
        # Image hash cache: local file path -> SHA-256 hex-digest at last upload time.
        # Used by --verify-images to detect whether the local file changed since last upload,
        # avoiding the unreliability of comparing local bytes to NetBox-served bytes (NetBox
        # re-encodes images).  Stored under ~/.cache/nb-dt-import/ (XDG_CACHE_HOME respected).
        _cache_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "nb-dt-import"
        try:
            _cache_dir.mkdir(parents=True, exist_ok=True)
            self._image_hash_cache_path = str(_cache_dir / "image-hashes.json")
        except OSError:
            self.handle.verbose_log(
                "[yellow]Warning: could not create image hash cache directory "
                f"({_cache_dir}); hash-based re-upload detection will be disabled "
                "for this run.[/yellow]"
            )
            self._image_hash_cache_path = None
        self._image_hash_cache: dict = _load_image_hash_cache(self._image_hash_cache_path)
        self.connect_api()
        self.verify_compatibility()
        self.graphql = NetBoxGraphQLClient(
            self.url,
            self.token,
            self.ignore_ssl,
            log_handler=self.handle,
            page_size=settings.GRAPHQL_PAGE_SIZE,
        )
        try:
            self.existing_manufacturers = self.get_manufacturers()
        except GraphQLError as e:
            system_exit(f"GraphQL error: {e}")
        try:
            self.device_types = DeviceTypes(
                self.netbox,
                self.handle,
                self.counter,
                self.ignore_ssl,
                self.new_filters,
                graphql=self.graphql,
                m2m_front_ports=self.m2m_front_ports,
                max_threads=settings.PRELOAD_THREADS,
            )
        except Exception as e:
            system_exit(f"Error initializing device types: {e}")
        self._change_detector: ChangeDetector | None = None

    @property
    def change_detector(self) -> "ChangeDetector":
        """Lazily initialised, reused :class:`ChangeDetector` instance."""
        if self._change_detector is None:
            self._change_detector = ChangeDetector(
                self.device_types,
                self.handle,
                remove_unmanaged_types=self.remove_unmanaged_types,
            )
        return self._change_detector

    def load_vendor(self, manufacturer_slug: str):
        """Load device types for *manufacturer_slug* and reset per-vendor state.

        Delegates to :meth:`DeviceTypes.load_for_vendor` to populate the device
        type lookup indexes, then clears the cached :class:`ChangeDetector` so
        that the next access constructs a fresh instance against the new data.

        Args:
            manufacturer_slug (str): Manufacturer slug to load.
        """
        self.device_types.load_for_vendor(manufacturer_slug)
        self._change_detector = None
        self._module_image_details = {}  # stale module entries must not bleed across vendors

    def _persist_hash_cache(self) -> None:
        """Save the image hash cache and warn once if the write fails."""
        if self._image_hash_cache_path is None:
            return
        if not _save_image_hash_cache(self._image_hash_cache_path, self._image_hash_cache):
            self.handle.verbose_log(
                "[yellow]Warning: failed to persist image hash cache; "
                "local image edits may not be detected on the next run.[/yellow]"
            )

    def connect_api(self):
        """Connect to the NetBox API using the stored URL and token credentials."""
        try:
            self.netbox = pynetbox.api(self.url, token=self.token, threading=True)
            if self.ignore_ssl:
                self.handle.verbose_log("IGNORE_SSL_ERRORS is True, catching exception and disabling SSL verification.")
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                self.netbox.http_session.verify = False
        except Exception as e:
            self.handle.exception("Exception", "NetBox API Error", e)

    def get_api(self):
        """Return the underlying pynetbox API instance."""
        return self.netbox

    def get_counter(self):
        """Return the shared operation counter."""
        return self.counter

    def verify_compatibility(self):
        """Check the connected NetBox version and configure feature flags accordingly.

        Sets ``self.modules = True`` for NetBox >= 3.2 and ``self.new_filters = True``
        for >= 4.1. Logs the detected version when the new-filter flag is enabled.
        """
        # nb.version should be the version in the form '3.2'
        # Strip non-numeric suffixes (e.g. "4.1-beta") before converting to int.
        try:
            nb_version = self.netbox.version
        except requests.exceptions.ProxyError as e:
            system_exit(
                f"Proxy error while connecting to NetBox at {self.url}: {e}\n"
                f"Hint: If NetBox is running locally, ensure that the NETBOX_URL host "
                f"is included in your 'no_proxy' / 'NO_PROXY' environment variable "
                f"(both with and without brackets for IPv6, e.g. '::1,[::1]')."
            )
        except requests.exceptions.ConnectionError as e:
            system_exit(_fmt_connection_error(self.url, e))
        except pynetbox.core.query.RequestError as e:
            endpoint = getattr(e, "base", self.url)
            status = getattr(e.req, "status_code", "?") if hasattr(e, "req") else "?"
            reason = getattr(e.req, "reason", "") if hasattr(e, "req") else ""
            body = str(getattr(e, "error", "") or "").strip()[:500]
            details = f"HTTP {status} {reason}".strip()
            msg = f"NetBox returned an error connecting to {endpoint} ({details})."
            if body:
                msg += f"\nResponse body (may be from an intermediate proxy):\n{body}"
            msg += f"\nHint: Verify that {self.url} is reachable and not blocked by a proxy."
            system_exit(msg)
        _raw = [int(re.sub(r"\D.*", "", x.strip()) or "0") for x in nb_version.split(".")]
        version_split = (_raw + [0, 0])[:2]  # pad to (major, minor) to guard against single-component strings

        # Later than 3.2
        # Might want to check for the module-types entry as well?
        if version_split[0] > 3 or (version_split[0] == 3 and version_split[1] >= 2):
            self.modules = True

        # check if version >= 4.1 in order to use new filter names (https://github.com/netbox-community/netbox/issues/15410)
        if version_split[0] > 4 or (version_split[0] == 4 and version_split[1] >= 1):
            self.new_filters = True
            self.rack_types = True
            self.handle.log(f"Netbox version {self.netbox.version} found. Using new filters.")

        # NetBox 4.5 replaced FrontPortTemplate.rear_port (FK) + rear_port_position (int)
        # with a ManyToMany through table (PortMapping).  The creation and read APIs differ.
        # https://github.com/netbox-community/netbox/issues/20564
        if version_split[0] > 4 or (version_split[0] == 4 and version_split[1] >= 5):
            self.m2m_front_ports = True
            self.handle.log(f"Netbox version {self.netbox.version} found. Using M2M front/rear port mappings.")

    def get_manufacturers(self):
        """Fetch all manufacturers from NetBox via GraphQL and return them indexed by name."""
        return self.graphql.get_manufacturers()

    def create_manufacturers(self, vendors):
        """Create any vendors not already present in NetBox as manufacturers.

        Skips vendors whose name or slug already exists. Logs creation attempts and any
        API errors. Updates the shared counter for each manufacturer created.

        Args:
            vendors (list[dict]): Vendor dicts with at least a "name" key; "slug" is added if absent.
        """
        # Get existing manufacturers (name + slug)
        self.existing_manufacturers = self.get_manufacturers()
        existing_slugs = {item.slug for item in self.existing_manufacturers.values()}
        existing_names = {item.name for item in self.existing_manufacturers.values()}

        to_create = []

        for vendor in vendors:
            # Ensure slug is set
            vendor.setdefault("slug", vendor["name"].lower().replace(" ", "-"))

            # Check existence by name or slug
            if vendor["name"] in existing_names or vendor["slug"] in existing_slugs:
                self.handle.verbose_log(f"Manufacturer Exists: {vendor['name']} (slug: {vendor['slug']})")
            else:
                to_create.append(vendor)
                self.handle.verbose_log(f"Manufacturer queued for addition: {vendor['name']} (slug: {vendor['slug']})")

        # Only if there are manufacturers to create → API call
        if to_create:
            self.handle.log(f"Creating {len(to_create)} new manufacturers...")
            try:
                created_manufacturers = _retry_on_connection_error(self.netbox.dcim.manufacturers.create, to_create)
                for manufacturer in created_manufacturers:
                    self.handle.verbose_log(f"Manufacturer Created: {manufacturer.name} - {manufacturer.id}")
                    self.counter.update({"manufacturer": 1})
            except pynetbox.RequestError as request_error:
                # Log error with detailed API error message
                self.handle.log(f"Error creating manufacturers: {request_error.error}")
            except _RETRYABLE_EXCEPTIONS as e:
                self.handle.log(f"Connection error creating manufacturers after {_MAX_RETRIES} retries: {e}")
        else:
            self.handle.verbose_log("No new manufacturers to create.")

    def _resolve_image_paths(self, device_type, src_file):
        """Discover local elevation-image paths for the device type and clean image flags.

        Locates the elevation-images directory relative to *src_file*, resolves
        front_image/rear_image globs, logs missing files, and removes the flag
        keys from *device_type* in-place.

        Args:
            device_type (dict): Parsed YAML device-type dict; ``front_image`` /
                ``rear_image`` keys are removed in-place.
            src_file (str): Filesystem path to the YAML source file.

        Returns:
            dict: Mapping of image kind (``"front_image"`` / ``"rear_image"``) to
                local file path for images that were found on disk.
        """
        saved_images = {}
        _image_base_path = _image_dir_for_yaml(src_file, "device-types", "elevation-images")
        image_base = str(_image_base_path) if _image_base_path is not None else None
        for i in ["front_image", "rear_image"]:
            if i in device_type:
                if device_type[i] and image_base is not None and device_type.get("slug"):
                    image_glob = f"{image_base}/{device_type['slug']}.{i.split('_')[0]}.*"
                    images = sorted(glob.glob(image_glob, recursive=False))
                    if images:
                        saved_images[i] = images[0]
                    else:
                        self.handle.log(f"Error locating image file using '{image_glob}'")
                elif device_type[i] and image_base is None:
                    self.handle.verbose_log(
                        f"Skipping image discovery for '{device_type.get('slug', '')}' "
                        "because source path lacks 'device-types'."
                    )
                del device_type[i]
        return saved_images

    def _try_resolve_and_retry_device_type_update(self, dt, device_type, updates, error):
        """Classify a failed device-type PATCH and, if safe, remediate then retry.

        Inspects *error* via :func:`classify_device_type_update_failure`.  When
        the failure is a recognised constraint, blocking templates exist, AND
        no live devices reference this type, AND the operator has opted in via
        ``--force-resolve-conflicts``, the remediation steps are executed and
        the original PATCH is retried once.  Otherwise an actionable hint is
        logged and ``False`` is returned (the caller will count this as a
        failure via :meth:`_log_device_type_change_outcome`).

        Args:
            dt: pynetbox device-type record being updated.
            device_type (dict): Parsed YAML device-type dict.
            updates (dict): PATCH payload that previously failed.
            error: ``pynetbox.RequestError`` instance from the failed PATCH.

        Returns:
            tuple[bool, FailureResolution | None]: ``(retry_succeeded, resolution)``
            where ``resolution`` is the classifier's output (or ``None`` if the
            classifier itself raised), useful for downstream reporting.
        """
        try:
            resolution = classify_device_type_update_failure(
                error.error,
                netbox=self.netbox,
                device_type_id=dt.id,
                device_type_yaml=device_type,
                new_filters=self.new_filters,
            )
        except Exception as exc:  # defensive: classifier must never break the run
            self.handle.verbose_log(f"Failure classifier raised {type(exc).__name__}: {exc}")
            return False, None

        if resolution.kind == FailureKind.UNHANDLED:
            return False, resolution

        # Build a structured operator-facing log so the constraint and its
        # remediation path are crystal clear.
        if resolution.blocking_objects:
            blockers = ", ".join(resolution.blocking_objects[:10])
            if len(resolution.blocking_objects) > 10:
                blockers += f", … (+{len(resolution.blocking_objects) - 10} more)"
            self.handle.log(f"Constraint analysis for {dt.model}: blocked by {blockers}")
        if resolution.description:
            self.handle.log(f"  {resolution.description}")
        if resolution.hint:
            self.handle.log(f"  Hint: {resolution.hint}")

        if resolution.kind == FailureKind.MANUAL_REQUIRED or not resolution.is_actionable:
            return False, resolution

        if not self.force_resolve_conflicts:
            return False, resolution

        # Opt-in destructive remediation.
        self.handle.log(
            f"Auto-resolving constraint for {dt.model} "
            f"(--force-resolve-conflicts; {len(resolution.remediation_steps)} step(s))"
        )
        try:
            for step in resolution.remediation_steps:
                step()
        except Exception as exc:
            self.handle.log(f"Auto-resolve failed for {dt.model}: {exc}")
            return False, resolution

        # Retry the original PATCH exactly once.
        try:
            _retry_on_connection_error(
                self.netbox.dcim.device_types.update,
                [{"id": dt.id, **updates}],
            )
            dt.update(updates)
            return True, resolution
        except pynetbox.RequestError as e:
            self.handle.log(f"Retry after auto-resolve still failed for {dt.model}: {e.error}")
            return False, resolution
        except _RETRYABLE_EXCEPTIONS as e:
            self.handle.log(f"Connection error during retry after auto-resolve for {dt.model}: {e}")
            return False, resolution

    def _log_device_type_change_outcome(
        self,
        dt,
        dt_change,
        *,
        property_attempted,
        property_succeeded,
        component_delta,
        actionable_count,
        failure_resolution=None,
    ):
        """Emit the right post-update log for an existing device type.

        Distinguishes "actually updated", "partial update" (property PATCH
        failed but components ran, or only some component changes succeeded),
        and "completely failed" (PATCH was the only action and it failed, or
        component API calls were issued but all failed) so the operator-visible
        log no longer reports "Device Type Updated" when nothing was applied.

        When the operation failed or was partial, also records a structured
        outcome into :attr:`outcomes` so the end-of-run summary can render an
        itemised report.

        Args:
            dt: pynetbox device-type record.
            dt_change: ChangeEntry for this device-type.
            property_attempted (bool): True if a property PATCH was issued.
            property_succeeded (bool): True if the property PATCH (or its retry)
                applied cleanly.
            component_delta (int): Number of component operations that succeeded
                (sum of counter deltas for components_updated, components_added,
                components_removed after the API calls).
            actionable_count (int): Number of component changes that issued API
                calls (non-removal changes, or removals with --remove-components
                enabled).
            failure_resolution: Optional :class:`FailureResolution` whose
                ``description``, ``blocking_objects`` and ``hint`` will be
                attached to the registry record when the update failed.
        """
        identity = f"{dt.manufacturer.name}/{dt.model}"
        component_attempted = actionable_count > 0
        component_succeeded = component_delta > 0
        something_applied = property_succeeded or component_succeeded
        if something_applied:
            is_full_success = (not property_attempted or property_succeeded) and (
                not component_attempted or component_delta == actionable_count
            )
            if is_full_success:
                if component_succeeded and not property_succeeded:
                    # Component-only update: no property change was attempted or needed.
                    self.counter.update({"device_types_component_updates": 1})
                prop_count = 1 if property_succeeded else 0
                comp_suffix = "; skipping component creation." if component_delta == 0 else "."
                self.handle.verbose_log(
                    f"Device Type Updated: {dt.manufacturer.name} - {dt.model} - {dt.id}. "
                    f"Applied {prop_count} property and {component_delta} component change(s)" + comp_suffix
                )
            else:
                if component_delta > 0:
                    self.counter.update({"device_types_component_updates": 1})
                reason_parts = []
                if property_attempted and not property_succeeded:
                    reason_parts.append("Property PATCH failed")
                if component_attempted:
                    if component_delta < actionable_count:
                        reason_parts.append(f"applied {component_delta} of {actionable_count} component change(s)")
                    else:
                        reason_parts.append(f"applied {component_delta} component change(s)")
                reason = "; ".join(reason_parts) + "." if reason_parts else "Partial update."
                self.handle.verbose_log(
                    f"Device Type Partially Updated: {dt.manufacturer.name} - {dt.model} - {dt.id}. {reason}"
                )
                self.outcomes.record(
                    EntityKind.DEVICE_TYPE,
                    identity,
                    Outcome.PARTIAL,
                    reason=reason,
                    blocking_objects=(failure_resolution.blocking_objects if failure_resolution else None),
                    hint=(failure_resolution.hint if failure_resolution else None),
                )
        elif property_attempted or component_attempted:
            self.counter.update({"device_types_failed": 1})
            self.handle.log(
                f"Device Type Update Failed: {dt.manufacturer.name} - {dt.model} - {dt.id}. "
                f"Attempted {1 if property_attempted else 0} property PATCH and "
                f"{actionable_count} component change(s); "
                "no changes were applied (see error above)."
            )
            self.outcomes.record(
                EntityKind.DEVICE_TYPE,
                identity,
                Outcome.FAILED,
                reason=(
                    failure_resolution.description
                    if failure_resolution
                    else (
                        "Property PATCH and component updates failed."
                        if property_attempted and component_attempted
                        else "Property PATCH failed."
                        if property_attempted
                        else "Component updates failed."
                    )
                ),
                blocking_objects=(failure_resolution.blocking_objects if failure_resolution else None),
                hint=(failure_resolution.hint if failure_resolution else None),
            )
        else:
            self.handle.verbose_log(
                f"Device Type Cached: {dt.manufacturer.name} - {dt.model} - {dt.id}. "
                "No property or component changes applied."
            )

    def _filter_images_for_upload(self, dt, saved_images):
        """Remove from *saved_images* any image that does not need uploading.

        For each image kind present in *saved_images* that already has a record in NetBox,
        either removes the entry unconditionally (default mode) or verifies physical
        presence and local-file hash (``--verify-images`` mode) before deciding.

        In ``--verify-images`` mode two independent checks are run:

        1. **HTTP accessibility** — an HTTP GET confirms the file exists on the server.
           A non-2xx response means the file is physically missing.
        2. **Local-file hash** — the current SHA-256 of the local image is compared to
           the hash recorded in the image-hash cache at the time of the last upload.
           A mismatch means the local source file was updated since the last import.

        NetBox re-encodes images on upload so comparing local bytes to remote bytes is
        unreliable; the local-hash cache approach is used instead.

        Args:
            dt: pynetbox device type record for the existing device type.
            saved_images (dict): Mapping of image kind to local file path; modified in-place.
        """
        for image_kind in ("front_image", "rear_image"):
            if image_kind not in saved_images:
                continue
            db_url = getattr(dt, image_kind, None)
            if not db_url:
                continue  # no record in NetBox yet → keep for upload
            label = image_kind.replace("_", " ").capitalize()
            if not self.verify_images:
                self.handle.verbose_log(f"{label} already exists for {dt.model}, skipping upload.")
                del saved_images[image_kind]
                continue
            # --verify-images: Step 1 — check physical presence via HTTP
            status = _check_image_url(self.url, db_url, self.ignore_ssl, self.token, log_fn=self.handle.verbose_log)
            if status == "missing":
                self.handle.verbose_log(f"{label} is missing on server for {dt.model}, will re-upload.")
                continue  # keep in saved_images for upload
            # --verify-images: Step 2 — check if local file changed since last upload
            if _is_image_hash_changed(saved_images[image_kind], self._image_hash_cache):
                self.handle.verbose_log(f"{label} content has changed for {dt.model}, will re-upload.")
                continue  # keep in saved_images for upload
            # Both checks passed — image is present and unchanged;
            # seed hash cache so future local edits will be detected.
            local_path = saved_images[image_kind]
            if local_path not in self._image_hash_cache:
                _store_image_hashes(self._image_hash_cache, {image_kind: local_path})
                self._persist_hash_cache()
            self.handle.verbose_log(f"{label} verified OK for {dt.model}, skipping upload.")
            del saved_images[image_kind]

    def _handle_existing_device_type(
        self,
        dt,
        device_type,
        manufacturer_slug,
        saved_images,
        only_new,
        dt_change,
        remove_components,
    ):
        """Process an existing device type: upload images, apply updates, and log status.

        Handles image deduplication and upload for already-existing device types,
        optionally applies property and component changes when *dt_change* is set,
        and logs an appropriate status message.

        Args:
            dt: pynetbox device type record for the existing device type.
            device_type (dict): Parsed YAML device-type dict.
            manufacturer_slug (str): Manufacturer slug used for change lookup.
            saved_images (dict): Mapping of image kind to local file path.
            only_new (bool): When True, skip update logic after image handling.
            dt_change: ChangeEntry for this device type, or None if no changes detected.
            remove_components (bool): When True (with *dt_change*), remove components
                absent from the YAML.
        """
        if saved_images:
            self._filter_images_for_upload(dt, saved_images)
            if saved_images:
                self.device_types.upload_images(self.url, self.token, saved_images, dt.id)
                _store_image_hashes(self._image_hash_cache, saved_images)
                self._persist_hash_cache()

        if only_new:
            self.handle.verbose_log(
                f"Device Type Cached: {dt.manufacturer.name} - {dt.model} - {dt.id}. "
                f"Skipping updates (images already handled)."
            )
            return

        if dt_change is not None:
            property_attempted = False
            property_succeeded = False
            component_delta = 0
            actionable_count = 0
            failure_resolution = None

            # Apply property changes (exclude image properties — uploads are handled separately)
            if dt_change.property_changes:
                updates = {
                    pc.property_name: pc.new_value
                    for pc in dt_change.property_changes
                    if pc.property_name not in ("front_image", "rear_image")
                }
                if updates:
                    property_attempted = True
                    try:
                        _retry_on_connection_error(self.netbox.dcim.device_types.update, [{"id": dt.id, **updates}])
                        dt.update(updates)  # keep local cache in sync
                        self.counter.update({"properties_updated": 1})
                        property_succeeded = True
                        self.handle.verbose_log(f"Updated device type {dt.model} properties: {list(updates.keys())}")
                    except pynetbox.RequestError as e:
                        self.handle.log(f"Error updating device type {dt.model}: {e.error}")
                        retried_ok, failure_resolution = self._try_resolve_and_retry_device_type_update(
                            dt, device_type, updates, e
                        )
                        if retried_ok:
                            self.counter.update({"properties_updated": 1})
                            property_succeeded = True
                            self.handle.verbose_log(
                                f"Updated device type {dt.model} properties after auto-resolve: {list(updates.keys())}"
                            )
                    except _RETRYABLE_EXCEPTIONS as e:
                        self.handle.log(
                            f"Connection error updating device type {dt.model} after {_MAX_RETRIES} retries: {e}"
                        )

            # Apply component changes
            if dt_change.component_changes:
                actionable_count = _count_actionable_component_changes(dt_change.component_changes, remove_components)
                before_components = (
                    self.counter["components_updated"],
                    self.counter["components_added"],
                    self.counter["components_removed"],
                )
                self.device_types.update_components(
                    device_type,
                    dt.id,
                    dt_change.component_changes,
                    parent_type="device",
                )
                if remove_components:
                    self.device_types.remove_components(dt.id, dt_change.component_changes, parent_type="device")
                after_components = (
                    self.counter["components_updated"],
                    self.counter["components_added"],
                    self.counter["components_removed"],
                )
                component_delta = sum(after_components) - sum(before_components)

            # Distinguish full update, partial, and complete failure.
            self._log_device_type_change_outcome(
                dt,
                dt_change,
                property_attempted=property_attempted,
                property_succeeded=property_succeeded,
                component_delta=component_delta,
                actionable_count=actionable_count,
                failure_resolution=failure_resolution,
            )
        else:
            self.handle.verbose_log(
                f"Device Type Cached: {dt.manufacturer.name} - {dt.model} - {dt.id}. "
                "No pending updates; skipping component creation."
            )

    def _create_new_device_type(self, device_type, src_file):
        """Attempt to create a new device type record in NetBox.

        Args:
            device_type (dict): Parsed YAML device-type dict to create.
            src_file (str): Filesystem path to the YAML source file (used in error messages).

        Returns:
            tuple[object | None, bool]: ``(dt, should_continue)`` where *dt* is the
                created pynetbox record (or None on failure) and *should_continue* is
                True when the caller should skip to the next iteration.
        """
        try:
            dt = _retry_on_connection_error(self.netbox.dcim.device_types.create, device_type)
            self.counter.update({"added": 1})
            self.handle.verbose_log(f"Device Type Created: {dt.manufacturer.name} - " + f"{dt.model} - {dt.id}")
            return dt, False
        except pynetbox.RequestError as e:
            self.handle.log(
                f"Error {e.error} creating device type:"
                f" {device_type.get('manufacturer', {}).get('slug', '')} {device_type.get('model', '')}"
                f" (Context: {src_file})"
            )
            return None, True
        except _RETRYABLE_EXCEPTIONS as e:
            self.handle.log(
                f"Connection error creating device type"
                f" {device_type.get('manufacturer', {}).get('slug', '')} {device_type.get('model', '')}"
                f" after {_MAX_RETRIES} retries: {e} (Context: {src_file})"
            )
            return None, True

    def _create_device_type_components(self, device_type, dt_id, src_file, saved_images):
        """Create all component templates and upload images for a newly created device type.

        Args:
            device_type (dict): Parsed YAML device-type dict with component lists.
            dt_id: NetBox ID of the newly created device type.
            src_file (str): Filesystem path to the YAML source file (for front-port context).
            saved_images (dict): Mapping of image kind to local file path for upload.
        """
        if "interfaces" in device_type:
            self.device_types.create_interfaces(device_type["interfaces"], dt_id)
        if "power-ports" in device_type:
            self.device_types.create_power_ports(device_type["power-ports"], dt_id)
        if "console-ports" in device_type:
            self.device_types.create_console_ports(device_type["console-ports"], dt_id)
        if "power-outlets" in device_type:
            self.device_types.create_power_outlets(device_type["power-outlets"], dt_id)
        if "console-server-ports" in device_type:
            self.device_types.create_console_server_ports(device_type["console-server-ports"], dt_id)
        if "rear-ports" in device_type:
            self.device_types.create_rear_ports(device_type["rear-ports"], dt_id)
        if "front-ports" in device_type:
            self.device_types.create_front_ports(device_type["front-ports"], dt_id, context=src_file)
        if "device-bays" in device_type:
            self.device_types.create_device_bays(device_type["device-bays"], dt_id)
        if self.modules and "module-bays" in device_type:
            self.device_types.create_module_bays(device_type["module-bays"], dt_id)
        if saved_images:
            self.device_types.upload_images(self.url, self.token, saved_images, dt_id)
            _store_image_hashes(self._image_hash_cache, saved_images)
            self._persist_hash_cache()

    def create_device_types(
        self,
        device_types_to_add,
        progress=None,
        only_new=False,
        update=False,
        change_report=None,
        remove_components=False,
    ):
        """Create or update device types and their component templates in NetBox.

        For each device type:

        - Images are uploaded to existing types if the file exists locally and is not yet in NetBox.
        - If the type already exists and ``only_new`` is True, it is skipped (after image handling).
        - If ``update`` is True and a matching change entry exists, property changes are applied
          and component additions/removals are performed.
        - If the type does not exist, it is created along with all component templates.

        Args:
            device_types_to_add (list[dict]): Parsed YAML device-type dicts to process.
            progress: Optional progress iterator wrapping ``device_types_to_add``.
            only_new (bool): If True, skip update logic for existing device types.
            update (bool): If True, apply property/component changes to existing types.
            change_report (ChangeReport | None): Pre-computed change report; required when ``update`` is True.
            remove_components (bool): If True (with ``update``), remove components absent from YAML.
        """
        # Note: Caching is now done externally before this method via preload_all_components()

        iterator = progress if progress is not None else device_types_to_add
        # Pre-index change_report for O(1) lookup instead of an O(M) scan per device type.
        change_by_key = (
            {(c.manufacturer_slug, c.model): c for c in change_report.modified_device_types}
            if update and change_report
            else {}
        )
        for device_type in iterator:
            # Remove file base path
            src_file = device_type["src"]
            del device_type["src"]

            saved_images = self._resolve_image_paths(device_type, src_file)

            # Look up by (manufacturer_slug, model), with fallback to (manufacturer_slug, slug).
            # Using .get() to avoid masking real KeyErrors from accesses inside the logic below.
            manufacturer_slug = device_type.get("manufacturer", {}).get("slug", "")
            device_slug = device_type.get("slug", "")

            # Try primary lookup by model
            dt = self.device_types.existing_device_types.get((manufacturer_slug, device_type.get("model", "")))

            # Fallback to lookup by slug if model lookup failed
            if dt is None and device_slug:
                dt = self.device_types.existing_device_types_by_slug.get((manufacturer_slug, device_slug))
                if dt is not None:
                    self.handle.verbose_log(
                        f"Device Type found by slug (model mismatch): NetBox has '{dt.model}', "
                        f"YAML has '{device_type.get('model', '')}'"
                    )

            if dt is not None:
                dt_change = change_by_key.get((manufacturer_slug, device_type.get("model", "")))
                self._handle_existing_device_type(
                    dt,
                    device_type,
                    manufacturer_slug,
                    saved_images,
                    only_new,
                    dt_change,
                    remove_components,
                )
                continue

            # Device type doesn't exist - create it
            dt, should_continue = self._create_new_device_type(device_type, src_file)
            if should_continue:
                continue

            self._create_device_type_components(device_type, dt.id, src_file, saved_images)

    def get_existing_module_types(self):
        """Fetch all module types from NetBox via GraphQL and return them indexed by manufacturer slug and model.

        Returns:
            dict: ``{manufacturer_slug: {model: DotDict_record}}``
        """
        return self.graphql.get_module_types()

    def get_existing_rack_types(self):
        """Fetch all rack types from NetBox via GraphQL and return them indexed by manufacturer slug and model.

        Returns:
            dict: ``{manufacturer_slug: {model: record}}``
        """
        return self.graphql.get_rack_types()

    def create_rack_types(self, rack_types, progress=None, only_new=False, all_rack_types=None):
        """Create or update rack types in NetBox from parsed YAML definitions.

        For each rack type: looks up by (manufacturer_slug, model). If it already exists and
        ``only_new`` is True, skips it. Otherwise compares scalar fields and issues a bulk
        update for any changed values. If it does not exist, creates it.

        Args:
            rack_types (list[dict]): Parsed YAML rack-type dicts to process.
            progress: Optional progress iterator wrapping ``rack_types``.
            only_new (bool): If True, skip updates for existing rack types.
            all_rack_types (dict | None): Existing rack types cache; fetched if None.
        """
        if not rack_types:
            return

        if all_rack_types is None:
            all_rack_types = self.get_existing_rack_types()

        iterator = progress if progress is not None else rack_types
        for rack_type in iterator:
            src_file = rack_type.get("src", _UNKNOWN_SRC)
            if "src" in rack_type:
                del rack_type["src"]

            manufacturer_slug = rack_type.get("manufacturer", {}).get("slug", "")
            model = rack_type.get("model", "")
            existing = all_rack_types.get(manufacturer_slug, {}).get(model)

            if existing is not None:
                self.handle.verbose_log(f"Rack Type Cached: {manufacturer_slug} - {model} - {existing.id}")
                if only_new:
                    continue

                fields_to_compare = [
                    "slug",
                    "form_factor",
                    "width",
                    "u_height",
                    "starting_unit",
                    "outer_width",
                    "outer_height",
                    "outer_depth",
                    "outer_unit",
                    "mounting_depth",
                    "weight",
                    "max_weight",
                    "weight_unit",
                    "desc_units",
                    "comments",
                    "description",
                ]
                updates = {
                    field: rack_type[field]
                    for field in fields_to_compare
                    if field in rack_type and not values_equal(rack_type[field], getattr(existing, field, None))
                }
                if updates:
                    try:
                        _retry_on_connection_error(self.netbox.dcim.rack_types.update, [{"id": existing.id, **updates}])
                        self.counter.update({"rack_type_updated": 1})
                        self.handle.verbose_log(
                            f"Rack Type Updated: {manufacturer_slug} - {model} - {existing.id} "
                            f"(changed: {list(updates.keys())})"
                        )
                    except pynetbox.RequestError as e:
                        self.handle.log(f"Error updating Rack Type {model}: {e.error} (Context: {src_file})")
                    except _RETRYABLE_EXCEPTIONS as e:
                        self.handle.log(
                            f"Connection error updating Rack Type {model} after {_MAX_RETRIES} retries:"
                            f" {e} (Context: {src_file})"
                        )
                else:
                    self.handle.verbose_log(f"Rack Type Unchanged: {manufacturer_slug} - {model} - {existing.id}")
            else:
                try:
                    rt = _retry_on_connection_error(self.netbox.dcim.rack_types.create, rack_type)
                    self.counter.update({"rack_type_added": 1})
                    all_rack_types.setdefault(manufacturer_slug, {})[model] = rt
                    self.handle.verbose_log(f"Rack Type Created: {manufacturer_slug} - {model} - {rt.id}")
                except pynetbox.RequestError as excep:
                    self.handle.log(f"Error creating Rack Type: {excep.error} (Context: {src_file})")
                except _RETRYABLE_EXCEPTIONS as e:
                    self.handle.log(
                        f"Connection error creating Rack Type {model} after {_MAX_RETRIES} retries:"
                        f" {e} (Context: {src_file})"
                    )

    @staticmethod
    def _find_existing_module_type(module_type, all_module_types):
        """Look up a module type in *all_module_types* by model name.

        Args:
            module_type (dict): Parsed YAML module-type dict with "manufacturer" and "model" keys.
            all_module_types (dict): Nested mapping ``{manufacturer_slug: {model: record}}``.

        Returns:
            pynetbox Record | None: Matching record, or None if not found.
        """
        manufacturer_slug = module_type["manufacturer"]["slug"]
        existing_for_vendor = all_module_types.get(manufacturer_slug, {})
        return existing_for_vendor.get(module_type["model"])

    @staticmethod
    def filter_new_module_types(module_types, all_module_types):
        """Return module types that do not yet exist in NetBox.

        Args:
            module_types (list[dict]): Parsed YAML module-type dicts to filter.
            all_module_types (dict): Existing module types indexed by manufacturer slug and model.

        Returns:
            list[dict]: Module types not found in *all_module_types*.
        """
        new_module_types = []
        for module_type in module_types:
            if NetBox._find_existing_module_type(module_type, all_module_types) is None:
                new_module_types.append(module_type)
        return new_module_types

    def _log_module_property_diffs(self, mfr_slug, model, fields_info, component_changes=None):
        """Emit diff-u style lines for changed module type properties and component changes.

        Args:
            mfr_slug (str): Manufacturer slug.
            model (str): Module type model name.
            fields_info (list[tuple]): List of ``(field, old_val, new_val)`` tuples.
            component_changes (list | None): Optional list of ComponentChange objects.
        """
        self.handle.verbose_log(f"  ~ {mfr_slug}/{model}")
        if fields_info:
            self.handle.verbose_log("    Properties:")
            log_property_diffs(fields_info, self.handle.verbose_log)
        if component_changes:
            added = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_ADDED]
            changed = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_CHANGED]
            removed = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_REMOVED]
            if added:
                self.handle.verbose_log(f"      + {len(added)} new component(s)")
                for comp in added:
                    self.handle.verbose_log(f"        + {comp.component_type}: {comp.component_name}")
            if changed:
                self.handle.verbose_log(f"      ~ {len(changed)} changed component(s)")
                for comp in changed:
                    self.handle.verbose_log(f"        ~ {comp.component_type}: {comp.component_name}")
                    log_property_diffs(
                        [(pc.property_name, pc.old_value, pc.new_value) for pc in comp.property_changes],
                        self.handle.verbose_log,
                        "            ",
                    )
            if removed:
                self.handle.verbose_log(f"      - {len(removed)} component(s) present in NetBox but absent from YAML")
                for comp in removed:
                    self.handle.verbose_log(f"        - {comp.component_type}: {comp.component_name}")

    def _module_type_has_missing_components(self, module_type, existing_module, component_keys):
        """Return True if any YAML-defined components are absent from the existing module type in NetBox."""
        for component_key in component_keys:
            components = module_type.get(component_key)
            if not components:
                continue
            endpoint_attr, cache_name = ENDPOINT_CACHE_MAP[component_key]
            endpoint = getattr(self.netbox.dcim, endpoint_attr)
            existing_components = self.device_types._get_cached_or_fetch(
                cache_name, existing_module.id, "module", endpoint
            )
            requested_names = {c.get("name") for c in components if c.get("name")}
            if any(name not in existing_components for name in requested_names):
                return True
        return False

    def filter_actionable_module_types(self, module_types, all_module_types, only_new=False):
        """Determine which module types need to be created or updated in NetBox.

        For ``only_new=True``, returns only module types absent from NetBox. Otherwise,
        ensures the component cache is populated via the global GraphQL preload (running
        it on demand if device-type processing already ran it) and includes any module
        types whose images, scalar properties, or components differ from NetBox.

        Args:
            module_types (list[dict]): Parsed YAML module-type dicts.
            all_module_types (dict): Existing module types from :meth:`get_existing_module_types`.
            only_new (bool): If True, skip change detection and return only truly new entries.

        Returns:
            tuple[list[dict], dict, list]: Three-element tuple:

            - Actionable module types (list[dict]) to be created or updated.
            - Existing-image mapping ``{module_type_id: set_of_image_names}``.
            - Changed-property log: list of ``(mfr_slug, model, fields_info,
              comp_changes)`` tuples, one entry per modified module type, used
              for diff-u output via :meth:`log_module_type_changes`.
        """
        if not module_types:
            return [], {}, []

        if only_new:
            return self.filter_new_module_types(module_types, all_module_types), {}, []

        module_type_existing_images = self._fetch_module_type_existing_images()

        actionable_module_types = []
        # Collects (mfr_slug, model, [(field, old_val, new_val)]) for diff-u logging.
        changed_property_log = []

        # Ensure the component cache is populated with GraphQL data (which carries correct
        # mappings for front-port templates).  The global preload already ran during device-type
        # processing in normal mode; this call is a no-op then.  When no device types were
        # present (e.g. vendor-filtered runs or --only-new was used for device types) the
        # preload is triggered here so module-type comparisons still hit accurate cache data.
        if not self.device_types._global_preload_done:
            self.device_types.preload_all_components()

        existing_module_map = {}
        for module_type in module_types:
            existing_module = self._find_existing_module_type(module_type, all_module_types)
            existing_module_map[id(module_type)] = existing_module

        detector = self.change_detector

        for module_type in module_types:
            existing_module = existing_module_map[id(module_type)]
            if existing_module is None:
                actionable_module_types.append(module_type)
                continue

            existing_images = module_type_existing_images.get(existing_module.id, set())
            image_files = self._discover_module_image_files(module_type.get("src", ""))
            image_changed = any(
                os.path.splitext(os.path.basename(path))[0] not in existing_images for path in image_files
            )
            # With --verify-images, images whose names already exist in NetBox also need
            # to be re-examined for physical presence and local-file hash changes.
            # _upload_module_type_images contains all the probe + decision logic; we just
            # need to ensure this module type is considered actionable so it reaches that path.
            if not image_changed and self.verify_images and image_files and existing_images:
                image_changed = True

            changed_fields_info = []
            for f in _load_module_type_properties():
                if f not in module_type:
                    continue
                nb_val = getattr(existing_module, f, _MISSING)
                if nb_val is _MISSING:
                    # Field not fetched from NetBox yet; skip to avoid false positives.
                    continue
                if not values_equal(module_type[f], nb_val):
                    changed_fields_info.append((f, nb_val, module_type[f]))

            component_changes = detector._compare_components(module_type, existing_module.id, parent_type="module")

            if changed_fields_info or component_changes:
                changed_property_log.append(
                    (
                        module_type["manufacturer"]["slug"],
                        module_type["model"],
                        changed_fields_info,
                        component_changes,
                    )
                )

            if image_changed or changed_fields_info or component_changes:
                actionable_module_types.append(module_type)

        return actionable_module_types, module_type_existing_images, changed_property_log

    def log_module_type_changes(self, changed_property_log):
        """Emit verbose diff output for modified module types.

        Args:
            changed_property_log: List of ``(mfr_slug, model, fields_info, comp_changes)``
                tuples as returned by :meth:`filter_actionable_module_types`.
        """
        if changed_property_log:
            self.handle.verbose_log("MODIFIED MODULE TYPES:")
            for mfr_slug, model, fields_info, comp_changes in changed_property_log:
                self._log_module_property_diffs(mfr_slug, model, fields_info, comp_changes)

    def _fetch_module_type_existing_images(self):
        """Query NetBox for all image attachments on module types via GraphQL and return a mapping.

        When ``self.verify_images`` is True the richer attachment metadata (ID + URL) is fetched
        via :meth:`~core.graphql_client.NetBoxGraphQLClient.get_module_type_image_details` and
        stored on ``self._module_image_details`` for use by
        :meth:`_upload_module_type_images`.

        Returns:
            dict: ``{module_type_id: set_of_attachment_names}``
        """
        if self.verify_images:
            details = self.graphql.get_module_type_image_details()
            self._module_image_details = details
            module_type_existing_images = {obj_id: set(names.keys()) for obj_id, names in details.items()}
        else:
            self._module_image_details = {}
            module_type_existing_images = self.graphql.get_module_type_images()
        self.handle.verbose_log(
            f"Found {len(module_type_existing_images)} module type(s) with existing image attachments."
        )
        return module_type_existing_images

    def _try_update_module_type(self, curr_mt, module_type_res, src_file):
        """Apply pending field updates to an existing module type in NetBox.

        Returns:
            tuple[bool, bool]: ``(success, updated)`` where *success* is False on error and
                *updated* is True when at least one field was actually patched.
        """
        updates = {}
        for field in _load_module_type_properties():
            if field not in curr_mt:
                continue
            current_value = getattr(module_type_res, field, _MISSING)
            if current_value is _MISSING:
                continue
            if not values_equal(curr_mt[field], current_value):
                updates[field] = curr_mt[field]
        if not updates:
            return True, False
        try:
            _retry_on_connection_error(self.netbox.dcim.module_types.update, [{"id": module_type_res.id, **updates}])
            self.handle.verbose_log(
                f"Module Type Updated: {module_type_res.manufacturer.name} - "
                f"{module_type_res.model} - {module_type_res.id} "
                f"(changed: {list(updates.keys())})"
            )
        except pynetbox.RequestError as excep:
            self.handle.log(f"Error updating Module Type: {excep.error} (Context: {src_file})")
            return False, False
        except _RETRYABLE_EXCEPTIONS as e:
            self.handle.log(
                f"Connection error updating Module Type after {_MAX_RETRIES} retries: {e} (Context: {src_file})"
            )
            return False, False
        return True, True

    def _create_module_type_components(self, curr_mt, module_type_id, src_file):
        """Create all component templates for a newly created module type.

        Args:
            curr_mt (dict): Parsed YAML module-type dict.
            module_type_id (int): ID of the newly created module type in NetBox.
            src_file (str): Source file path for error context.
        """
        component_map = {
            "interfaces": self.device_types.create_module_interfaces,
            "power-ports": self.device_types.create_module_power_ports,
            "console-ports": self.device_types.create_module_console_ports,
            "power-outlets": self.device_types.create_module_power_outlets,
            "console-server-ports": self.device_types.create_module_console_server_ports,
            "rear-ports": self.device_types.create_module_rear_ports,
            "front-ports": self.device_types.create_module_front_ports,
        }
        for key, create_fn in component_map.items():
            if key in curr_mt:
                create_fn(curr_mt[key], module_type_id, context=src_file)

    def _apply_module_type_component_updates(
        self, curr_mt, module_type_res, properties_updated, remove_components, patch_ok=True
    ):
        """Detect and apply component changes for an existing module type in update mode.

        Args:
            curr_mt (dict): Parsed YAML module-type dict.
            module_type_res: NetBox module type record.
            properties_updated (bool): Whether scalar properties were already patched (used to
                avoid double-counting the module as updated).
            remove_components (bool): When True, removed components are deleted from NetBox.
            patch_ok (bool): Whether the preceding scalar PATCH call succeeded (or was a no-op).
                When False the property drift is still present; a component-only reconciliation
                must not be recorded as a full ``module_updated`` success.
        """
        if not self.device_types._global_preload_done:
            self.device_types.preload_all_components()
        identity = f"{module_type_res.manufacturer.name}/{module_type_res.model}"
        component_changes = self.change_detector._compare_components(curr_mt, module_type_res.id, parent_type="module")
        if component_changes:
            actionable_count = _count_actionable_component_changes(component_changes, remove_components)
            before_updated = self.counter["components_updated"]
            before_added = self.counter["components_added"]
            before_removed = self.counter["components_removed"]
            self.device_types.update_components(curr_mt, module_type_res.id, component_changes, parent_type="module")
            if remove_components:
                self.device_types.remove_components(module_type_res.id, component_changes, parent_type="module")
            component_delta = (
                self.counter["components_updated"]
                - before_updated
                + self.counter["components_added"]
                - before_added
                + self.counter["components_removed"]
                - before_removed
            )
            if actionable_count == 0:
                if properties_updated and patch_ok:
                    self.counter["module_updated"] += 1
                elif not patch_ok:
                    self.counter["module_update_failed"] += 1
                    self.outcomes.record(
                        EntityKind.MODULE_TYPE,
                        identity,
                        Outcome.FAILED,
                        reason="Scalar PATCH failed; no component changes were actionable.",
                    )
            elif component_delta == 0:
                if properties_updated and patch_ok:
                    # Properties patched successfully; components were attempted but
                    # none changed — treat as a partial success, not a full failure.
                    self.counter["module_partial_update"] += 1
                else:
                    self.counter["module_update_failed"] += 1
                    reason = (
                        "Scalar PATCH failed; component reconciliation ran but applied 0 changes."
                        if not patch_ok
                        else "Component reconciliation ran but applied 0 changes."
                    )
                    self.outcomes.record(
                        EntityKind.MODULE_TYPE,
                        identity,
                        Outcome.FAILED,
                        reason=reason,
                    )
            elif component_delta == actionable_count and patch_ok:
                self.counter["module_updated"] += 1
            else:
                self.counter["module_partial_update"] += 1
        elif properties_updated and patch_ok:
            self.counter["module_updated"] += 1
        elif not patch_ok:
            self.counter["module_update_failed"] += 1
            self.outcomes.record(
                EntityKind.MODULE_TYPE,
                identity,
                Outcome.FAILED,
                reason="Scalar PATCH failed; no component changes detected.",
            )

    def _process_single_module_type(
        self, curr_mt, src_file, all_module_types, module_type_existing_images, only_new, remove_components=False
    ):
        """Find or create a single module type and create or update its component templates.

        For new module types all component templates are created directly.  For existing
        module types in update mode (``only_new=False``) scalar properties are patched and
        component changes (additions, modifications) are applied via
        :meth:`DeviceTypes.update_components`.

        Args:
            curr_mt (dict): Parsed YAML module-type dict (with ``src`` key already removed).
            src_file (str): Source file path for error messages and image discovery.
            all_module_types (dict): Existing module types cache; updated in-place on creation.
            module_type_existing_images (dict): Existing image map by module type ID.
            only_new (bool): When True, skip all updates for existing module types.
            remove_components (bool): When True, components absent from the YAML are deleted.

        Returns:
            bool: False if an error occurred and the caller should skip to the next iteration;
                True otherwise.
        """
        is_new = False
        properties_updated = False
        patch_ok = True
        module_type_res = self._find_existing_module_type(curr_mt, all_module_types)
        if module_type_res is not None:
            self.handle.verbose_log(
                f"Module Type Cached: {module_type_res.manufacturer.name} - "
                + f"{module_type_res.model} - {module_type_res.id}"
            )
            # Upload images before the scalar PATCH so attachments are created
            # even if the property update later fails (module already exists in
            # NetBox so the attachment POST can reference its id immediately).
            self._upload_module_type_images(module_type_res, src_file, module_type_existing_images)
            if not only_new:
                ok, properties_updated = self._try_update_module_type(curr_mt, module_type_res, src_file)
                patch_ok = ok
                if not ok:
                    # Scalar PATCH failed; continue with component reconciliation so a
                    # transient property update failure does not block component sync.
                    # Outcome counter is determined by _apply_module_type_component_updates.
                    self.handle.verbose_log(
                        f"Scalar PATCH failed for module type "
                        f"{module_type_res.manufacturer.name} - {module_type_res.model}; "
                        "continuing with component reconciliation."
                    )
        else:
            try:
                module_type_res = _retry_on_connection_error(self.netbox.dcim.module_types.create, curr_mt)
                self.counter["module_added"] += 1
                is_new = True
                manufacturer_slug = curr_mt["manufacturer"]["slug"]
                all_module_types.setdefault(manufacturer_slug, {})[curr_mt["model"]] = module_type_res
                self.handle.verbose_log(
                    f"Module Type Created: {module_type_res.manufacturer.name} - "
                    + f"{module_type_res.model} - {module_type_res.id}"
                )
            except pynetbox.RequestError as excep:
                self.handle.log(f"Error creating Module Type: {excep.error} (Context: {src_file})")
                return False
            except _RETRYABLE_EXCEPTIONS as e:
                self.handle.log(
                    f"Connection error creating Module Type after {_MAX_RETRIES} retries: {e} (Context: {src_file})"
                )
                return False

        if only_new and not is_new:
            return True

        if is_new:
            # New module type: upload images and create all component templates directly.
            self._upload_module_type_images(module_type_res, src_file, module_type_existing_images)
            self._create_module_type_components(curr_mt, module_type_res.id, src_file)
        else:
            # Existing module type in update mode: detect and apply component changes.
            # The global GraphQL cache is already populated, so _compare_components is a
            # pure dict-lookup with no API calls.
            self._apply_module_type_component_updates(
                curr_mt, module_type_res, properties_updated, remove_components, patch_ok=patch_ok
            )
        return True

    def create_module_types(
        self,
        module_types,
        progress=None,
        only_new=False,
        all_module_types=None,
        module_type_existing_images=None,
        remove_components=False,
    ):
        """Create or update module types and their component templates in NetBox.

        For each module type: fetches or creates the record, uploads any new images,
        and creates missing component templates (interfaces, power ports, console ports,
        power outlets, console server ports, rear ports, and front ports).

        Args:
            module_types (list[dict]): Parsed YAML module-type dicts to process.
            progress: Optional progress iterator wrapping ``module_types``.
            only_new (bool): If True, skip component updates for existing module types.
            all_module_types (dict | None): Existing module types cache; fetched if None.
            module_type_existing_images (dict | None): Existing image map; fetched if None.
            remove_components (bool): When True, components absent from the YAML are deleted.
        """
        if not module_types:
            return

        if all_module_types is None:
            all_module_types = self.get_existing_module_types()

        if module_type_existing_images is None:
            module_type_existing_images = self._fetch_module_type_existing_images()

        iterator = progress if progress is not None else module_types
        for curr_mt in iterator:
            src_file = curr_mt.get("src", _UNKNOWN_SRC)
            if "src" in curr_mt:
                del curr_mt["src"]
            if not self._process_single_module_type(
                curr_mt,
                src_file,
                all_module_types,
                module_type_existing_images,
                only_new,
                remove_components=remove_components,
            ):
                continue

    def count_device_type_images(self, device_types_to_add):
        """Pre-count the number of device type images that will actually be uploaded.

        Scans all device types for front_image/rear_image flags, checks whether the
        corresponding image files exist on disk, and excludes images that already
        exist in NetBox for known device types.

        Args:
            device_types_to_add (list[dict]): Parsed YAML device-type dicts.

        Returns:
            int: Number of image files that will be uploaded.
        """
        existing_dt = self.device_types.existing_device_types
        existing_dt_by_slug = self.device_types.existing_device_types_by_slug
        count = 0
        for device_type in device_types_to_add:
            src_file = device_type.get("src", "")
            _image_base_path = _image_dir_for_yaml(src_file, "device-types", "elevation-images")
            if _image_base_path is None:
                continue
            image_base = str(_image_base_path)

            manufacturer_slug = device_type.get("manufacturer", {}).get("slug", "")
            device_slug = device_type.get("slug", "")

            # Look up existing device type the same way create_device_types does
            dt = existing_dt.get((manufacturer_slug, device_type.get("model", "")))
            if dt is None and device_slug:
                dt = existing_dt_by_slug.get((manufacturer_slug, device_slug))

            for i in ["front_image", "rear_image"]:
                if device_type.get(i):
                    # Skip if existing device type already has this image, unless verify_images
                    # is active (in that case we may re-upload even existing images so count them).
                    if not self.verify_images and dt is not None and getattr(dt, i, None):
                        continue
                    image_glob = f"{image_base}/{device_slug}.{i.split('_')[0]}.*"
                    if glob.glob(image_glob, recursive=False):
                        count += 1
        return count

    @staticmethod
    def count_module_type_images(module_types, all_module_types=None, module_type_existing_images=None):
        """Pre-count the number of module type images that will actually be uploaded.

        Scans all module types for associated image files in the module-images directory
        and excludes images that already exist in NetBox.

        Args:
            module_types (list[dict]): Parsed YAML module-type dicts.
            all_module_types (dict | None): Existing module types cache
                (``{manufacturer_slug: {model: record}}``).
            module_type_existing_images (dict | None): Existing image map
                (``{module_type_id: set_of_image_names}``).

        Returns:
            int: Number of image files that will be uploaded.
        """
        if all_module_types is None:
            all_module_types = {}
        if module_type_existing_images is None:
            module_type_existing_images = {}

        count = 0
        for mt in module_types:
            src_file = mt.get("src", "")
            image_files = NetBox._discover_module_image_files(src_file)
            if not image_files:
                continue

            # Find existing module type to check for already-uploaded images
            manufacturer_slug = mt.get("manufacturer", {}).get("slug", "")
            model = mt.get("model", "")
            manufacturer_mts = all_module_types.get(manufacturer_slug, {})
            existing_mt = manufacturer_mts.get(model)

            if existing_mt is not None:
                existing_names = module_type_existing_images.get(existing_mt.id, set())
                for img_path in image_files:
                    img_name = os.path.splitext(os.path.basename(img_path))[0]
                    if img_name not in existing_names:
                        count += 1
            else:
                # New module type — all images will be uploaded
                count += len(image_files)
        return count

    @staticmethod
    def _discover_module_image_files(src_file):
        """Locate image files associated with a module-type YAML source file.

        Derives the image directory by replacing the ``module-types`` component in the source
        path with ``module-images``. Upstream devicetype-library stores module images flat
        under ``module-images/<manufacturer>/`` and (per netbox-community/devicetype-library#3944)
        names them ``<module-name>.(front|rear).<ext>``. This function matches any image
        whose basename begins with the YAML stem followed by a dot, which covers both the
        new ``<stem>.front.<ext>`` / ``<stem>.rear.<ext>`` naming and legacy bare
        ``<stem>.<ext>`` files for users on older forks.

        Args:
            src_file (str): Path to the module-type YAML file.

        Returns:
            list[str]: Absolute paths of discovered image files; empty if the directory cannot
                be derived or contains no recognised images.
        """
        image_dir = _image_dir_for_yaml(src_file, "module-types", "module-images")
        if image_dir is None:
            return []
        src_path = Path(src_file)
        # Match `<stem>.<anything>` flat in the vendor directory (e.g. `LC.front.png`,
        # `LC.rear.jpg`, or legacy bare `LC.png`).
        image_files = glob.glob(str(image_dir / f"{src_path.stem}.*"))
        return [f for f in image_files if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS]

    def _try_delete_stale_attachment(self, detail, img_path, module_type_res, existing, img_name) -> bool:
        """Delete the stale attachment for *img_name* so a fresh upload can follow.

        Returns True when the attachment was successfully deleted (caller should
        proceed to re-upload).  Returns False when deletion is skipped or fails
        (caller should ``continue`` without re-uploading to avoid duplicates).
        """
        att_id = detail.get("att_id") if isinstance(detail, dict) else None
        if not isinstance(att_id, int):
            self.handle.verbose_log(
                f"Cannot delete stale attachment for "
                f"'{os.path.basename(img_path)}' on {module_type_res.model}: "
                "missing or invalid att_id, skipping upload to avoid duplicates."
            )
            return False
        if not _delete_image_attachment(self.url, self.token, att_id, self.ignore_ssl, self.handle):
            self.handle.verbose_log(
                f"Failed to delete stale attachment for "
                f"'{os.path.basename(img_path)}' on {module_type_res.model}, "
                "skipping upload to avoid duplicates."
            )
            return False
        existing.discard(img_name)
        return True

    def _upload_module_type_images(self, module_type_res, src_file, module_type_existing_images):
        """Discover and upload images for a module type, skipping duplicates.

        Derives an image directory by replacing the 'module-types' path component
        with 'module-images' (flat layout — no per-module subdirectory) and matches
        files whose basename begins with the module filename stem (e.g.
        ``<stem>.front.<ext>``, ``<stem>.rear.<ext>``). Only uploads images whose name
        (basename without extension) is not already present in
        module_type_existing_images for this module type.

        When ``self.verify_images`` is True, existing attachments are verified via
        HTTP GET. If an attachment is missing on the server or its content differs
        from the local file, the stale attachment is deleted and the image is
        re-uploaded.

        Args:
            module_type_res: pynetbox Record for the module type.
            src_file (str): Source YAML file path used to derive the image directory.
            module_type_existing_images (dict): module_type_id -> set of attachment names.
        """
        image_files = self._discover_module_image_files(src_file)
        if not image_files:
            return

        existing = module_type_existing_images.setdefault(module_type_res.id, set())
        for img_path in image_files:
            img_name = os.path.splitext(os.path.basename(img_path))[0]
            if img_name in existing:
                if self.verify_images:
                    detail = self._module_image_details.get(module_type_res.id, {}).get(img_name)
                    if detail:
                        img_url = detail.get("url", "")
                        full_url = img_url if img_url.startswith("http") else self.url.rstrip("/") + img_url
                        # Step 1: HTTP accessibility check
                        status = _check_image_url(
                            self.url,
                            full_url,
                            self.ignore_ssl,
                            self.token,
                            log_fn=self.handle.verbose_log,
                        )
                        if status == "missing":
                            self.handle.verbose_log(
                                f"Image '{os.path.basename(img_path)}' missing on server for "
                                f"{module_type_res.model}, re-uploading."
                            )
                            deleted = self._try_delete_stale_attachment(
                                detail, img_path, module_type_res, existing, img_name
                            )
                            if not deleted:
                                continue
                        # Step 2: local-file hash check
                        elif _is_image_hash_changed(img_path, self._image_hash_cache):
                            self.handle.verbose_log(
                                f"Image '{os.path.basename(img_path)}' content has changed for "
                                f"{module_type_res.model}, re-uploading."
                            )
                            deleted = self._try_delete_stale_attachment(
                                detail, img_path, module_type_res, existing, img_name
                            )
                            if not deleted:
                                continue
                        else:
                            # Verify OK: image present and hash unchanged.
                            # Seed hash cache so future local edits will be detected.
                            if img_path not in self._image_hash_cache:
                                _store_image_hashes(self._image_hash_cache, {"image": img_path})
                                self._persist_hash_cache()
                            self.handle.verbose_log(
                                f"Image '{os.path.basename(img_path)}' verified OK for "
                                f"{module_type_res.model}, skipping."
                            )
                            continue
                    else:
                        # If no detail available, skip upload to avoid creating duplicate attachments.
                        self.handle.verbose_log(
                            f"Image '{os.path.basename(img_path)}' already exists for "
                            f"{module_type_res.model} but detail is unavailable; "
                            "skipping upload to avoid duplicates."
                        )
                        continue
                else:
                    self.handle.verbose_log(
                        f"Image '{os.path.basename(img_path)}' already exists for {module_type_res.model}, skipping."
                    )
                    continue
            if self.device_types.upload_image_attachment(
                self.url, self.token, img_path, "dcim.moduletype", module_type_res.id
            ):
                existing.add(img_name)
                _store_image_hashes(self._image_hash_cache, {"image": img_path})
                self._persist_hash_cache()


# Component type -> (dcim endpoint attribute name, cache key name).
# The two tuple elements are intentionally identical today (endpoint attribute == cache name)
# but are kept separate to allow them to diverge independently in the future.
ENDPOINT_CACHE_MAP = {
    "interfaces": ("interface_templates", "interface_templates"),
    "power-ports": ("power_port_templates", "power_port_templates"),
    "console-ports": ("console_port_templates", "console_port_templates"),
    "power-outlets": ("power_outlet_templates", "power_outlet_templates"),
    "console-server-ports": (
        "console_server_port_templates",
        "console_server_port_templates",
    ),
    "rear-ports": ("rear_port_templates", "rear_port_templates"),
    "front-ports": ("front_port_templates", "front_port_templates"),
    "device-bays": ("device_bay_templates", "device_bay_templates"),
    "module-bays": ("module_bay_templates", "module_bay_templates"),
}


class _FrontPortRecordWithMappings:
    """Wrapper around a front port template record that normalises port mappings.

    Supports two data shapes returned by the GraphQL client:

    * **NetBox >= 4.5** — GraphQL ``mappings`` list with ``front_port_position``,
      ``rear_port_position``, and ``rear_port { id name }`` per entry.
    * **NetBox < 4.5** — GraphQL ``rear_port_position`` scalar (legacy direct field).

    Exposes ``_mappings_canonical`` as a list of dicts for use by
    :class:`~change_detector.ChangeDetector` and the update-mode PATCH logic::

        [{"rear_port_name": str | None, "front_port_position": int, "rear_port_position": int}]

    All other attribute accesses are forwarded to the underlying record.
    """

    __slots__ = ("_record", "_mappings_canonical")

    def __init__(self, record):
        """Wrap *record* and pre-compute a canonical mappings list for ChangeDetector compatibility.

        Normalises the ``mappings`` field (NetBox >= 4.5 list of ``PortTemplateMapping`` objects)
        or the ``rear_port_position`` scalar (NetBox < 4.5) into a uniform list of dicts stored
        in ``_mappings_canonical``.
        """
        object.__setattr__(self, "_record", record)
        mappings_raw = getattr(record, "mappings", None)
        if mappings_raw is not None:
            # NetBox >= 4.5: mappings is a list of PortTemplateMapping objects
            canonical = []
            for m in mappings_raw or []:
                rp = m.get("rear_port") if isinstance(m, dict) else getattr(m, "rear_port", None)
                rp_name = (
                    (rp.get("name") if isinstance(rp, dict) else getattr(rp, "name", None)) if rp is not None else None
                )
                fp_pos = (
                    m.get("front_port_position", 1) if isinstance(m, dict) else getattr(m, "front_port_position", 1)
                )
                rp_pos = m.get("rear_port_position", 1) if isinstance(m, dict) else getattr(m, "rear_port_position", 1)
                canonical.append(
                    {
                        "rear_port_name": rp_name,
                        "front_port_position": fp_pos,
                        "rear_port_position": rp_pos,
                    }
                )
        else:
            # NetBox < 4.5: rear_port_position is a direct scalar field
            rp_pos = getattr(record, "rear_port_position", None)
            canonical = (
                [
                    {
                        "rear_port_name": None,
                        "front_port_position": 1,
                        "rear_port_position": rp_pos,
                    }
                ]
                if rp_pos is not None
                else None  # Both mappings and rear_port_position absent; skip comparison.
            )
        object.__setattr__(self, "_mappings_canonical", canonical)

    def __getattr__(self, name):
        """Delegate attribute access to the wrapped record."""
        return getattr(self._record, name)


class DeviceTypes:
    """Manages caching and creation of device-type component templates in NetBox."""

    def __init__(
        self,
        netbox,
        exception_handler,
        counter,
        ignore_ssl,
        new_filters,
        *,
        graphql,
        m2m_front_ports=False,
        max_threads=8,
    ):
        """Initialize empty DeviceTypes cache structures; no data is fetched at construction time.

        Device type data is loaded lazily via :meth:`load_for_vendor` on a per-vendor
        basis rather than eagerly at startup.

        Args:
            netbox: Connected pynetbox API instance.
            exception_handler (LogHandler): Handler for logging and error reporting.
            counter (Counter): Shared operation counter updated during creation.
            ignore_ssl (bool): Whether SSL certificate verification is disabled.
            new_filters (bool): Whether to use updated filter parameter names (NetBox >= 4.1).
            graphql (NetBoxGraphQLClient): GraphQL client for read queries.
            m2m_front_ports (bool): Whether NetBox uses the 4.5+ M2M port mapping model.
            max_threads (int): Maximum number of concurrent threads for component preloading.
        """
        self.netbox = netbox
        self.handle = exception_handler
        self.counter = counter
        self.ignore_ssl = ignore_ssl
        self.new_filters = new_filters
        self.graphql = graphql
        self.m2m_front_ports = m2m_front_ports
        self.max_threads = max_threads
        self.cached_components = {}
        self._global_preload_done = False
        self._image_progress = None
        self.existing_device_types = {}
        self.existing_device_types_by_slug = {}

    def get_device_types(self):
        """Fetch all device types from NetBox via GraphQL and build two lookup indexes.

        Returns:
            tuple[dict, dict]:
                - ``by_model``: ``{(manufacturer_slug, model): record}``
                - ``by_slug``: ``{(manufacturer_slug, slug): record}``
        """
        return self.graphql.get_device_types()

    def load_for_vendor(self, manufacturer_slug: str):
        """Fetch device types for a single vendor and populate the lookup indexes.

        Replaces any previously loaded data so that state from a prior vendor
        does not bleed into the current one.

        Args:
            manufacturer_slug (str): Manufacturer slug to load device types for.
        """
        self.cached_components = {}
        self._global_preload_done = False
        by_model, by_slug = self.graphql.get_device_types(manufacturer_slugs=[manufacturer_slug])
        self.existing_device_types = by_model
        self.existing_device_types_by_slug = by_slug

    # Endpoints whose GraphQL schema is missing fields required for accurate
    # change detection and where the REST API provides the missing data.
    # Add endpoint names here if a future NetBox version drops a field from
    # GraphQL but keeps it in REST (or vice-versa).
    REST_ONLY_ENDPOINTS: frozenset = frozenset()

    # Endpoints that only apply to device types (no module-type path).
    # Matches _NO_MODULE_TYPE in graphql_client.py.
    _NO_MODULE_TYPE_ENDPOINTS: frozenset = frozenset({"device_bay_templates"})

    @staticmethod
    def _component_preload_targets():
        """Return the list of ``(endpoint_attr, display_label)`` pairs used for component preloading."""
        return [
            ("interface_templates", "Interfaces"),
            ("power_port_templates", "Power Ports"),
            ("console_port_templates", "Console Ports"),
            ("console_server_port_templates", "Console Server Ports"),
            ("power_outlet_templates", "Power Outlets"),
            ("rear_port_templates", "Rear Ports"),
            ("front_port_templates", "Front Ports"),
            ("device_bay_templates", "Device Bays"),
            ("module_bay_templates", "Module Bays"),
        ]

    def start_component_preload(
        self,
        progress=None,
        manufacturer_slug: str | None = None,
        task_registry: dict | None = None,
    ):
        """Start concurrent component prefetch and return a preload job handle.

        Args:
            progress: Optional Rich Progress instance for task tracking.
            manufacturer_slug (str | None): When provided, fetch only component templates
                belonging to this manufacturer's device types and module types.
            task_registry (dict | None): When provided, task_ids are looked up or created
                in this shared registry so they persist and accumulate counts across all
                vendors rather than appearing and disappearing per vendor.
        """
        components = self._component_preload_targets()
        max_workers = max(1, min(len(components), self.max_threads))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

        try:
            endpoint_totals = {endpoint_name: None for endpoint_name, _label in components}
            progress_updates = queue.Queue()
            task_ids = None

            if progress is not None:
                task_ids = {}
                for endpoint_name, label in components:
                    desc = f"Caching {label}"
                    if task_registry is not None:
                        if desc not in task_registry:
                            task_registry[desc] = progress.add_task(desc, total=None)
                        task_ids[endpoint_name] = task_registry[desc]
                    else:
                        task_ids[endpoint_name] = progress.add_task(desc, total=None)

            def update_progress(endpoint_name, advance):
                """Put a progress update onto the queue for the main thread to consume."""
                progress_updates.put((endpoint_name, advance))

            futures = {
                endpoint_name: executor.submit(
                    self._fetch_global_endpoint_records,
                    endpoint_name,
                    update_progress,
                    manufacturer_slug,
                )
                for endpoint_name, _label in components
            }
            return {
                "mode": "global",
                "components": components,
                "futures": futures,
                "progress_updates": progress_updates,
                "endpoint_totals": endpoint_totals,
                "task_ids": task_ids,
                "finished_endpoints": set(),
                "executor": executor,
                # When task_registry is provided the caller owns the tasks;
                # this job must not stop or remove them on completion.
                "owns_tasks": task_registry is None,
            }
        except Exception:
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    @staticmethod
    def stop_component_preload(preload_job, progress=None):
        """Cancel any pending futures in *preload_job* and shut down its executor.

        Args:
            preload_job (dict | None): Preload job returned by :meth:`start_component_preload`; no-op if None.
            progress: Optional Rich Progress instance; if provided, any remaining progress
                tasks in the job are removed from the display.
        """
        if not preload_job:
            return

        futures = preload_job.get("futures", {})
        for future in futures.values():
            if not future.done():
                future.cancel()

        executor = preload_job.get("executor")
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)
            preload_job["executor"] = None

        if progress is not None:
            task_ids = preload_job.get("task_ids") or {}
            owns_tasks = preload_job.get("owns_tasks", True)
            if owns_tasks:
                for task_id in task_ids.values():
                    try:
                        progress.stop_task(task_id)
                        progress.remove_task(task_id)
                    except Exception:
                        pass

    @staticmethod
    def _apply_progress_updates(progress_updates, progress, task_ids, allowed_endpoints=None):
        """Drain the progress queue and advance the corresponding Rich progress tasks.

        Args:
            progress_updates (queue.Queue | None): Queue of ``(endpoint_name, advance)`` tuples.
            progress: Rich Progress instance, or None to skip.
            task_ids (dict | None): Mapping of endpoint name to Rich task ID.
            allowed_endpoints (set | None): If provided, only updates for these endpoints are applied.

        Returns:
            bool: True if at least one task was advanced; False otherwise.
        """
        if progress_updates is None or progress is None or not task_ids:
            return False

        advanced = False
        updates = {}
        while True:
            try:
                endpoint_name, advance = progress_updates.get_nowait()
                if allowed_endpoints is not None and endpoint_name not in allowed_endpoints:
                    # Drop updates for already-completed endpoints; their progress tasks are
                    # already stopped so re-enqueuing would have no visible effect.
                    continue
                updates[endpoint_name] = updates.get(endpoint_name, 0) + advance
            except queue.Empty:
                break

        for endpoint_name, advance in updates.items():
            if advance == 0:
                continue
            task_id = task_ids.get(endpoint_name)
            if task_id is not None:
                if advance < 0:
                    # Rewind on retry: clamp completed at 0 to avoid negative bars.
                    task = next((t for t in progress.tasks if t.id == task_id), None)
                    if task is not None:
                        new_completed = max(0, task.completed + advance)
                        progress.update(task_id, completed=new_completed)
                else:
                    progress.update(task_id, advance=advance)
                advanced = True

        return advanced

    def pump_preload_progress(self, preload_job, progress):
        """Drain pending progress updates and mark completed endpoints for *preload_job*.

        Intended to be called periodically while parsing is in progress so that the
        progress bar advances before :meth:`preload_all_components` is called.

        Args:
            preload_job (dict | None): Preload job returned by :meth:`start_component_preload`.
            progress: Rich Progress instance.

        Returns:
            bool: True if any progress updates were applied or endpoints were marked done.
        """
        if not preload_job:
            return False
        futures = preload_job.get("futures", {})
        finished_endpoints = preload_job.setdefault("finished_endpoints", set())
        pending_endpoints = {endpoint_name for endpoint_name in futures if endpoint_name not in finished_endpoints}

        advanced = self._apply_progress_updates(
            preload_job.get("progress_updates"),
            progress,
            preload_job.get("task_ids"),
            allowed_endpoints=pending_endpoints if pending_endpoints else None,
        )

        task_ids = preload_job.get("task_ids") or {}
        owns_tasks = preload_job.get("owns_tasks", True)
        for endpoint_name in pending_endpoints:
            future = futures.get(endpoint_name)
            if future is None or not future.done():
                continue
            if progress is not None and endpoint_name in task_ids:
                try:
                    records = future.result()
                    final_total = max(len(records), 1)
                except Exception:
                    final_total = 1
                if owns_tasks:
                    progress.update(task_ids[endpoint_name], total=final_total, completed=final_total)
                    progress.stop_task(task_ids[endpoint_name])
                    progress.remove_task(task_ids[endpoint_name])
            finished_endpoints.add(endpoint_name)
            advanced = True

        return advanced

    def preload_all_components(
        self,
        progress_wrapper=None,
        preload_job=None,
        progress=None,
        manufacturer_slug: str | None = None,
        task_registry: dict | None = None,
    ):
        """Pre-fetch component templates to avoid N+1 queries during updates.

        Args:
            progress_wrapper: Optional callable to wrap iterables with progress bars.
            preload_job: Optional preload job from :meth:`start_component_preload`.
            progress: Optional shared Rich Progress instance used to render
                all caching tasks inside a single progress panel.
            manufacturer_slug (str | None): When provided, only fetch component templates
                for device/module types belonging to this manufacturer.
            task_registry (dict | None): Shared registry for cumulative progress tasks.
                When provided, "Caching X" tasks persist across all vendors.
        """
        components = self._component_preload_targets()

        if preload_job:
            self._preload_global(
                preload_job.get("components", components),
                progress_wrapper,
                preload_job=preload_job,
                progress=progress,
                task_registry=task_registry,
            )
        else:
            self._preload_global(
                components,
                progress_wrapper,
                progress=progress,
                manufacturer_slug=manufacturer_slug,
                task_registry=task_registry,
            )

        if manufacturer_slug is not None:
            try:
                vendor_dt_ids = {record.id for record in self.existing_device_types.values()}
                vendor_mt_data = self.graphql.get_module_types(manufacturer_slugs=[manufacturer_slug])
                vendor_mt_ids = {record.id for models in vendor_mt_data.values() for record in models.values()}
            except Exception as exc:
                self.handle.log(f"WARNING: Component cache integrity check skipped: {exc}")
            else:
                self._verify_component_cache_integrity(vendor_dt_ids, vendor_mt_ids)
                # Count check is intentionally outside the warning try/except above:
                # a mismatch means GraphQL silently truncated results and the import
                # must not proceed with incomplete data.
                self._check_component_counts_against_rest(vendor_dt_ids, vendor_mt_ids)

        self._global_preload_done = True

    def _preload_track_progress(
        self,
        components,
        futures,
        progress,
        task_ids,
        preload_job,
        progress_updates,
        endpoint_totals,
        owns_tasks=True,
    ):
        """Collect preload results and advance progress tasks as each endpoint future completes.

        Handles already-finished endpoints from a shared preload job, then drains
        the remaining pending futures while advancing per-endpoint progress tasks.

        Args:
            components (list): Sequence of ``(endpoint_name, label)`` pairs.
            futures (dict): Mapping of endpoint name to submitted Future.
            progress: Rich Progress instance for task updates.
            task_ids (dict): Mapping of endpoint name to progress task ID.
            preload_job (dict | None): Shared preload-job state dict, or None.
            progress_updates (queue.Queue | None): Queue carrying ``(endpoint_name, advance)`` tuples.
            endpoint_totals (dict): Expected record count per endpoint.
            owns_tasks (bool): Whether this call owns the progress tasks and should stop/remove them.

        Returns:
            dict: ``{endpoint_name: [records]}`` populated as futures complete.
        """
        future_map = {endpoint: futures[endpoint] for endpoint, _label in components if endpoint in futures}
        pending = set(future_map.keys())
        records_by_endpoint = {}
        if preload_job:
            already_done = pending & preload_job.get("finished_endpoints", set())
            # Collect results and stop tasks for endpoints already finalised by pump_preload_progress.
            for endpoint_name in already_done:
                try:
                    records_by_endpoint[endpoint_name] = future_map[endpoint_name].result()
                except Exception as exc:
                    self.handle.log(f"Preload failed for {endpoint_name}: {exc}")
                    raise
                if endpoint_name in task_ids:
                    try:
                        final_total = max(
                            endpoint_totals.get(endpoint_name) or 0,
                            len(records_by_endpoint[endpoint_name]),
                            1,
                        )
                        if owns_tasks:
                            progress.update(
                                task_ids[endpoint_name],
                                total=final_total,
                                completed=final_total,
                            )
                            progress.stop_task(task_ids[endpoint_name])
                            progress.remove_task(task_ids[endpoint_name])
                    except Exception:
                        pass
            # Exclude from pending to avoid double stop_task.
            pending -= already_done
        self._drain_pending(
            pending,
            future_map,
            progress,
            task_ids,
            progress_updates,
            endpoint_totals,
            records_by_endpoint,
            owns_tasks=owns_tasks,
        )
        return records_by_endpoint

    def _drain_pending(
        self,
        pending,
        future_map,
        progress,
        task_ids,
        progress_updates,
        endpoint_totals,
        records_by_endpoint,
        owns_tasks=True,
    ):
        """Wait for pending endpoint futures to complete, collecting results and updating progress.

        Continuously loops until all pending futures are resolved, advancing the progress
        display as results arrive and handling blocking waits when no updates are available.

        Args:
            pending (set): Endpoint names whose futures have not yet been collected.
            future_map (dict): Mapping of endpoint name to Future.
            progress: Rich Progress instance for task updates.
            task_ids (dict): Mapping of endpoint name to progress task ID.
            progress_updates (queue.Queue | None): Queue of ``(endpoint_name, advance)`` tuples.
            endpoint_totals (dict): Expected record count per endpoint.
            records_by_endpoint (dict): Accumulator dict updated in-place with results.
            owns_tasks (bool): Whether this call owns the progress tasks and should stop/remove them.
        """
        while pending:
            had_updates = self._apply_progress_updates(
                progress_updates,
                progress,
                task_ids,
                allowed_endpoints=pending,
            )
            done_now = [ep for ep in pending if future_map[ep].done()]
            for endpoint_name in done_now:
                pending.remove(endpoint_name)
                try:
                    records_by_endpoint[endpoint_name] = future_map[endpoint_name].result()
                except Exception as exc:
                    self.handle.log(f"Preload failed for {endpoint_name}: {exc}")
                    raise
                final_total = max(
                    endpoint_totals.get(endpoint_name) or 0,
                    len(records_by_endpoint[endpoint_name]),
                    1,
                )
                task_id = task_ids.get(endpoint_name)
                if task_id is not None and owns_tasks:
                    progress.update(task_id, total=final_total, completed=final_total)
                    progress.stop_task(task_id)
                    progress.remove_task(task_id)
            if pending and not had_updates:
                if progress_updates is not None:
                    try:
                        endpoint_name, advance = progress_updates.get(timeout=0.1)
                        if endpoint_name not in pending:
                            # Drop: endpoint already finalised; no task to advance.
                            continue
                        task_id = task_ids.get(endpoint_name)
                        if task_id is not None and advance != 0:
                            if advance < 0:
                                task = next(
                                    (t for t in progress.tasks if t.id == task_id),
                                    None,
                                )
                                if task is not None:
                                    new_completed = max(0, task.completed + advance)
                                    progress.update(task_id, completed=new_completed)
                            else:
                                progress.update(task_id, advance=advance)
                    except queue.Empty:
                        pass
                else:
                    concurrent.futures.wait(
                        [future_map[ep] for ep in pending],
                        timeout=0.1,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )

    def _preload_no_progress(self, components, futures):
        """Collect preload results sequentially without any progress display.

        Waits for each endpoint's future in order, logging verbose messages as each
        completes, and accumulates results for the cache-merging step.

        Args:
            components (list): Sequence of ``(endpoint_name, label)`` pairs.
            futures (dict): Mapping of endpoint name to submitted Future.

        Returns:
            dict: ``{endpoint_name: [records]}`` populated as each future resolves.
        """
        records_by_endpoint = {}
        for endpoint, label in components:
            self.handle.verbose_log(f"Pre-fetching {label}...")
            try:
                records_by_endpoint[endpoint] = futures[endpoint].result()
            except Exception as exc:
                self.handle.log(f"Preload failed for {label}: {exc}")
                raise
        return records_by_endpoint

    def _preload_global(
        self,
        components,
        progress_wrapper=None,
        preload_job=None,
        progress=None,
        manufacturer_slug=None,
        task_registry=None,
    ):
        """Fetch all component templates, optionally scoped to a single manufacturer."""
        own_executor = preload_job is None
        if preload_job:
            executor = preload_job.get("executor")
            futures = preload_job.get("futures", {})
            progress_updates = preload_job.get("progress_updates")
            endpoint_totals = preload_job.get("endpoint_totals", {})
        else:
            max_workers = max(1, min(len(components), self.max_threads))
            endpoint_totals = {endpoint_name: None for endpoint_name, _label in components}
            executor = None
            futures = {}
            progress_updates = None

        try:
            if own_executor:
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
                if progress is not None:
                    progress_updates = queue.Queue()

                    def update_progress(endpoint_name, advance):
                        """Put a progress update onto the queue for the main-thread pump to consume."""
                        progress_updates.put((endpoint_name, advance))

                    futures = {
                        endpoint: executor.submit(
                            self._fetch_global_endpoint_records,
                            endpoint,
                            update_progress,
                            manufacturer_slug,
                        )
                        for endpoint, _label in components
                    }
                else:
                    futures = {
                        endpoint: executor.submit(
                            self._fetch_global_endpoint_records,
                            endpoint,
                            None,
                            manufacturer_slug,
                        )
                        for endpoint, _label in components
                    }
            if progress is not None:
                task_ids = preload_job.get("task_ids") if preload_job else None
                owns_tasks = preload_job.get("owns_tasks", True) if preload_job else (task_registry is None)
                if not task_ids:
                    task_ids = {}
                    for endpoint, label in components:
                        desc = f"Caching {label}"
                        if task_registry is not None:
                            if desc not in task_registry:
                                task_registry[desc] = progress.add_task(desc, total=None)
                            task_ids[endpoint] = task_registry[desc]
                        else:
                            task_ids[endpoint] = progress.add_task(desc, total=None)
                records_by_endpoint = self._preload_track_progress(
                    components,
                    futures,
                    progress,
                    task_ids,
                    preload_job,
                    progress_updates,
                    endpoint_totals,
                    owns_tasks=owns_tasks,
                )
            else:
                records_by_endpoint = self._preload_no_progress(components, futures)
            for endpoint, label in components:
                all_items = records_by_endpoint.get(endpoint, [])
                cache, count = self._build_component_cache(all_items)
                # Merge to preserve entries from prior incremental preloads.
                self.cached_components.setdefault(endpoint, {}).update(cache)
                self.handle.verbose_log(f"Cached {count} {label}.")
        finally:
            if executor:
                if own_executor:
                    executor.shutdown(wait=True)
                elif preload_job and preload_job.get("executor") is executor:
                    executor.shutdown(wait=True)
                    preload_job["executor"] = None

    def _fetch_global_endpoint_records(self, endpoint_name, progress_callback=None, manufacturer_slug=None):
        """Fetch all records for *endpoint_name* from NetBox.

        Most endpoints are fetched via GraphQL for speed.  Endpoints listed in
        :attr:`REST_ONLY_ENDPOINTS` are fetched via the pynetbox REST client
        instead because their GraphQL schema is missing fields that are required
        for accurate change detection.

        ``front_port_templates`` records are always wrapped in
        :class:`_FrontPortRecordWithMappings` after fetching so that
        :class:`~change_detector.ChangeDetector` can access ``_mappings_canonical``
        regardless of whether the server returned ``mappings`` (>= 4.5) or the
        legacy ``rear_port_position`` scalar (< 4.5).

        Args:
            endpoint_name (str): Component template endpoint name (e.g. ``"interface_templates"``).
            progress_callback (callable | None): Called with ``(endpoint_name, advance)``
                once per page during the GraphQL fetch (or once after the batch fetch
                completes for REST endpoints).  *advance* is a positive integer equal to
                the number of records on that page.
            manufacturer_slug (str | None): When provided, only templates belonging to
                device types or module types of this manufacturer are fetched.

        Returns:
            list: All component template records.
        """
        use_rest = endpoint_name in self.REST_ONLY_ENDPOINTS

        if use_rest:
            endpoint = getattr(self.netbox.dcim, endpoint_name)
            records = list(endpoint.all())
            if progress_callback is not None and records:
                progress_callback(endpoint_name, len(records))
            return records

        def _live_advance(n):
            if progress_callback is not None and n:
                progress_callback(endpoint_name, n)

        on_page = _live_advance if progress_callback is not None else None
        records = self.graphql.get_component_templates(
            endpoint_name, manufacturer_slug=manufacturer_slug, on_page=on_page
        )
        if endpoint_name == "front_port_templates":
            records = [_FrontPortRecordWithMappings(r) for r in records]

        return records

    @staticmethod
    def _build_component_cache(items):
        """Organise a flat list of component records into a nested cache structure.

        Args:
            items (list): pynetbox records; each must have a ``device_type`` or ``module_type`` attribute.

        Returns:
            tuple[dict, int]: Cache ``{(parent_type, parent_id): {name: record}}`` and the total
                number of items successfully indexed.
        """
        cache = {}
        count = 0
        for item in items:
            parent_id = None
            parent_type = None

            if getattr(item, "device_type", None):
                parent_id = item.device_type.id
                parent_type = "device"
            elif getattr(item, "module_type", None):
                parent_id = item.module_type.id
                parent_type = "module"

            if not parent_id:
                continue

            key = (parent_type, parent_id)
            if key not in cache:
                cache[key] = {}
            cache[key][item.name] = item
            count += 1

        return cache, count

    def _verify_component_cache_integrity(self, vendor_dt_ids: set, vendor_mt_ids: set) -> bool:
        """Check that cached component records belong to the current vendor.

        For each endpoint in :attr:`cached_components`, verifies that at least one
        record has a parent ID (``device_type.id`` or ``module_type.id``) that
        appears in *vendor_dt_ids* or *vendor_mt_ids* respectively.  A non-empty
        endpoint whose records contain **no** matching IDs is treated as garbage
        data and cleared.

        Args:
            vendor_dt_ids (set): Device type IDs belonging to the current vendor.
            vendor_mt_ids (set): Module type IDs belonging to the current vendor.

        Returns:
            bool: ``True`` if all non-empty endpoints passed the check,
                ``False`` if any were cleared.
        """
        all_ok = True
        for endpoint_name, entries in list(self.cached_components.items()):
            if not entries:
                continue
            has_valid = any(
                (parent_type == "device" and parent_id in vendor_dt_ids)
                or (parent_type == "module" and parent_id in vendor_mt_ids)
                for (parent_type, parent_id) in entries
            )
            if not has_valid:
                self.handle.log(
                    f"ERROR: Cached {endpoint_name} contains no records matching the current vendor — "
                    "clearing to prevent cross-vendor contamination."
                )
                self.cached_components[endpoint_name] = {}
                all_ok = False
        return all_ok

    def _rest_count_chunked(self, rest_endpoint, filter_key, ids, chunk_size=100):
        """Return REST count for *ids* using *filter_key*, chunked to avoid URL-length limits.

        Args:
            rest_endpoint: pynetbox endpoint object (e.g. ``self.netbox.dcim.interface_templates``).
            filter_key (str): Filter parameter name (e.g. ``"device_type_id"``).
            ids (list): List of integer IDs to filter by.
            chunk_size (int): Maximum IDs per REST request.

        Returns:
            int: Total count across all chunks.
        """
        total = 0
        for i in range(0, len(ids), chunk_size):
            chunk = ids[i : i + chunk_size]
            total += rest_endpoint.count(**{filter_key: chunk})
        return total

    def _check_component_counts_against_rest(self, vendor_dt_ids: set, vendor_mt_ids: set):
        """Verify that GraphQL-cached component counts match REST API counts for this vendor.

        For each preloaded component endpoint, counts cached records belonging to the
        current vendor and compares with pynetbox REST counts.  A discrepancy means
        GraphQL silently truncated the fetch and the import should not proceed.

        Args:
            vendor_dt_ids: Device type IDs for the current vendor.
            vendor_mt_ids: Module type IDs for the current vendor.

        Raises:
            GraphQLCountMismatchError: If any endpoint's cached count differs from REST.
        """
        dt_filter_key = device_type_filter_key(self.new_filters)
        mt_filter_key = module_type_filter_key(self.new_filters)
        dt_ids = list(vendor_dt_ids)
        mt_ids = list(vendor_mt_ids)

        for endpoint_name, _label in self._component_preload_targets():
            if endpoint_name in self.REST_ONLY_ENDPOINTS:
                # REST-only endpoints are fetched via REST already — comparing REST
                # count to REST count is tautological and adds no value.
                continue

            endpoint_cache = self.cached_components.get(endpoint_name, {})
            cached_count = sum(
                len(records)
                for (parent_type, parent_id), records in endpoint_cache.items()
                if (parent_type == "device" and parent_id in vendor_dt_ids)
                or (parent_type == "module" and parent_id in vendor_mt_ids)
            )

            rest_ep = getattr(self.netbox.dcim, endpoint_name)
            rest_count = 0
            if dt_ids:
                rest_count += self._rest_count_chunked(rest_ep, dt_filter_key, dt_ids)
            if mt_ids and endpoint_name not in self._NO_MODULE_TYPE_ENDPOINTS:
                rest_count += self._rest_count_chunked(rest_ep, mt_filter_key, mt_ids)

            if cached_count != rest_count:
                raise GraphQLCountMismatchError(
                    f"{endpoint_name}: GraphQL returned {cached_count} records "
                    f"but REST reports {rest_count} — "
                    "GraphQL may have silently truncated the result set."
                )

    def _get_filter_kwargs(self, parent_id, parent_type="device"):
        """Build endpoint filter keyword arguments for the given parent type and ID.

        Delegates to :mod:`core.compat` helpers so the version-compat logic
        lives in exactly one place.

        Args:
            parent_id (int): ID of the device type or module type.
            parent_type (str): ``"device"`` or ``"module"``.

        Returns:
            dict: Filter kwargs to pass to a pynetbox endpoint's ``filter()`` method.
        """
        if parent_type == "device":
            return device_type_filter_kwargs(parent_id, new_filters=self.new_filters)
        else:
            return module_type_filter_kwargs(parent_id, new_filters=self.new_filters)

    def _get_cached_or_fetch(self, cache_name, parent_id, parent_type, endpoint):
        """Return cached components or fall back to a targeted REST filter.

        The global preload (``preload_all_components``) populates most entries before
        any create/update operations.  A cache miss therefore occurs only for newly
        created device types (not yet in the preload snapshot) or after a cache entry
        has been invalidated following a mutation.  In both cases a targeted
        ``endpoint.filter()`` call is fast and returns only the relevant records.

        Args:
            cache_name: Key in self.cached_components (e.g. "rear_port_templates")
            parent_id: Device type or module type ID
            parent_type: "device" or "module"
            endpoint: pynetbox endpoint proxy used for the targeted REST filter

        Returns:
            Dict mapping component name -> record
        """
        cache_key = (parent_type, parent_id)
        if cache_name in self.cached_components:
            if cache_key in self.cached_components[cache_name]:
                return self.cached_components[cache_name][cache_key]

        # Cache miss: targeted REST filter (fast for both device and module types)
        filter_kwargs = self._get_filter_kwargs(parent_id, parent_type)
        records = list(endpoint.filter(**filter_kwargs))
        result = {item.name: item for item in records}
        self.cached_components.setdefault(cache_name, {})[cache_key] = result
        return result

    def preload_module_type_components(self, module_type_ids, component_keys):
        """Bulk-fetch components for module types and populate the cache.

        For each component endpoint referenced by *component_keys*, issues one
        ``filter()`` call per chunk of up to ``FILTER_CHUNK_SIZE`` module-type IDs
        (filtering by module_type_id=[...]) and distributes the returned items into
        per-module-type cache entries so that subsequent ``_get_cached_or_fetch``
        calls hit the cache.  All component types are fetched in parallel.
        """
        if not module_type_ids:
            return

        seen_endpoints = set()
        targets = []
        for component_key in component_keys:
            endpoint_attr, cache_name = ENDPOINT_CACHE_MAP[component_key]
            if endpoint_attr in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_attr)
            targets.append((endpoint_attr, cache_name))

        filter_key = module_type_filter_key(self.new_filters)
        id_list = sorted(module_type_ids)

        # Pre-populate empty entries so cache hits return {} for IDs with no components.
        for _, cache_name in targets:
            cache = self.cached_components.setdefault(cache_name, {})
            for mid in id_list:
                cache.setdefault(("module", mid), {})

        def _fetch_one(endpoint_attr, cache_name):
            """Fetch all module-type component records for *endpoint_attr* and populate *cache_name*."""
            endpoint = getattr(self.netbox.dcim, endpoint_attr)
            results = []
            for chunk in _chunked(id_list, FILTER_CHUNK_SIZE):
                for item in endpoint.filter(**{filter_key: chunk}):
                    module_type = getattr(item, "module_type", None)
                    if module_type is None:
                        continue
                    if cache_name == "front_port_templates":
                        item = _FrontPortRecordWithMappings(item)
                    results.append((module_type.id, item))
            return cache_name, results

        max_workers = max(1, min(len(targets), self.max_threads))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_fetch_one, ea, cn): (ea, cn) for ea, cn in targets}
            for future in concurrent.futures.as_completed(futures):
                cache_name, results = future.result()
                cache = self.cached_components[cache_name]
                for mid, item in results:
                    cache.setdefault(("module", mid), {})[item.name] = item

    def _create_generic(
        self,
        items,
        parent_id,
        endpoint,
        component_name,
        parent_type="device",
        post_process=None,
        context=None,
        cache_name=None,
    ):
        """Create component templates in NetBox, skipping those that already exist.

        Fetches existing components (via cache or API), filters *items* to only new entries,
        optionally runs *post_process* to mutate items before creation (e.g. resolving port IDs),
        then calls ``endpoint.create()`` and updates counters. On error, logs each failed item.

        Args:
            items (list[dict]): Component definitions to create; each must have a "name" key.
            parent_id (int): ID of the parent device or module type.
            endpoint: pynetbox endpoint proxy for create/filter calls.
            component_name (str): Human-readable component type for log messages.
            parent_type (str): ``"device"`` or ``"module"``; determines parent key and counter key.
            post_process (callable | None): Optional ``(items, parent_id)`` callback run before creation.
            context (str | None): Optional context string appended to error log messages.
            cache_name (str | None): Key in ``self.cached_components``; entry is invalidated after creation.
        """
        # Look up existing components via cache or API fallback
        existing = self._get_cached_or_fetch(cache_name, parent_id, parent_type, endpoint)

        to_create = [x for x in items if x["name"] not in existing]
        parent_key = "device_type" if parent_type == "device" else "module_type"

        # Build shallow copies so the caller's dicts are not mutated.
        to_create = [{**item, parent_key: parent_id} for item in to_create]

        if post_process:
            post_process(to_create, parent_id)

        if to_create:
            try:
                created = _retry_on_connection_error(endpoint.create, to_create)
                if parent_type == "device":
                    count = self.handle.log_device_ports_created(created, component_name)
                    self.counter.update({"components_added": count})
                else:
                    count = self.handle.log_module_ports_created(created, component_name)
                    self.counter.update({"components_added": count})

                # Invalidate cache so subsequent lookups re-fetch with new records
                if cache_name and cache_name in self.cached_components:
                    cache_key = (parent_type, parent_id)
                    self.cached_components[cache_name].pop(cache_key, None)
            except pynetbox.RequestError as excep:
                context_str = f" (Context: {context})" if context else ""
                if isinstance(excep.error, list):
                    for i, error in enumerate(excep.error):
                        if error:
                            item_name = to_create[i].get("name", "Unknown") if i < len(to_create) else f"index {i}"
                            self.handle.log(f"Failed to create {component_name} '{item_name}': {error}{context_str}")
                else:
                    failed_items = [x["name"] for x in to_create]
                    self.handle.log(
                        f"Error '{excep.error}' creating {component_name}. Items: {failed_items}{context_str}"
                    )
            except _RETRYABLE_EXCEPTIONS as excep:
                context_str = f" (Context: {context})" if context else ""
                failed_items = [x["name"] for x in to_create]
                self.handle.log(
                    f"Connection error creating {component_name} after {_MAX_RETRIES} retries: {excep}."
                    f" Items: {failed_items}{context_str}"
                )

    def _build_mappings_patch(self, comp_name, new_mappings_set, device_type_id, parent_type):
        """Build the ``rear_ports`` PATCH payload for a front port ``_mappings`` change.

        Args:
            comp_name (str): Component name for log messages.
            new_mappings_set: frozenset of ``(rear_port_name, fp_pos, rp_pos)`` tuples.
            device_type_id: NetBox ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``.

        Returns:
            list | None: ``rear_ports`` payload list, or ``None`` if resolution failed.
        """
        existing_rp = self._get_cached_or_fetch(
            "rear_port_templates",
            device_type_id,
            parent_type,
            self.netbox.dcim.rear_port_templates,
        )
        rear_ports_payload = []
        for tup in sorted(new_mappings_set):
            if len(tup) != 3:
                # positions-only tuple (<4.5 fallback); cannot rebuild M2M
                return None
            rp_name, fp_pos, rp_pos = tup
            rear_port = existing_rp.get(rp_name)
            if rear_port is None:
                self.handle.log(f'Cannot update mapping for "{comp_name}": rear port "{rp_name}" not found in cache.')
                return None
            rear_ports_payload.append(
                {
                    "position": fp_pos,
                    "rear_port": rear_port.id,
                    "rear_port_position": rp_pos,
                }
            )
        return rear_ports_payload

    def _apply_mappings_change(self, comp_name, new_mappings, yaml_mappings, update_data, device_type_id, parent_type):
        """Merge a ``_mappings`` PropertyChange into *update_data*.

        On NetBox >= 4.5 (M2M model) builds and sets ``update_data["rear_ports"]``.
        On legacy NetBox (<4.5) translates a mapping tuple to scalar ``rear_port``
        and ``rear_port_position`` fields, or clears those fields when the mapping
        is empty.  Logs a warning and leaves *update_data* unchanged when the
        referenced rear port cannot be resolved.

        Args:
            comp_name (str): Front port component name (for logging).
            new_mappings: New mapping value from PropertyChange (frozenset of tuples).
            yaml_mappings (list): Raw YAML ``_mappings`` entries for this front port,
                used as a fallback on legacy NetBox when ChangeDetector emits 2-tuples.
            update_data (dict): Payload dict being built for the NetBox update call.
            device_type_id: NetBox ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``.
        """
        if self.m2m_front_ports:
            payload = self._build_mappings_patch(comp_name, new_mappings, device_type_id, parent_type)
            if payload is not None:
                update_data["rear_ports"] = payload
        else:
            if not new_mappings:
                # Explicit empty stanza: clear the existing legacy rear port link.
                update_data["rear_port"] = None
                update_data["rear_port_position"] = None
                return
            first = next(iter(new_mappings))
            if len(first) != 3:
                # Legacy NetBox (<4.5): ChangeDetector emits 2-tuples (fp_pos, rp_pos)
                # because rear port names are unavailable via the GraphQL API.
                # Fall back to the YAML _mappings entry which does include the name.
                if not yaml_mappings:
                    self.handle.log(
                        f"Warning: cannot update mappings for '{comp_name}' on NetBox < 4.5:"
                        " rear port names unavailable, skipping mapping update"
                    )
                    return
                first_yaml = yaml_mappings[0]
                rp_name = first_yaml.get("rear_port")
                rp_pos = first_yaml.get("rear_port_position", 1)
            else:
                rp_name, _fp_pos, rp_pos = first
            rps = self._get_cached_or_fetch(
                "rear_port_templates",
                device_type_id,
                parent_type,
                self.netbox.dcim.rear_port_templates,
            )
            rp = rps.get(rp_name)
            if rp:
                update_data["rear_port"] = rp.id
                update_data["rear_port_position"] = rp_pos
            else:
                self.handle.log(f"Warning: cannot update mappings for '{comp_name}': rear port '{rp_name}' not found")

    def _apply_updates_for_type(self, comp_type, changes, yaml_data, device_type_id, parent_type):
        """Apply property updates for all changed components of a single type.

        Looks up the NetBox endpoint for *comp_type*, fetches or uses the cached
        existing components, builds per-component update payloads, and submits them
        individually.  Invalidates the component cache on success.

        Args:
            comp_type (str): YAML component key (e.g. ``"interfaces"``).
            changes (list): ComponentChange objects with change_type COMPONENT_CHANGED.
            yaml_data (dict): Full parsed YAML for the device type, used to look up
                ``_mappings`` entries for front ports on legacy NetBox.
            device_type_id: NetBox ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``.
        """
        mapping = ENDPOINT_CACHE_MAP.get(comp_type)
        if not mapping:
            return
        endpoint_attr, cache_name = mapping
        endpoint = getattr(self.netbox.dcim, endpoint_attr, None)
        if not endpoint:
            return

        existing = self._get_cached_or_fetch(cache_name, device_type_id, parent_type, endpoint)

        updates = []
        for change in changes:
            if change.component_name in existing:
                comp = existing[change.component_name]
                update_data = {"id": comp.id}
                for pc in change.property_changes:
                    if comp_type == "front-ports" and pc.property_name == "_mappings":
                        yaml_front_port = next(
                            (p for p in (yaml_data.get("front-ports") or []) if p.get("name") == change.component_name),
                            None,
                        )
                        self._apply_mappings_change(
                            change.component_name,
                            pc.new_value,
                            (yaml_front_port or {}).get("_mappings") or [],
                            update_data,
                            device_type_id,
                            parent_type,
                        )
                        continue
                    update_data[pc.property_name] = pc.new_value
                if len(update_data) > 1:  # has fields beyond just "id"
                    updates.append(update_data)

        success_count = 0
        for update_data in updates:
            try:
                _retry_on_connection_error(endpoint.update, [update_data])
                success_count += 1
                self.handle.verbose_log(f"Updated {comp_type} (ID: {update_data['id']})")
            except pynetbox.RequestError as e:
                self.handle.log(f"Error updating {comp_type} (ID: {update_data['id']}): {e.error}")
            except _RETRYABLE_EXCEPTIONS as e:
                self.handle.log(
                    f"Connection error updating {comp_type} (ID: {update_data['id']}) after {_MAX_RETRIES} retries: {e}"
                )

        if success_count:
            self.counter.update({"components_updated": success_count})
            self.handle.verbose_log(f"Updated {success_count} {comp_type}")

            # Invalidate cache so subsequent lookups re-fetch with updated records
            if cache_name in self.cached_components:
                cache_key = (parent_type, device_type_id)
                self.cached_components[cache_name].pop(cache_key, None)

    def _apply_additions_for_type(self, comp_type, changes, yaml_data, device_type_id, parent_type):
        """Create new component templates of a single type based on detected additions.

        Resolves the YAML key for *comp_type* (including alias fallback), finds the
        specific components to add from *yaml_data*, and delegates creation to the
        appropriate endpoint helper.

        Args:
            comp_type (str): YAML component key (e.g. ``"interfaces"``).
            changes (list): ComponentChange objects with change_type COMPONENT_ADDED.
            yaml_data (dict): Full YAML device-type dict containing component lists.
            device_type_id: NetBox ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``.
        """
        yaml_key = None
        if comp_type in yaml_data:
            yaml_key = comp_type
        if yaml_key is None:
            return

        mapping = ENDPOINT_CACHE_MAP.get(comp_type)
        if not mapping:
            return
        endpoint_attr, cache_name = mapping
        endpoint = getattr(self.netbox.dcim, endpoint_attr, None)
        if not endpoint:
            return

        # Find the new components in the YAML data
        yaml_components = yaml_data.get(yaml_key) or []
        new_component_names = {change.component_name for change in changes}
        components_to_add = [c for c in yaml_components if c.get("name") in new_component_names]

        if not components_to_add:
            return

        # Front ports require special link_rear_ports post-processing (including M2M on 4.5+).
        # Delegate to the dedicated create methods instead of calling _create_generic directly.
        if comp_type == "front-ports":
            if parent_type == "device":
                self.create_front_ports(components_to_add, device_type_id)
            else:
                self.create_module_front_ports(components_to_add, device_type_id)
            return

        # Format component name for logging (e.g. "power_port_templates" -> "Power Port")
        component_name = endpoint_attr.replace("_templates", "").replace("_", " ").title()

        self._create_generic(
            components_to_add,
            device_type_id,
            endpoint,
            component_name,
            parent_type=parent_type,
            cache_name=cache_name,
        )

    def update_components(self, yaml_data, device_type_id, component_changes, parent_type="device"):
        """Update existing components and add new components based on detected changes.

        Args:
            yaml_data: YAML device type data containing component definitions
            device_type_id: ID of the device type in NetBox
            component_changes: List of ComponentChange objects with detected changes
            parent_type: "device" or "module"
        """
        # Group changes by component type and change type
        changes_to_update = {}
        changes_to_add = {}
        for change in component_changes:
            if change.change_type == ChangeType.COMPONENT_CHANGED:
                if change.component_type not in changes_to_update:
                    changes_to_update[change.component_type] = []
                changes_to_update[change.component_type].append(change)
            elif change.change_type == ChangeType.COMPONENT_ADDED:
                if change.component_type not in changes_to_add:
                    changes_to_add[change.component_type] = []
                changes_to_add[change.component_type].append(change)

        for comp_type, changes in changes_to_update.items():
            self._apply_updates_for_type(comp_type, changes, yaml_data, device_type_id, parent_type)

        for comp_type, changes in changes_to_add.items():
            self._apply_additions_for_type(comp_type, changes, yaml_data, device_type_id, parent_type)

    def remove_components(self, device_type_id, component_changes, parent_type="device"):
        """Remove components that exist in NetBox but not in YAML.

        Args:
            device_type_id: ID of the device type in NetBox
            component_changes: List of ComponentChange objects with detected changes
            parent_type: "device" or "module"
        """
        # Filter for removal changes only
        removals = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_REMOVED]

        # Group removals by component type
        removals_by_type = {}
        for removal in removals:
            if removal.component_type not in removals_by_type:
                removals_by_type[removal.component_type] = []
            removals_by_type[removal.component_type].append(removal)

        # Process removals for each component type
        for comp_type, changes in removals_by_type.items():
            mapping = ENDPOINT_CACHE_MAP.get(comp_type)
            if not mapping:
                continue
            endpoint_attr, cache_name = mapping
            endpoint = getattr(self.netbox.dcim, endpoint_attr, None)
            if not endpoint:
                continue

            existing = self._get_cached_or_fetch(cache_name, device_type_id, parent_type, endpoint)

            ids_to_delete = []
            for change in changes:
                if change.component_name in existing:
                    comp = existing[change.component_name]
                    ids_to_delete.append(comp.id)
                    self.handle.verbose_log(f"Removing {comp_type}: {change.component_name} (ID: {comp.id})")

            # Delete components one at a time so a single failure doesn't skip the rest
            success_count = 0
            for comp_id in ids_to_delete:
                try:
                    _retry_on_connection_error(endpoint.delete, [comp_id])
                    success_count += 1
                except pynetbox.RequestError as e:
                    self.handle.log(f"Error removing {comp_type} (ID: {comp_id}): {e.error}")
                except _RETRYABLE_EXCEPTIONS as e:
                    self.handle.log(
                        f"Connection error removing {comp_type} (ID: {comp_id}) after {_MAX_RETRIES} retries: {e}"
                    )

            if success_count:
                self.counter.update({"components_removed": success_count})
                self.handle.log(f"Removed {success_count} {comp_type}")

                # Invalidate cache so subsequent lookups re-fetch without deleted records
                if cache_name in self.cached_components:
                    cache_key = (parent_type, device_type_id)
                    self.cached_components[cache_name].pop(cache_key, None)

    def create_interfaces(self, interfaces, device_type, context=None):
        """Create interface templates for a device type, handling bridge references.

        Strips ``bridge`` entries before creation and re-applies them after by resolving
        bridge interface names to their NetBox IDs.

        Args:
            interfaces (list[dict]): Interface template definitions; may include a "bridge" key.
            device_type (int): ID of the parent device type.
            context (str | None): Optional context string for log messages.
        """
        bridged_interfaces = {}
        # Pre-process to separate bridge config
        for x in interfaces:
            if "bridge" in x:
                bridged_interfaces[x["name"]] = x["bridge"]
                del x["bridge"]

        self._create_generic(
            interfaces,
            device_type,
            self.netbox.dcim.interface_templates,
            "Interface",
            context=context,
            cache_name="interface_templates",
        )

        if bridged_interfaces:
            all_interfaces = self._get_cached_or_fetch(
                "interface_templates",
                device_type,
                "device",
                self.netbox.dcim.interface_templates,
            )

            to_update = []
            for name, bridge_name in bridged_interfaces.items():
                if name in all_interfaces and bridge_name in all_interfaces:
                    iface = all_interfaces[name]
                    bridge = all_interfaces[bridge_name]
                    to_update.append({"id": iface.id, "bridge": bridge.id})
                else:
                    self.handle.log(f"Error bridging {name} to {bridge_name}: Interface not found (Context: {context})")

            if to_update:
                try:
                    _retry_on_connection_error(self.netbox.dcim.interface_templates.update, to_update)
                    self.handle.verbose_log(f"Bridged {len(to_update)} interfaces.")
                except pynetbox.RequestError as e:
                    self.handle.log(f"Error bridging interfaces: {e} (Context: {context})")
                except _RETRYABLE_EXCEPTIONS as e:
                    self.handle.log(
                        f"Connection error bridging interfaces after {_MAX_RETRIES} retries: {e} (Context: {context})"
                    )

    def create_power_ports(self, power_ports, device_type, context=None):
        """Create power port templates for a device type."""
        self._create_generic(
            power_ports,
            device_type,
            self.netbox.dcim.power_port_templates,
            "Power Port",
            context=context,
            cache_name="power_port_templates",
        )

    def create_console_ports(self, console_ports, device_type, context=None):
        """Create console port templates for a device type."""
        self._create_generic(
            console_ports,
            device_type,
            self.netbox.dcim.console_port_templates,
            "Console Port",
            context=context,
            cache_name="console_port_templates",
        )

    def create_power_outlets(self, power_outlets, device_type, context=None):
        """Create power outlet templates for a device type, resolving power-port name references.

        Args:
            power_outlets (list[dict]): Power-outlet template definitions; may include a "power_port" name key.
            device_type (int): ID of the parent device type.
            context (str | None): Optional context string for log messages.
        """

        def link_ports(items, pid):
            """Resolve power-port name references in *items* and persist the outlet templates for device type *pid*."""
            existing_pp = self._get_cached_or_fetch(
                "power_port_templates",
                pid,
                "device",
                self.netbox.dcim.power_port_templates,
            )

            outlets_to_remove = []
            for outlet in items:
                if "power_port" not in outlet:
                    continue
                try:
                    power_port = existing_pp[outlet["power_port"]]
                    outlet["power_port"] = power_port.id
                except KeyError:
                    available = list(existing_pp.keys()) if existing_pp else []
                    ctx = f" (Context: {context})" if context else ""
                    self.handle.log(
                        f'Could not find Power Port "{outlet["power_port"]}" for '
                        f'Power Outlet "{outlet.get("name", "Unknown")}". '
                        f"Available: {available}{ctx}"
                    )
                    outlets_to_remove.append(outlet)

            # Remove outlets with invalid power port references
            for outlet in outlets_to_remove:
                items.remove(outlet)

            if outlets_to_remove:
                skipped_names = [o["name"] for o in outlets_to_remove]
                ctx = f" (Context: {context})" if context else ""
                self.handle.log(
                    f"Skipped {len(outlets_to_remove)} power outlet(s) with invalid power port refs: "
                    f"{skipped_names}{ctx}"
                )

        self._create_generic(
            power_outlets,
            device_type,
            self.netbox.dcim.power_outlet_templates,
            "Power Outlet",
            post_process=link_ports,
            context=context,
            cache_name="power_outlet_templates",
        )

    def create_console_server_ports(self, console_server_ports, device_type, context=None):
        """Create console server port templates for a device type."""
        self._create_generic(
            console_server_ports,
            device_type,
            self.netbox.dcim.console_server_port_templates,
            "Console Server Port",
            context=context,
            cache_name="console_server_port_templates",
        )

    def create_rear_ports(self, rear_ports, device_type, context=None):
        """Create rear port templates for a device type."""
        self._create_generic(
            rear_ports,
            device_type,
            self.netbox.dcim.rear_port_templates,
            "Rear Port",
            context=context,
            cache_name="rear_port_templates",
        )

    def _build_link_rear_ports(self, parent_type, label, context=None):
        """Return a ``post_process`` callable that resolves rear-port name references.

        Reads the ``_mappings`` list placed on each front-port dict by
        :func:`~core.repo.normalize_port_mappings` and resolves each entry's
        ``rear_port`` name to the corresponding rear-port template ID.

        On NetBox >= 4.5 the M2M port-mapping model is used: each front port
        receives ``rear_ports: [{position, rear_port, rear_port_position}, ...]``
        (``position`` is the API name for ``front_port_position``).  Multiple
        mappings per front port are fully supported.

        On NetBox < 4.5 only the **first** mapping is sent (single FK model); a
        warning is logged when more than one mapping is present.

        Front ports with no ``_mappings`` and no legacy inline ``rear_port`` key
        are sent as-is (no rear port linkage).  Front ports whose mapped rear port
        name cannot be resolved are skipped with a log entry.

        Args:
            parent_type (str): ``"device"`` or ``"module"`` — passed to :meth:`_get_cached_or_fetch`.
            label (str): Human-readable label for log messages (e.g. ``"Front Port"``).
            context (str | None): Optional context string appended to log messages.
        """
        m2m = self.m2m_front_ports

        def link_rear_ports(items, pid):
            """Resolve rear-port position references in *items* and persist the front port templates for *pid*."""
            existing_rp = self._get_cached_or_fetch(
                "rear_port_templates",
                pid,
                parent_type,
                self.netbox.dcim.rear_port_templates,
            )

            ports_to_remove = []
            for port in items:
                mappings = port.pop("_mappings", None)
                if mappings is None:
                    # Legacy inline fallback (should not happen after normalize_port_mappings,
                    # but kept for safety when files are loaded without going through repo.py).
                    rp_name = port.get("rear_port")
                    if not rp_name:
                        continue
                    mappings = [
                        {
                            "rear_port": port.pop("rear_port"),
                            "front_port_position": 1,
                            "rear_port_position": port.pop("rear_port_position", 1),
                        }
                    ]
                elif not mappings:
                    continue

                resolved = []
                skip = False
                for m in mappings:
                    rp_name = m["rear_port"]
                    rear_port = existing_rp.get(rp_name)
                    if rear_port is None:
                        available = list(existing_rp.keys()) if existing_rp else []
                        ctx = f" (Context: {context})" if context else ""
                        self.handle.log(
                            f'Could not find Rear Port "{rp_name}" for {label} "{port["name"]}". '
                            f"Available: {available}{ctx}"
                        )
                        skip = True
                        break
                    resolved.append(
                        {
                            "rear_port": rear_port.id,
                            "front_port_position": m.get("front_port_position", 1),
                            "rear_port_position": m.get("rear_port_position", 1),
                        }
                    )

                if skip:
                    ports_to_remove.append(port)
                    continue

                if m2m:
                    # "position" is the correct API field name — the NetBox serializer
                    # declares `position = IntegerField(source='front_port_position')`,
                    # so the REST API accepts "position", NOT "front_port_position".
                    port["rear_ports"] = [
                        {
                            "position": r["front_port_position"],
                            "rear_port": r["rear_port"],
                            "rear_port_position": r["rear_port_position"],
                        }
                        for r in resolved
                    ]
                else:
                    if len(resolved) > 1:
                        ctx = f" (Context: {context})" if context else ""
                        self.handle.log(
                            f'Multiple mappings for {label} "{port["name"]}" on NetBox < 4.5: '
                            f"only first mapping applied{ctx}"
                        )
                    port["rear_port"] = resolved[0]["rear_port"]
                    port["rear_port_position"] = resolved[0]["rear_port_position"]

            for port in ports_to_remove:
                items.remove(port)

            if ports_to_remove:
                skipped_names = [p["name"] for p in ports_to_remove]
                ctx = f" (Context: {context})" if context else ""
                self.handle.log(
                    f"Skipped {len(ports_to_remove)} {label.lower()}(s) with invalid rear port refs: "
                    f"{skipped_names}{ctx}"
                )

        return link_rear_ports

    def create_front_ports(self, front_ports, device_type, context=None):
        """Create front port templates for a device type, resolving rear-port references."""
        self._create_generic(
            front_ports,
            device_type,
            self.netbox.dcim.front_port_templates,
            "Front Port",
            post_process=self._build_link_rear_ports("device", "Front Port", context),
            context=context,
            cache_name="front_port_templates",
        )

    def create_device_bays(self, device_bays, device_type, context=None):
        """Create device bay templates for a device type."""
        self._create_generic(
            device_bays,
            device_type,
            self.netbox.dcim.device_bay_templates,
            "Device Bay",
            context=context,
            cache_name="device_bay_templates",
        )

    def create_module_bays(self, module_bays, device_type, context=None):
        """Create module bay templates for a device type."""
        self._create_generic(
            module_bays,
            device_type,
            self.netbox.dcim.module_bay_templates,
            "Module Bay",
            context=context,
            cache_name="module_bay_templates",
        )

    # Module methods
    def create_module_interfaces(self, interfaces, module_type, context=None):
        """Create interface templates for a module type."""
        self._create_generic(
            interfaces,
            module_type,
            self.netbox.dcim.interface_templates,
            "Module Interface",
            parent_type="module",
            context=context,
            cache_name="interface_templates",
        )

    def create_module_power_ports(self, power_ports, module_type, context=None):
        """Create power port templates for a module type."""
        self._create_generic(
            power_ports,
            module_type,
            self.netbox.dcim.power_port_templates,
            "Module Power Port",
            parent_type="module",
            context=context,
            cache_name="power_port_templates",
        )

    def create_module_console_ports(self, console_ports, module_type, context=None):
        """Create console port templates for a module type."""
        self._create_generic(
            console_ports,
            module_type,
            self.netbox.dcim.console_port_templates,
            "Module Console Port",
            parent_type="module",
            context=context,
            cache_name="console_port_templates",
        )

    def create_module_power_outlets(self, power_outlets, module_type, context=None):
        """Create power outlet templates for a module type, resolving power-port name references."""

        def link_ports(items, pid):
            """Resolve power-port name references in *items* and persist the outlet templates for module type *pid*."""
            existing_pp = self._get_cached_or_fetch(
                "power_port_templates",
                pid,
                "module",
                self.netbox.dcim.power_port_templates,
            )

            outlets_to_remove = []
            for outlet in items:
                if "power_port" not in outlet:
                    continue
                try:
                    power_port = existing_pp[outlet["power_port"]]
                    outlet["power_port"] = power_port.id
                except KeyError:
                    available = list(existing_pp.keys()) if existing_pp else []
                    ctx = f" (Context: {context})" if context else ""
                    self.handle.log(
                        f'Could not find Power Port "{outlet["power_port"]}" for '
                        f'Module Power Outlet "{outlet.get("name", "Unknown")}". '
                        f"Available: {available}{ctx}"
                    )
                    outlets_to_remove.append(outlet)

            for outlet in outlets_to_remove:
                items.remove(outlet)

            if outlets_to_remove:
                skipped_names = [o["name"] for o in outlets_to_remove]
                ctx = f" (Context: {context})" if context else ""
                self.handle.log(
                    f"Skipped {len(outlets_to_remove)} module power outlet(s) with invalid power port refs: "
                    f"{skipped_names}{ctx}"
                )

        self._create_generic(
            power_outlets,
            module_type,
            self.netbox.dcim.power_outlet_templates,
            "Module Power Outlet",
            parent_type="module",
            post_process=link_ports,
            context=context,
            cache_name="power_outlet_templates",
        )

    def create_module_console_server_ports(self, console_server_ports, module_type, context=None):
        """Create console server port templates for a module type."""
        self._create_generic(
            console_server_ports,
            module_type,
            self.netbox.dcim.console_server_port_templates,
            "Module Console Server Port",
            parent_type="module",
            context=context,
            cache_name="console_server_port_templates",
        )

    def create_module_rear_ports(self, rear_ports, module_type, context=None):
        """Create rear-port templates for a module type in NetBox.

        Adds any rear port templates from `rear_ports` that do not already exist for the specified `module_type`.
        Args:
            rear_ports (list[dict]): List of rear-port template definitions to create; each item
                must include a `name` and any other template fields required by NetBox.
            module_type (int|object): The module type identifier or object used to associate
                created templates with the parent module type.
            context (str, optional): Optional context string used for logging to identify the source of these templates.
        """
        self._create_generic(
            rear_ports,
            module_type,
            self.netbox.dcim.rear_port_templates,
            "Module Rear Port",
            parent_type="module",
            context=context,
            cache_name="rear_port_templates",
        )

    def create_module_front_ports(self, front_ports, module_type, context=None):
        """Create front-port templates for a module type, resolving rear-port references."""
        self._create_generic(
            front_ports,
            module_type,
            self.netbox.dcim.front_port_templates,
            "Module Front Port",
            parent_type="module",
            post_process=self._build_link_rear_ports("module", "Module Front Port", context),
            context=context,
            cache_name="front_port_templates",
        )

    def upload_images(self, baseurl, token, images, device_type):
        """Upload front and/or rear image files to the specified NetBox device type.

        Sends a PATCH request to the device-type endpoint attaching the provided image files,
        increments self.counter["images"] by the number of files sent, and ensures all opened
        file handles are closed. Respects self.ignore_ssl to determine SSL verification behavior.

        Args:
            baseurl (str): Base URL of the NetBox instance (e.g. "https://netbox.example.com").
            token (str): API token used for the Authorization header.
            images (dict): Mapping of form field name to local file path (e.g.
                {"front_image": "/path/front.jpg", "rear_image": "/path/rear.jpg"}).
            device_type (int | str): Identifier of the device type to update in NetBox (used in the endpoint URL).
        """
        url = f"{baseurl}/api/dcim/device-types/{device_type}/"
        headers = {"Authorization": _build_auth_header(token)}

        # Open files with proper cleanup to avoid resource leaks
        file_handles = {}
        try:
            for field, path in images.items():
                file_handles[field] = (os.path.basename(path), open(path, "rb"))
            response = requests.patch(
                url,
                headers=headers,
                files=file_handles,
                verify=(not self.ignore_ssl),
                timeout=60,
            )
            response.raise_for_status()
            self.handle.verbose_log(f"Images {images} updated at {url}: {response.status_code}")
            self.counter["images"] += len(images)
            if self._image_progress:
                self._image_progress(len(images))
        except requests.RequestException as e:
            self.handle.log(f"Error uploading images for device type {device_type}: {e}")
        except OSError as e:
            self.handle.log(f"Error reading image file for device type {device_type}: {e}")
        finally:
            for _, (_, fh) in file_handles.items():
                try:
                    fh.close()
                except Exception:
                    pass

    def upload_image_attachment(self, baseurl, token, image_path, object_type, object_id):
        """Upload an image as an Image Attachment to a NetBox object.

        Uses POST /api/extras/image-attachments/ to attach an image to any
        NetBox object type (e.g. module types which lack built-in image fields).

        Args:
            baseurl (str): Base URL of the NetBox instance.
            token (str): API token for authorization.
            image_path (str): Local file path of the image to upload.
            object_type (str): NetBox content type string (e.g. "dcim.moduletype").
            object_id (int | str): ID of the object to attach the image to.

        Returns:
            bool: True if the upload succeeded, False on any error.
        """
        url = f"{baseurl}/api/extras/image-attachments/"
        headers = {"Authorization": _build_auth_header(token)}
        data = {
            "object_type": object_type,
            "object_id": str(object_id),
            "name": os.path.splitext(os.path.basename(image_path))[0],
        }

        try:
            with open(image_path, "rb") as f:
                files = {"image": (os.path.basename(image_path), f)}
                response = requests.post(
                    url,
                    headers=headers,
                    data=data,
                    files=files,
                    verify=(not self.ignore_ssl),
                    timeout=60,
                )
                response.raise_for_status()
                self.handle.verbose_log(
                    f"Image attachment '{os.path.basename(image_path)}' uploaded"
                    f" for {object_type} {object_id}: {response.status_code}"
                )
                self.counter["images"] += 1
                if self._image_progress:
                    self._image_progress(1)
                return True
        except requests.RequestException as e:
            self.handle.log(f"Error uploading image attachment for {object_type} {object_id}: {e}")
            return False
        except OSError as e:
            self.handle.log(f"Error reading image file {image_path}: {e}")
            return False
