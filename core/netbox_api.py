"""NetBox REST and GraphQL API client for importing device and module type libraries."""

from collections import Counter
from functools import lru_cache
import hashlib
import json
import re
import tempfile
import time
import pynetbox
import requests
import os
import glob
from pathlib import Path
from typing import Any, Optional

from core.change_detector import ChangeDetector, ChangeType
from core.component_cache import ComponentCache
from core.component_registry import (
    BY_YAML_KEY,
    COMPONENT_TYPES,
    LINK_BRIDGE,
    LINK_POWER_PORT,
    LINK_REAR_PORTS,
    MODULE_TYPE_COMPONENTS,
)
from core.formatting import log_property_diffs
from core.errors import FatalError, UnknownError
from core.graphql_client import GraphQLError, NetBoxGraphQLClient
from core.normalization import values_equal
from core.outcomes import EntityKind, Outcome, OutcomeRegistry
from core.schema_reader import load_properties_for_type
from core.update_failure_resolver import (
    FailureKind,
    classify_device_type_update_failure,
    extract_error_payload,
)


class SSLVerificationError(FatalError):
    """A TLS certificate verification failure."""

    def __init__(self, ignore_ssl_errors: bool, cause=None):
        """Report the active TLS verification setting."""
        super().__init__(
            f"SSL verification failed. IGNORE_SSL_ERRORS is {ignore_ssl_errors}. "
            "Set IGNORE_SSL_ERRORS to True if you want to ignore this error. EXITING.",
            cause=cause,
        )


class NetBoxError(FatalError):
    """A fatal error reported by the NetBox integration."""


def _build_auth_header(token):
    """Return the Authorization header value for the given API token."""
    scheme = "Bearer" if token.startswith("nbt_") else "Token"
    return f"{scheme} {token}"


# Cap on the NetBox response body appended to an error log: a 500 raised with DEBUG enabled
# returns a full HTML traceback page, which would otherwise flood the log.
_MAX_ERROR_BODY_CHARS = 500

# Server-controlled text is escaped before logging: LogHandler.log emits one timestamped
# record per call, so an embedded newline would let a response forge additional records.
_LOG_ESCAPES = {c: f"\\x{c:02x}" for c in [*range(0x20), 0x7F]}
_LOG_ESCAPES.update({ord("\n"): "\\n", ord("\r"): "\\r", ord("\t"): "\\t"})


def _format_request_error(exc) -> str:
    """Return *exc* as text, with NetBox's response body appended when there is one.

    ``requests.HTTPError`` stringifies to only the status line, discarding the body where
    NetBox reports the actual cause (e.g. ``{"front_image": ["Upload a valid image..."]}``
    for an image above its pixel cap).  Without the body an operator sees nothing but
    ``400 Client Error: Bad Request``.

    The body is server-controlled, so control characters are escaped before truncation.
    """
    body = (getattr(getattr(exc, "response", None), "text", "") or "").strip()
    if not body:
        return str(exc)
    body = body.translate(_LOG_ESCAPES)
    if len(body) > _MAX_ERROR_BODY_CHARS:
        body = f"{body[:_MAX_ERROR_BODY_CHARS]}… (truncated)"
    return f"{exc} — NetBox returned: {body}"


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

    Returns "present" only when the server returns a 2xx response *and* the Content-Type
    indicates an actual image.  A 2xx with a non-image Content-Type (e.g. ``text/html``
    from a login-redirect) is treated as "missing" so that files absent from the
    filesystem but still recorded in the database are re-uploaded.

    Returns:
        "present": the server holds the image (2xx with an image Content-Type)
        "missing": the server returned a non-2xx response, or a 2xx but with a
                   non-image Content-Type (image not physically present / auth redirect)
        "unknown": the request did not complete, so the server said nothing about
                   this image.  The caller decides what to do; a failure on the wire
                   is not evidence about the file.

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
        log_fn: Optional callable ``(msg: str) -> None`` invoked with the transport
            error detail.  Pass ``handle.verbose_log``.
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
            log_fn(f"[yellow]Network error checking image {full_url}: {exc}[/yellow]")
        return "unknown"
    if not response.ok:
        return "missing"
    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if not content_type.startswith("image/"):
        return "missing"
    return "present"


def _is_image_hash_changed(local_path: str, hash_cache: dict, log_fn=None) -> bool:
    """Return True if the local file's SHA-256 hash differs from the cached value.

    The cache maps local file paths to the SHA-256 hex-digest recorded at the time
    the file was last uploaded.  Comparing local-to-local (rather than local-to-remote)
    avoids the unreliability caused by NetBox re-encoding images on upload.

    Returns False when *local_path* is absent from *hash_cache* (conservative: avoids
    re-uploading images that have never been tracked), and when the file cannot be
    read, which is reported through *log_fn* because a file this run cannot open is
    also a file it cannot upload.

    Args:
        local_path: Absolute filesystem path to the local image file.
        hash_cache: Dict mapping local path strings to SHA-256 hex-digests.
        log_fn: Optional callable ``(msg: str) -> None`` invoked when the file
            cannot be read.
    """
    cached = hash_cache.get(local_path)
    if cached is None:
        return False
    try:
        with open(local_path, "rb") as fh:
            current = hashlib.sha256(fh.read()).hexdigest()
    except OSError as exc:
        if log_fn is not None:
            log_fn(f"[yellow]Cannot read image {local_path} to check for changes: {exc}[/yellow]")
        return False
    return current != cached


def _load_image_hash_cache(path: Optional[str], log_fn=None) -> dict:
    """Load the image-hash cache from *path* (JSON), returning an empty dict when it cannot be read.

    An absent file is the normal first run and stays quiet.  Anything else means the
    run lost its record of which images it already uploaded, which is reported through
    *log_fn*: every tracked image then reads as unchanged until it is uploaded again.
    """
    if path is None:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        if log_fn is not None:
            log_fn(f"[yellow]Ignoring unreadable image hash cache {path}: {exc}[/yellow]")
        return {}
    if not isinstance(data, dict):
        if log_fn is not None:
            log_fn(
                f"[yellow]Ignoring image hash cache {path}: expected an object, found {type(data).__name__}[/yellow]"
            )
        return {}
    return data


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
    except OSError:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return False


def _store_image_hashes(cache: dict, images: dict, log_fn=None) -> None:
    """Compute and store SHA-256 hashes for each local image path in *images*.

    *images* maps arbitrary string keys to local file paths.  Updates *cache* in-place.
    A file that cannot be read gets no entry, so the next run re-uploads it; that is
    reported through *log_fn* rather than passed over.
    """
    for path in images.values():
        try:
            with open(path, "rb") as fh:
                cache[path] = hashlib.sha256(fh.read()).hexdigest()
        except OSError as exc:
            if log_fn is not None:
                log_fn(f"[yellow]Cannot hash image {path}, so it will be re-uploaded next run: {exc}[/yellow]")


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
        handle.log(f"Error deleting image attachment {att_id}: {_format_request_error(e)}")
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
def _load_module_type_properties(repo_path):
    """Load module type scalar properties from the schema, falling back to hardcoded list.

    The result is cached after the first call, which happens after the repo checkout
    so the schema files are available.
    """
    props = load_properties_for_type(
        os.path.join(repo_path, "schema"),
        "moduletype",
        exclude=_MODULE_TYPE_SCHEMA_EXCLUDE,
    )
    return props if props else list(_MODULE_TYPE_PROPERTIES_FALLBACK)


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

    def __init__(self, config, handle):
        """Initialize NetBox API connection, verify version compatibility, and load manufacturers/device types.

        Args:
            config (RunConfig): Supplies the NetBox URL, token, TLS choice, and tuning values.
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
        self.url = config.netbox_url
        self.token = config.netbox_token
        self.repo_path = config.repo_path
        self.verbose = config.verbose
        self.handle = handle
        self.netbox: Any = None
        self.ignore_ssl = config.ignore_ssl_errors
        self.modules = False
        self.new_filters = False
        self.m2m_front_ports = False  # True for NetBox >= 4.5 (M2M port mappings)
        self.rack_types = False
        self.force_resolve_conflicts = config.force_resolve_conflicts
        self.remove_unmanaged_types = config.remove_unmanaged_types
        self.verify_images = config.verify_images
        self._module_image_details: dict = {}  # populated by _fetch_module_type_existing_images in verify mode
        # Image hash cache: local file path -> SHA-256 hex-digest at last upload time.
        # Used by --verify-images to detect whether the local file changed since last upload,
        # avoiding the unreliability of comparing local bytes to NetBox-served bytes (NetBox
        # re-encodes images).  Stored under ~/.cache/nb-dt-import/ (XDG_CACHE_HOME respected).
        _cache_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "nb-dt-import"
        try:
            _cache_dir.mkdir(parents=True, exist_ok=True)
            self._image_hash_cache_path: Optional[str] = str(_cache_dir / "image-hashes.json")
        except OSError as exc:
            self.handle.log(
                "[yellow]Warning: could not create image hash cache directory "
                f"({_cache_dir}): {exc}. Hash-based re-upload detection is disabled "
                "for this run.[/yellow]"
            )
            self._image_hash_cache_path = None
        self._hash_cache_write_failed = False
        self._image_hash_cache: dict = _load_image_hash_cache(self._image_hash_cache_path, log_fn=self.handle.log)
        self.connect_api()
        self.verify_compatibility()
        self.graphql = NetBoxGraphQLClient(
            self.url,
            self.token,
            self.ignore_ssl,
            handle=self.handle,
            page_size=config.graphql_page_size,
        )
        try:
            self.existing_manufacturers = self.get_manufacturers()
        except GraphQLError as e:
            raise NetBoxError(f"GraphQL error: {e}") from e
        try:
            self.device_types = DeviceTypes(
                self.netbox,
                self.handle,
                self.counter,
                self.ignore_ssl,
                self.new_filters,
                graphql=self.graphql,
                m2m_front_ports=self.m2m_front_ports,
                repo_path=config.repo_path,
                max_threads=config.preload_threads,
            )
        except Exception as e:
            raise NetBoxError(f"Error initializing device types: {e}") from e
        self._change_detector: ChangeDetector | None = None

    @property
    def change_detector(self) -> "ChangeDetector":
        """Lazily initialised, reused :class:`ChangeDetector` instance."""
        if self._change_detector is None:
            self._change_detector = ChangeDetector(
                self.device_types,
                self.handle,
                remove_unmanaged_types=self.remove_unmanaged_types,
                verbose=self.verbose,
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
        if _save_image_hash_cache(self._image_hash_cache_path, self._image_hash_cache):
            return
        if not self._hash_cache_write_failed:
            self._hash_cache_write_failed = True
            self.handle.log(
                "[yellow]Warning: failed to persist image hash cache "
                f"({self._image_hash_cache_path}); "
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
            raise UnknownError("NetBox API Error", cause=e) from e

    def verify_compatibility(self):
        """Check the connected NetBox version and configure feature flags accordingly.

        Sets ``self.modules = True`` for NetBox >= 3.2 and ``self.new_filters = True``
        for >= 4.1. Logs the detected version when the new-filter flag is enabled.
        """
        # nb.version should be the version in the form '3.2'
        # Strip non-numeric suffixes (e.g. "4.1-beta") before converting to int.
        try:
            nb_version = self.netbox.version
        except requests.exceptions.SSLError as e:
            raise SSLVerificationError(self.ignore_ssl, cause=e) from e
        except requests.exceptions.ProxyError as e:
            raise NetBoxError(
                f"Proxy error while connecting to NetBox at {self.url}: {e}\n"
                f"Hint: If NetBox is running locally, ensure that the NETBOX_URL host "
                f"is included in your 'no_proxy' / 'NO_PROXY' environment variable "
                f"(both with and without brackets for IPv6, e.g. '::1,[::1]')."
            ) from e
        except requests.exceptions.ConnectionError as e:
            raise NetBoxError(_fmt_connection_error(self.url, e)) from e
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
            raise NetBoxError(msg) from e
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
            if status == "unknown":
                self.handle.log(
                    f"[yellow]Could not verify {label} on the server for {dt.model}; "
                    "falling back to the local hash alone.[/yellow]"
                )
            # --verify-images: Step 2 — check if local file changed since last upload
            if _is_image_hash_changed(saved_images[image_kind], self._image_hash_cache, log_fn=self.handle.log):
                self.handle.verbose_log(f"{label} content has changed for {dt.model}, will re-upload.")
                continue  # keep in saved_images for upload
            # Both checks passed — image is present and unchanged;
            # seed hash cache so future local edits will be detected.
            local_path = saved_images[image_kind]
            if local_path not in self._image_hash_cache:
                _store_image_hashes(self._image_hash_cache, {image_kind: local_path}, log_fn=self.handle.log)
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
                _store_image_hashes(self._image_hash_cache, saved_images, log_fn=self.handle.log)
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
        for component in COMPONENT_TYPES:
            yaml_key = component.yaml_key
            if yaml_key not in device_type:
                continue
            if yaml_key == "module-bays" and not self.modules:
                continue
            self.device_types.create_components(yaml_key, device_type[yaml_key], dt_id, context=src_file)
        if saved_images:
            self.device_types.upload_images(self.url, self.token, saved_images, dt_id)
            _store_image_hashes(self._image_hash_cache, saved_images, log_fn=self.handle.log)
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
        # Note: the component cache is populated before this method runs.

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
        self.device_types.ensure_components_ready(manufacturer_slug=module_types[0]["manufacturer"]["slug"])

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
            for f in _load_module_type_properties(self.repo_path):
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
        for field in _load_module_type_properties(self.repo_path):
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
        for component in MODULE_TYPE_COMPONENTS:
            yaml_key = component.yaml_key
            if yaml_key in curr_mt:
                self.device_types.create_components(
                    yaml_key, curr_mt[yaml_key], module_type_id, parent_type="module", context=src_file
                )

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
        self.device_types.ensure_components_ready(manufacturer_slug=curr_mt["manufacturer"]["slug"])
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
                        if status == "unknown":
                            self.handle.log(
                                f"[yellow]Could not verify image '{os.path.basename(img_path)}' on the server "
                                f"for {module_type_res.model}; falling back to the local hash alone.[/yellow]"
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
                        elif _is_image_hash_changed(img_path, self._image_hash_cache, log_fn=self.handle.log):
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
                                _store_image_hashes(self._image_hash_cache, {"image": img_path}, log_fn=self.handle.log)
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
                _store_image_hashes(self._image_hash_cache, {"image": img_path}, log_fn=self.handle.log)
                self._persist_hash_cache()


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
        canonical: Optional[list]
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
        handle,
        counter,
        ignore_ssl,
        new_filters,
        *,
        graphql,
        repo_path,
        m2m_front_ports=False,
        max_threads=8,
    ):
        """Initialize empty DeviceTypes cache structures; no data is fetched at construction time.

        Device type data is loaded lazily via :meth:`load_for_vendor` on a per-vendor
        basis rather than eagerly at startup.

        Args:
            netbox: Connected pynetbox API instance.
            handle (LogHandler): Sink for creation and error messages.
            counter (Counter): Shared operation counter updated during creation.
            ignore_ssl (bool): Whether SSL certificate verification is disabled.
            new_filters (bool): Whether to use updated filter parameter names (NetBox >= 4.1).
            graphql (NetBoxGraphQLClient): GraphQL client for read queries.
            repo_path (str): Local library checkout, used to read the module-type schema.
            m2m_front_ports (bool): Whether NetBox uses the 4.5+ M2M port mapping model.
            max_threads (int): Maximum number of concurrent threads for component preloading.
        """
        self.netbox = netbox
        self.handle = handle
        self.counter = counter
        self.ignore_ssl = ignore_ssl
        self.new_filters = new_filters
        self.graphql = graphql
        self.repo_path = repo_path
        self.m2m_front_ports = m2m_front_ports
        self.max_threads = max_threads
        self.components = ComponentCache(
            netbox,
            graphql,
            handle,
            new_filters,
            max_threads,
            wrap_record=_FrontPortRecordWithMappings,
        )
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
        self.components.reset()
        by_model, by_slug = self.graphql.get_device_types(manufacturer_slugs=[manufacturer_slug])
        self.existing_device_types = by_model
        self.existing_device_types_by_slug = by_slug

    def ensure_components_ready(self, manufacturer_slug=None):
        """Populate the component cache, scoping the vendor checks to the loaded device types.

        Idempotent, so any stage that needs cached components may call it without
        knowing whether an earlier stage already did.
        """
        self.components.ensure_ready(
            manufacturer_slug=manufacturer_slug,
            device_type_ids={record.id for record in self.existing_device_types.values()},
        )

    def _create_generic(
        self,
        component,
        items,
        parent_id,
        parent_type="device",
        post_process=None,
        context=None,
    ):
        """Create component templates in NetBox, skipping those that already exist.

        Fetches existing components (via cache or API), filters *items* to only new entries,
        optionally runs *post_process* to mutate items before creation (e.g. resolving port IDs),
        then calls ``endpoint.create()`` and updates counters. On error, logs each failed item.

        Args:
            component (ComponentType): Registry row naming the endpoint, cache and label.
            items (list[dict]): Component definitions to create; each must have a "name" key.
            parent_id (int): ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``; determines parent key and counter key.
            post_process (callable | None): Optional ``(items, parent_id)`` callback run before creation.
            context (str | None): Optional context string appended to error log messages.
        """
        endpoint = getattr(self.netbox.dcim, component.endpoint)
        component_name = component.create_label(parent_type)
        cache_name = component.endpoint

        # Look up existing components via cache or API fallback
        existing = self.components.get(cache_name, parent_type, parent_id, endpoint)

        to_create = [x for x in items if x["name"] not in existing]
        parent_key = "device_type" if parent_type == "device" else "module_type"

        # Build shallow copies so the caller's dicts are not mutated.
        to_create = [{**item, parent_key: parent_id} for item in to_create]

        if post_process:
            post_process(to_create, parent_id)

        if to_create:
            try:
                created = _retry_on_connection_error(endpoint.create, to_create)
                self.handle.log_ports_created(created, parent_type, component_name)
                self.counter.update({"components_added": len(created)})

                self.components.invalidate(cache_name, parent_type, parent_id)
            except pynetbox.RequestError as excep:
                context_str = f" (Context: {context})" if context else ""
                # NetBox answers a rejected bulk create with one error object per submitted
                # item, positionally aligned, so name the items it actually rejected.
                payload = extract_error_payload(excep.error)
                per_item = payload if isinstance(payload, list) and len(payload) == len(to_create) else []
                reported = 0
                for item, error in zip(to_create, per_item):
                    if error:
                        reported += 1
                        self.handle.log(
                            f"Failed to create {component_name} '{item.get('name', 'Unknown')}': {error}{context_str}"
                        )
                if not reported:
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
        existing_rp = self.components.get(
            "rear_port_templates",
            parent_type,
            device_type_id,
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
            rps = self.components.get(
                "rear_port_templates",
                parent_type,
                device_type_id,
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
        component = BY_YAML_KEY.get(comp_type)
        if component is None:
            return
        endpoint = getattr(self.netbox.dcim, component.endpoint)

        existing = self.components.get(component.endpoint, parent_type, device_type_id, endpoint)

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

            self.components.invalidate(component.endpoint, parent_type, device_type_id)

    def _apply_additions_for_type(self, comp_type, changes, yaml_data, device_type_id, parent_type):
        """Create new component templates of a single type based on detected additions.

        Finds the components to add in *yaml_data* and hands them to
        :meth:`create_components`, which resolves any name references.

        Args:
            comp_type (str): YAML component key (e.g. ``"interfaces"``).
            changes (list): ComponentChange objects with change_type COMPONENT_ADDED.
            yaml_data (dict): Full YAML device-type dict containing component lists.
            device_type_id: NetBox ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``.
        """
        if comp_type not in yaml_data or comp_type not in BY_YAML_KEY:
            return

        yaml_components = yaml_data.get(comp_type) or []
        new_component_names = {change.component_name for change in changes}
        components_to_add = [c for c in yaml_components if c.get("name") in new_component_names]

        if not components_to_add:
            return

        self.create_components(comp_type, components_to_add, device_type_id, parent_type=parent_type)

    def update_components(self, yaml_data, device_type_id, component_changes, parent_type="device"):
        """Update existing components and add new components based on detected changes.

        Args:
            yaml_data: YAML device type data containing component definitions
            device_type_id: ID of the device type in NetBox
            component_changes: List of ComponentChange objects with detected changes
            parent_type: "device" or "module"
        """
        # Group changes by component type and change type
        changes_to_update: dict = {}
        changes_to_add: dict = {}
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
        removals_by_type: dict = {}
        for removal in removals:
            if removal.component_type not in removals_by_type:
                removals_by_type[removal.component_type] = []
            removals_by_type[removal.component_type].append(removal)

        # Process removals for each component type
        for comp_type, changes in removals_by_type.items():
            component = BY_YAML_KEY.get(comp_type)
            if component is None:
                continue
            endpoint = getattr(self.netbox.dcim, component.endpoint)

            existing = self.components.get(component.endpoint, parent_type, device_type_id, endpoint)

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

                self.components.invalidate(component.endpoint, parent_type, device_type_id)

    def _build_link_power_port(self, parent_type, label, context=None):
        """Return a ``post_process`` callable that resolves power-port name references.

        Power outlets name their feeding power port; NetBox wants its id.  Outlets whose
        power port cannot be resolved are dropped from the batch with a log entry, so one
        bad reference does not fail the whole create call.

        Args:
            parent_type (str): ``"device"`` or ``"module"``, passed to the component cache.
            label (str): Human-readable label for log messages (e.g. ``"Power Outlet"``).
            context (str | None): Optional context string appended to log messages.
        """

        def link_power_ports(items, pid):
            """Resolve power-port name references in *items* for parent *pid*."""
            existing_pp = self.components.get(
                "power_port_templates",
                parent_type,
                pid,
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
                        f'{label} "{outlet.get("name", "Unknown")}". '
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
                    f"Skipped {len(outlets_to_remove)} {label.lower()}(s) with invalid power port refs: "
                    f"{skipped_names}{ctx}"
                )

        return link_power_ports

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
            parent_type (str): ``"device"`` or ``"module"``, passed to the component cache.
            label (str): Human-readable label for log messages (e.g. ``"Front Port"``).
            context (str | None): Optional context string appended to log messages.
        """
        m2m = self.m2m_front_ports

        def link_rear_ports(items, pid):
            """Resolve rear-port position references in *items* and persist the front port templates for *pid*."""
            existing_rp = self.components.get(
                "rear_port_templates",
                parent_type,
                pid,
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

    def _link_bridges(self, bridged, parent_id, parent_type, context=None):
        """Point each bridged interface at its bridge partner, once both exist in NetBox.

        Runs after creation because NetBox wants the partner's id and the YAML has its name.

        Args:
            bridged (dict): ``{interface_name: bridge_interface_name}``.
            parent_id (int): NetBox ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``.
            context (str | None): Optional context string appended to log messages.
        """
        all_interfaces = self.components.get(
            "interface_templates",
            parent_type,
            parent_id,
            self.netbox.dcim.interface_templates,
        )

        to_update = []
        for name, bridge_name in bridged.items():
            if name in all_interfaces and bridge_name in all_interfaces:
                to_update.append({"id": all_interfaces[name].id, "bridge": all_interfaces[bridge_name].id})
            else:
                self.handle.log(f"Error bridging {name} to {bridge_name}: Interface not found (Context: {context})")

        if not to_update:
            return
        try:
            _retry_on_connection_error(self.netbox.dcim.interface_templates.update, to_update)
            self.handle.verbose_log(f"Bridged {len(to_update)} interfaces.")
        except pynetbox.RequestError as e:
            self.handle.log(f"Error bridging interfaces: {e} (Context: {context})")
        except _RETRYABLE_EXCEPTIONS as e:
            self.handle.log(
                f"Connection error bridging interfaces after {_MAX_RETRIES} retries: {e} (Context: {context})"
            )

    def create_components(self, yaml_key, items, parent_id, parent_type="device", context=None):
        """Create component templates of one kind for one parent, skipping those that exist.

        The registry row for *yaml_key* supplies the endpoint, the cache name, the log label
        and which name references have to become NetBox ids, so every component type takes
        the same path.

        Args:
            yaml_key (str): YAML component key, e.g. ``"interfaces"``.
            items (list[dict]): Component definitions from the YAML file.
            parent_id (int): NetBox ID of the parent device or module type.
            parent_type (str): ``"device"`` or ``"module"``.
            context (str | None): Optional context string appended to log messages.
        """
        component = BY_YAML_KEY[yaml_key]
        label = component.create_label(parent_type)

        post_process = None
        if component.link == LINK_POWER_PORT:
            post_process = self._build_link_power_port(parent_type, label, context)
        elif component.link == LINK_REAR_PORTS:
            post_process = self._build_link_rear_ports(parent_type, label, context)

        bridged = {}
        if component.link == LINK_BRIDGE:
            # NetBox wants the bridge partner's id, so hold the names back until it exists.
            for item in items:
                if "bridge" in item:
                    bridged[item["name"]] = item.pop("bridge")

        self._create_generic(
            component,
            items,
            parent_id,
            parent_type=parent_type,
            post_process=post_process,
            context=context,
        )

        if bridged:
            self._link_bridges(bridged, parent_id, parent_type, context)

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
            self.handle.log(f"Error uploading images for device type {device_type}: {_format_request_error(e)}")
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
            self.handle.log(
                f"Error uploading image attachment for {object_type} {object_id}: {_format_request_error(e)}"
            )
            return False
        except OSError as e:
            self.handle.log(f"Error reading image file {image_path}: {e}")
            return False
