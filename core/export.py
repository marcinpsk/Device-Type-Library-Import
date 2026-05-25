"""Export-diff feature: export NetBox types absent from or differing vs. the local repo.

Entry point: ``Exporter(settings, handle, export_dir, force_overwrite, vendor_slugs).run()``
"""

import hashlib
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

import requests
import yaml

from core.export_manifest import (
    is_entry_fresh,
    load_manifest,
    save_manifest,
    update_entry,
)
from core.graphql_client import NetBoxGraphQLClient
from core.nb_serializer import (
    COMPONENT_ENDPOINTS,
    serialize_device_type,
    serialize_module_type,
    serialize_rack_type,
)
from core.netbox_api import IMAGE_EXTENSIONS, _build_auth_header

_SKIP = object()  # sentinel: image already exists, no download needed

# Maps Content-Type to a canonical extension for extension-less attachments.
_CONTENT_TYPE_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
    "image/svg+xml": ".svg",
}


def _canon_mfr_slug(mfr: Any) -> str:
    """Return a canonical lowercase slug for a manufacturer value from a repo YAML.

    Handles three forms produced by ``yaml.safe_load()``:
    - ``{"slug": "nokia"}``                → ``"nokia"``
    - ``{"name": "Nokia", "slug": "nokia"}`` → ``"nokia"``
    - ``{"name": "Nokia"}``                → ``"nokia"``  (derived from name)
    - ``"Nokia"``                          → ``"nokia"``  (plain string)
    """
    if isinstance(mfr, dict):
        raw = mfr.get("slug") or mfr.get("name") or ""
    elif isinstance(mfr, str):
        raw = mfr
    else:
        return ""
    return re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")


def _sanitize_attachment_filename(att_name: str, url_path: str, content_type: str) -> str:
    """Return a safe, extension-bearing filename for a NetBox image attachment.

    1. Strips any directory components (prevents path traversal).
    2. If the name already carries a recognised image extension, returns it as-is.
    3. Otherwise derives an extension from *content_type* (preferred) or from
       the URL suffix, falling back to ``.bin`` if nothing matches.
    """
    safe = Path(att_name).name  # strip leading "../" or "subdir/"
    ext = Path(safe).suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        return safe
    # Try to derive extension from Content-Type
    ct_base = content_type.split(";")[0].strip().lower()
    derived = _CONTENT_TYPE_EXT.get(ct_base)
    if derived is None:
        # Fall back to URL path suffix
        url_ext = Path(url_path.split("?")[0]).suffix.lower()
        derived = url_ext if url_ext in IMAGE_EXTENSIONS else ".bin"
    return safe + derived if safe else f"attachment{derived}"


def _make_filename(model: str) -> str:
    """Sanitize *model* into a valid flat filename (no path separators, no spaces).

    Replaces spaces, forward/back-slashes with dashes and collapses duplicate dashes.
    Preserves original casing to stay consistent with DTL conventions.
    """
    name = re.sub(r"[ /\\]", "-", model)
    name = re.sub(r"-{2,}", "-", name)
    return name.strip("-")


@dataclass
class ExportItem:
    """A single type that should be written to the export directory."""

    kind: str  # "device-type" | "module-type" | "rack-type"
    nb_record: Any
    repo_yaml: Optional[dict]  # None when absent from repo
    serialized: dict  # What we will write
    reason: str  # "absent" | "differs" | "images-missing"
    mfr_name: str
    filename: str  # e.g. "nokia-7750-sr-7s.yaml"
    manifest_key: str  # e.g. "Nokia/nokia-7750-sr-7s"


def _normalize_for_compare(obj: Any) -> Any:
    """Recursively normalize a dict/list for equality comparison.

    - float with integer value → int  (handles u_height=1.0 vs u_height=1)
    - empty string → None
    - lists of named components → sorted by ``name`` (DTL ordering is cosmetic)
    """
    if isinstance(obj, dict):
        return {k: _normalize_for_compare(v) for k, v in obj.items()}
    if isinstance(obj, list):
        normalized = [_normalize_for_compare(item) for item in obj]
        if normalized and all(isinstance(i, dict) and "name" in i for i in normalized):
            normalized.sort(key=lambda d: str(d["name"]))
        return normalized
    if isinstance(obj, float) and not isinstance(obj, bool) and obj.is_integer():
        return int(obj)
    if isinstance(obj, str) and obj == "":
        return None
    return obj


def _yaml_equal(a: dict, b: dict) -> bool:
    """Return True when *a* and *b* are semantically equal YAML dicts."""
    return _normalize_for_compare(a) == _normalize_for_compare(b)


def _repo_supersedes(repo_yaml: dict, nb_serialized: dict) -> bool:
    """Return True when *repo_yaml* already contains every field NetBox would write.

    Used to suppress exports where the repo is a strict superset of NetBox: if
    every field/value in ``nb_serialized`` is also present (and equal, after
    normalization) in ``repo_yaml``, the export would only delete information
    (e.g. drop the repo-only ``profile`` field). In that case the export is
    skipped — the repo is considered the better source of truth.

    Lists of named components are matched element-wise by ``name``: each NB
    component must be present in the repo with the same fields/values, but the
    repo may carry additional components or extra per-component fields.
    """

    # Normalize manufacturer to canonical slug so dict-form repo values
    # (e.g. {name: Nokia, slug: Nokia}) compare equal to NB's plain slug string.
    def _norm_mfr(d: dict) -> dict:
        if "manufacturer" not in d:
            return d
        return {**d, "manufacturer": _canon_mfr_slug(d["manufacturer"])}

    nrepo = _normalize_for_compare(_norm_mfr(repo_yaml))
    nnb = _normalize_for_compare(_norm_mfr(nb_serialized))
    return _is_subset(nnb, nrepo)


def _is_subset(sub: Any, sup: Any) -> bool:
    """Return True if every leaf value in *sub* is present and equal in *sup*."""
    if isinstance(sub, dict):
        if not isinstance(sup, dict):
            return False
        for k, v in sub.items():
            if k not in sup:
                return False
            if not _is_subset(v, sup[k]):
                return False
        return True
    if isinstance(sub, list):
        if not isinstance(sup, list):
            return False
        # If items are named components, match by name; otherwise require
        # exact equality (positional list).
        if sub and all(isinstance(i, dict) and "name" in i for i in sub):
            sup_by_name = {i["name"]: i for i in sup if isinstance(i, dict) and "name" in i}
            for item in sub:
                other = sup_by_name.get(item["name"])
                if other is None or not _is_subset(item, other):
                    return False
            return True
        return sub == sup
    return sub == sup


class Exporter:
    """Exports NetBox device/module/rack types to a local directory in DTL format."""

    def __init__(self, settings, handle, export_dir: str, force_overwrite: bool, vendor_slugs: Optional[List[str]]):
        """Initialize the Exporter with settings and configuration."""
        self.settings = settings
        self.handle = handle
        self.export_dir = Path(export_dir)
        self.force_overwrite = force_overwrite
        self.vendor_slugs = vendor_slugs  # None means all vendors
        self.repo_path = Path(settings.REPO_PATH)
        self.base_url = settings.NETBOX_URL.rstrip("/")
        self.token = settings.NETBOX_TOKEN
        self.ignore_ssl = settings.IGNORE_SSL_ERRORS
        self.graphql = NetBoxGraphQLClient(
            url=settings.NETBOX_URL,
            token=settings.NETBOX_TOKEN,
            ignore_ssl=settings.IGNORE_SSL_ERRORS,
        )
        self._module_image_details: Optional[dict] = None

    def _get_module_image_details(self) -> dict:
        """Return module type image details, fetching from NetBox at most once per run."""
        if self._module_image_details is None:
            self._module_image_details = self.graphql.get_module_type_image_details()
        return self._module_image_details

    def run(self, progress=None) -> None:
        """Run the export-diff workflow."""
        self._module_image_details = None
        self._verify_export_dir_writable()
        manifest_path = self.export_dir / ".export-manifest.json"
        manifest = load_manifest(manifest_path)

        scope = (
            f" for {len(self.vendor_slugs)} vendor(s): {', '.join(self.vendor_slugs)}"
            if self.vendor_slugs
            else " (all vendors)"
        )
        self.handle.log(f"Export-diff: fetching NetBox device/module/rack types{scope}")

        # ── Fetch all types from NetBox ──────────────────────────────────────
        by_model, by_slug = self.graphql.get_device_types(
            manufacturer_slugs=self.vendor_slugs if self.vendor_slugs else None
        )
        all_mt = self.graphql.get_module_types(manufacturer_slugs=self.vendor_slugs if self.vendor_slugs else None)
        all_rt = self.graphql.get_rack_types(manufacturer_slugs=self.vendor_slugs if self.vendor_slugs else None)

        total_dt = len(by_model)
        total_mt = sum(len(v) for v in all_mt.values())
        total_rt = sum(len(v) for v in all_rt.values())
        self.handle.log(
            f"Fetched type metadata: {total_dt} device-types, "
            f"{total_mt} module-types, {total_rt} rack-types. "
            f"Component templates fetched per vendor below "
            f"({len(COMPONENT_ENDPOINTS)} endpoints/vendor)."
        )

        # ── Load repo YAML dicts ─────────────────────────────────────────────
        repo_dt_by_slug = self._load_repo_device_types()
        repo_mt_by_key = self._load_repo_module_types()
        repo_rt_by_key = self._load_repo_rack_types()
        self.handle.verbose_log(
            f"Loaded repo: {len(repo_dt_by_slug)} device-types, "
            f"{len(repo_mt_by_key)} module-types, {len(repo_rt_by_key)} rack-types"
        )

        # Collect all vendor slugs that have device types OR module types
        dt_by_vendor: dict = {}
        for (mfr_slug, _model), record in by_model.items():
            dt_by_vendor.setdefault(mfr_slug, []).append(record)

        mt_by_vendor: dict = {}
        for mfr_slug, models in all_mt.items():
            mt_by_vendor[mfr_slug] = list(models.values())

        all_vendor_slugs = sorted(set(dt_by_vendor) | set(mt_by_vendor))
        items, skipped_fresh = self._compare_vendors_to_items(
            all_vendor_slugs=all_vendor_slugs,
            dt_by_vendor=dt_by_vendor,
            mt_by_vendor=mt_by_vendor,
            manifest=manifest,
            repo_dt_by_slug=repo_dt_by_slug,
            repo_mt_by_key=repo_mt_by_key,
            progress=progress,
        )
        rack_items, rack_skipped_fresh = self._compare_racks_to_items(
            all_rt=all_rt,
            manifest=manifest,
            repo_rt_by_key=repo_rt_by_key,
            progress=progress,
        )
        items.extend(rack_items)
        skipped_fresh += rack_skipped_fresh

        if skipped_fresh:
            self.handle.verbose_log(f"Skipped {skipped_fresh} record(s) unchanged since last export (manifest fresh)")

        if not items:
            self.handle.log(
                "Nothing to export: every NetBox type is already represented in the repo "
                "(or fresh in manifest). Use --force-export-overwrite or delete the manifest "
                "to re-check."
            )
            save_manifest(manifest_path, manifest)
            return

        self._write_export_items(items, manifest, manifest_path, progress)

    def _compare_vendors_to_items(
        self,
        all_vendor_slugs,
        dt_by_vendor,
        mt_by_vendor,
        manifest,
        repo_dt_by_slug,
        repo_mt_by_key,
        progress,
    ) -> tuple[List[ExportItem], int]:
        """Compare stale device/module types per vendor and return export items."""
        items: List[ExportItem] = []
        skipped_fresh = 0
        compare_task = (
            progress.add_task("Comparing vendors", total=len(all_vendor_slugs))
            if progress is not None and all_vendor_slugs
            else None
        )

        for mfr_slug in all_vendor_slugs:
            stale_dts = []
            for record in dt_by_vendor.get(mfr_slug, []):
                if is_entry_fresh(
                    manifest,
                    "device-types",
                    f"{record.manufacturer.name}/{record.slug}",
                    record.last_updated,
                ):
                    skipped_fresh += 1
                    continue
                stale_dts.append(record)

            stale_mts = []
            for record in mt_by_vendor.get(mfr_slug, []):
                if is_entry_fresh(
                    manifest,
                    "module-types",
                    f"{record.manufacturer.name}/{record.model}",
                    record.last_updated,
                ):
                    skipped_fresh += 1
                    continue
                stale_mts.append(record)

            if not stale_dts and not stale_mts:
                if compare_task is not None:
                    progress.advance(compare_task)
                continue

            self.handle.verbose_log(
                f"  {mfr_slug}: {len(stale_dts)} device-type(s), "
                f"{len(stale_mts)} module-type(s) to compare; "
                f"fetching {len(COMPONENT_ENDPOINTS)} component-template endpoints…"
            )
            dt_components, mt_components = self._fetch_vendor_components(mfr_slug)

            for record in stale_dts:
                items.extend(
                    self._determine_export_set_for_device_types(
                        nb_records=[record],
                        repo_dt_by_slug=repo_dt_by_slug,
                        components_by_dt_id=dt_components,
                    )
                )

            for record in stale_mts:
                items.extend(
                    self._determine_export_set_for_module_types(
                        nb_records=[record],
                        repo_mt_by_key=repo_mt_by_key,
                        components_by_mt_id=mt_components,
                    )
                )

            if compare_task is not None:
                progress.advance(compare_task)

        return items, skipped_fresh

    def _compare_racks_to_items(self, all_rt, manifest, repo_rt_by_key, progress) -> tuple[List[ExportItem], int]:
        """Compare stale rack types and return export items."""
        items: List[ExportItem] = []
        skipped_fresh = 0
        rack_records = [record for models in all_rt.values() for record in models.values()]
        rack_task = (
            progress.add_task("Comparing rack types", total=len(rack_records))
            if progress is not None and rack_records
            else None
        )

        for record in rack_records:
            if is_entry_fresh(
                manifest,
                "rack-types",
                f"{record.manufacturer.name}/{record.model}",
                record.last_updated,
            ):
                skipped_fresh += 1
            else:
                items.extend(
                    self._determine_export_set_for_rack_types(
                        nb_records=[record],
                        repo_rt_by_key=repo_rt_by_key,
                    )
                )

            if rack_task is not None:
                progress.advance(rack_task)

        return items, skipped_fresh

    def _write_export_items(self, items, manifest, manifest_path, progress) -> None:
        """Write export items, update the manifest, and log the final summary."""
        absent = sum(1 for item in items if item.reason == "absent")
        differs = sum(1 for item in items if item.reason == "differs")
        img_missing = sum(1 for item in items if item.reason == "images-missing")
        self.handle.log(
            f"Will export {len(items)} item(s) to {self.export_dir}: "
            f"{absent} absent, {differs} differs, {img_missing} images-missing"
        )

        write_task = progress.add_task("Writing exports", total=len(items)) if progress is not None else None
        written_count = 0
        skipped_overwrite = 0
        for item in items:
            self.handle.verbose_log(f"Export [{item.reason}] {item.kind}: {item.mfr_name}/{item.filename}")
            subdir = {
                "device-type": "device-types",
                "module-type": "module-types",
                "rack-type": "rack-types",
            }[item.kind]
            dest = self.export_dir / subdir / item.mfr_name / item.filename
            # For "differs" items that have a repo counterpart, preserve repo-only
            # top-level fields (e.g. comments, profile) that NetBox does not return
            # in its serialized output.  Component lists are left as NB authoritative.
            to_write = item.serialized
            if item.reason == "differs" and item.repo_yaml:
                # Only preserve scalar/metadata repo fields not present in the NB output.
                # Exclude list-valued keys (component sections such as interfaces, power-ports,
                # console-ports, etc.) so that NB remains authoritative for all components.
                extra = {
                    k: v for k, v in item.repo_yaml.items() if k not in item.serialized and not isinstance(v, list)
                }
                if extra:
                    to_write = {**item.serialized, **extra}
            written = self._write_yaml(dest, to_write)
            if not written:
                skipped_overwrite += 1
                self.handle.log(
                    f"[yellow]Skipped (overwrite guard): {dest}. Use --force-export-overwrite to overwrite.[/yellow]"
                )
                if write_task is not None:
                    progress.advance(write_task)
                continue

            written_count += 1
            images_ok = self._download_type_images(item)
            if images_ok:
                update_entry(manifest, f"{item.kind}s", item.manifest_key, item.nb_record.last_updated)
            if write_task is not None:
                progress.advance(write_task)

        save_manifest(manifest_path, manifest)
        self.handle.log(
            f"Export-diff complete: wrote {written_count} file(s)"
            + (f", skipped {skipped_overwrite} (overwrite guard)" if skipped_overwrite else "")
        )

    # ── Directory helpers ────────────────────────────────────────────────────

    def _verify_export_dir_writable(self) -> None:
        """Raise PermissionError if export dir cannot be created or written to."""
        self.export_dir.mkdir(parents=True, exist_ok=True)
        if not os.access(self.export_dir, os.W_OK):
            raise PermissionError(f"Export directory {self.export_dir} is not writable")

    # ── Repo loading ─────────────────────────────────────────────────────────

    def _vendor_dirs(self, root: Path):
        """Yield child dirs of *root*, optionally filtered by ``self.vendor_slugs``.

        Matches against the directory name converted to a slug (lowercase,
        non-alphanumeric runs replaced with ``-``) so that directories like
        ``Extreme Networks`` match the CLI slug ``extreme-networks``.
        """
        if not root.exists():
            return

        def _to_slug(name: str) -> str:
            return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")

        if self.vendor_slugs:
            wanted = {_to_slug(v) for v in self.vendor_slugs}
            for d in root.iterdir():
                if d.is_dir() and _to_slug(d.name) in wanted:
                    yield d
        else:
            for d in root.iterdir():
                if d.is_dir():
                    yield d

    def _load_repo_device_types(self) -> dict:
        """Return ``{(mfr_slug, slug): yaml_dict}`` for repo device types (filtered by vendor)."""
        result: dict = {}
        seen_files: dict = {}  # key -> Path that produced it
        for vdir in self._vendor_dirs(self.repo_path / "device-types"):
            mfr_slug = re.sub(r"[^a-z0-9]+", "-", vdir.name.lower()).strip("-")
            yaml_files = sorted(set(vdir.rglob("*.yaml")) | set(vdir.rglob("*.yml")))
            for yaml_file in yaml_files:
                try:
                    data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                except (yaml.YAMLError, OSError) as exc:
                    self.handle.verbose_log(f"[yellow]Skipping malformed YAML {yaml_file}: {exc}[/yellow]")
                    continue
                if isinstance(data, dict) and "slug" in data:
                    key = (mfr_slug, data["slug"])
                    if key in result:
                        raise ValueError(f"Duplicate repo device-type key {key!r}: {seen_files[key]} and {yaml_file}")
                    result[key] = data
                    seen_files[key] = yaml_file
        return result

    def _load_repo_module_types(self) -> dict:
        """Return ``{(mfr_slug, model): yaml_dict}`` for repo module types (filtered by vendor)."""
        result: dict = {}
        seen_files: dict = {}
        for vdir in self._vendor_dirs(self.repo_path / "module-types"):
            yaml_files = sorted(set(vdir.rglob("*.yaml")) | set(vdir.rglob("*.yml")))
            for yaml_file in yaml_files:
                try:
                    data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                except (yaml.YAMLError, OSError) as exc:
                    self.handle.verbose_log(f"[yellow]Skipping malformed YAML {yaml_file}: {exc}[/yellow]")
                    continue
                if isinstance(data, dict) and "model" in data and "manufacturer" in data:
                    mfr_slug = _canon_mfr_slug(data["manufacturer"])
                    if mfr_slug:
                        key = (mfr_slug, data["model"])
                        if key in result:
                            raise ValueError(
                                f"Duplicate repo module-type key {key!r}: {seen_files[key]} and {yaml_file}"
                            )
                        result[key] = data
                        seen_files[key] = yaml_file
        return result

    def _load_repo_rack_types(self) -> dict:
        """Return ``{(mfr_slug, model): yaml_dict}`` for repo rack types (filtered by vendor)."""
        result: dict = {}
        seen_files: dict = {}
        for vdir in self._vendor_dirs(self.repo_path / "rack-types"):
            yaml_files = sorted(set(vdir.rglob("*.yaml")) | set(vdir.rglob("*.yml")))
            for yaml_file in yaml_files:
                try:
                    data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                except (yaml.YAMLError, OSError) as exc:
                    self.handle.verbose_log(f"[yellow]Skipping malformed YAML {yaml_file}: {exc}[/yellow]")
                    continue
                if isinstance(data, dict) and "model" in data and "manufacturer" in data:
                    mfr_slug = _canon_mfr_slug(data["manufacturer"])
                    if mfr_slug:
                        key = (mfr_slug, data["model"])
                        if key in result:
                            raise ValueError(f"Duplicate repo rack-type key {key!r}: {seen_files[key]} and {yaml_file}")
                        result[key] = data
                        seen_files[key] = yaml_file
        return result

    # ── Component fetching ───────────────────────────────────────────────────

    def _fetch_vendor_components(self, mfr_slug: str) -> tuple:
        """Fetch component templates for *mfr_slug* and group by type id.

        Returns ``(dt_components, mt_components)`` where each is
        ``{type_id: {endpoint_name: [records]}}``.

        Keeps device-type and module-type IDs in separate dicts to prevent
        collisions (both use PostgreSQL auto-increment, so id=5 can exist in
        both dcim_devicetype and dcim_moduletype simultaneously).

        The 9 endpoint queries are issued concurrently — for a vendor with
        many records (e.g. Juniper) this turns ~40s of sequential paginated
        GraphQL calls into ~5s.
        """
        from concurrent.futures import ThreadPoolExecutor

        dt_result: dict = {}
        mt_result: dict = {}

        # Each worker gets its own GraphQL client to avoid sharing a single
        # requests.Session across threads (Session is not thread-safe).
        _thread_local = threading.local()
        _clients: list = []
        _clients_lock = threading.Lock()

        def _fetch_one(endpoint_name):
            if not getattr(_thread_local, "graphql", None):
                client = NetBoxGraphQLClient(
                    self.graphql.url,
                    self.graphql.token,
                    self.graphql.ignore_ssl,
                    self.graphql._log_handler,
                    self.graphql.DEFAULT_PAGE_SIZE,
                )
                _thread_local.graphql = client
                with _clients_lock:
                    _clients.append(client)
            return endpoint_name, _thread_local.graphql.get_component_templates(
                endpoint_name, manufacturer_slug=mfr_slug
            )

        try:
            with ThreadPoolExecutor(max_workers=len(COMPONENT_ENDPOINTS)) as pool:
                results = list(pool.map(_fetch_one, [ep_name for _, ep_name in COMPONENT_ENDPOINTS]))
        finally:
            for client in _clients:
                try:
                    client.close()
                except Exception:
                    pass

        for endpoint_name, records in results:
            for rec in records:
                dt = getattr(rec, "device_type", None)
                mt = getattr(rec, "module_type", None)
                if dt and getattr(dt, "id", None):
                    dt_result.setdefault(dt.id, {}).setdefault(endpoint_name, []).append(rec)
                if mt and getattr(mt, "id", None):
                    mt_result.setdefault(mt.id, {}).setdefault(endpoint_name, []).append(rec)
        return dt_result, mt_result

    # ── Export set determination ─────────────────────────────────────────────

    def _determine_export_set_for_device_types(
        self, nb_records: list, repo_dt_by_slug: dict, components_by_dt_id: dict
    ) -> List[ExportItem]:
        items = []
        for rec in nb_records:
            serialized = serialize_device_type(rec, components_by_dt_id)
            mfr_name = rec.manufacturer.name
            mfr_slug = rec.manufacturer.slug
            filename = f"{_make_filename(rec.model)}.yaml"
            manifest_key = f"{mfr_name}/{rec.slug}"

            repo_yaml = repo_dt_by_slug.get((mfr_slug, rec.slug))
            if repo_yaml is None:
                reason = "absent"
            elif _repo_supersedes(repo_yaml, serialized):
                reason = self._check_missing_images(rec.front_image, rec.rear_image, mfr_name, rec.slug)
                if reason is None:
                    continue
            else:
                reason = "differs"

            items.append(
                ExportItem(
                    kind="device-type",
                    nb_record=rec,
                    repo_yaml=repo_yaml,
                    serialized=serialized,
                    reason=reason,
                    mfr_name=mfr_name,
                    filename=filename,
                    manifest_key=manifest_key,
                )
            )
        return items

    def _determine_export_set_for_module_types(
        self, nb_records: list, repo_mt_by_key: dict, components_by_mt_id: dict
    ) -> List[ExportItem]:
        items = []
        for rec in nb_records:
            serialized = serialize_module_type(rec, components_by_mt_id)
            mfr_name = rec.manufacturer.name
            mfr_slug = rec.manufacturer.slug
            filename = f"{_make_filename(rec.model)}.yaml"
            manifest_key = f"{mfr_name}/{rec.model}"

            repo_yaml = repo_mt_by_key.get((mfr_slug, rec.model))
            if repo_yaml is None:
                reason = "absent"
            elif _repo_supersedes(repo_yaml, serialized):
                continue
            else:
                reason = "differs"

            items.append(
                ExportItem(
                    kind="module-type",
                    nb_record=rec,
                    repo_yaml=repo_yaml,
                    serialized=serialized,
                    reason=reason,
                    mfr_name=mfr_name,
                    filename=filename,
                    manifest_key=manifest_key,
                )
            )
        return items

    def _determine_export_set_for_rack_types(self, nb_records: list, repo_rt_by_key: dict) -> List[ExportItem]:
        items = []
        for rec in nb_records:
            serialized = serialize_rack_type(rec)
            mfr_name = rec.manufacturer.name
            mfr_slug = rec.manufacturer.slug
            filename = f"{_make_filename(rec.model)}.yaml"
            manifest_key = f"{mfr_name}/{rec.model}"

            repo_yaml = repo_rt_by_key.get((mfr_slug, rec.model))
            if repo_yaml is None:
                reason = "absent"
            elif _repo_supersedes(repo_yaml, serialized):
                continue
            else:
                reason = "differs"

            items.append(
                ExportItem(
                    kind="rack-type",
                    nb_record=rec,
                    repo_yaml=repo_yaml,
                    serialized=serialized,
                    reason=reason,
                    mfr_name=mfr_name,
                    filename=filename,
                    manifest_key=manifest_key,
                )
            )
        return items

    def _check_missing_images(self, front_url, rear_url, mfr_name: str, slug: str) -> Optional[str]:
        """Return ``'images-missing'`` if any expected local image is absent; else None.

        DTL stores images under ``elevation-images/<Vendor>/<slug>.{front,rear}.{png,jpg,jpeg,gif}``
        so we accept any of those extensions when probing the repo.
        """
        img_dir = self.repo_path / "elevation-images" / mfr_name
        exts = tuple(ext.lstrip(".") for ext in IMAGE_EXTENSIONS)
        if front_url and not any((img_dir / f"{slug}.front.{e}").exists() for e in exts):
            return "images-missing"
        if rear_url and not any((img_dir / f"{slug}.rear.{e}").exists() for e in exts):
            return "images-missing"
        return None

    # ── File writing ─────────────────────────────────────────────────────────

    def _write_yaml(self, dest: Path, data: dict) -> bool:
        """Write *data* as YAML to *dest* with overwrite guard.

        Returns True on write success, False when the overwrite guard blocked.
        """
        dest.parent.mkdir(parents=True, exist_ok=True)
        content = yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
        if dest.exists():
            try:
                existing = dest.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                existing = None  # treat as different content
            if existing == content:
                return True  # same content — no need to overwrite
            if not self.force_overwrite:
                return False  # blocked by overwrite guard
        dest.write_text(content, encoding="utf-8")
        return True

    # ── Image downloading ────────────────────────────────────────────────────

    def _download_type_images(self, item: ExportItem) -> bool:
        """Download images for *item*. Returns True if all downloads succeeded."""
        if item.kind == "device-type":
            return self._download_device_type_images(item)
        elif item.kind == "module-type":
            return self._download_module_type_images(item)
        return True  # rack types have no images

    def _download_device_type_images(self, item: ExportItem) -> bool:
        img_dir = self.export_dir / "elevation-images" / item.mfr_name
        ok = True
        for suffix, url_path in (
            ("front", item.nb_record.front_image),
            ("rear", item.nb_record.rear_image),
        ):
            if not url_path:
                continue
            url_ext = Path(url_path.split("?")[0]).suffix.lower()
            ext = url_ext if url_ext in IMAGE_EXTENSIONS else ".png"
            content_type_out: list[str] = []
            dest = img_dir / f"{item.nb_record.slug}.{suffix}{ext}"
            result = self._download_image(url_path, dest, content_type_out=content_type_out)
            # If the URL carried no recognised extension, try to rename based on Content-Type.
            if result not in (None, _SKIP) and url_ext not in IMAGE_EXTENSIONS:
                ct = content_type_out[0] if content_type_out else ""
                new_name = _sanitize_attachment_filename(f"{item.nb_record.slug}.{suffix}", url_path, ct)
                new_dest = img_dir / new_name
                if new_dest != dest:
                    try:
                        if new_dest.exists() and not self.force_overwrite:
                            dest.unlink(missing_ok=True)
                        else:
                            dest.replace(new_dest)
                    except OSError as exc:
                        self.handle.verbose_log(f"Could not rename {dest.name!r} → {new_dest.name!r}: {exc}")
                        ok = False
            if result is None:  # actual failure
                ok = False
        return ok

    def _download_module_type_images(self, item: ExportItem) -> bool:
        """Download image attachments for a module type.

        Sanitizes each attachment filename to:
        - Strip directory components (prevents path traversal).
        - Ensure a recognised image extension (derived from the URL suffix or
          the response Content-Type header when the name carries none).
        """
        try:
            details = self._get_module_image_details()
        except Exception as exc:
            self.handle.log(f"[yellow]Could not fetch module image details: {exc}[/yellow]")
            return False
        type_images = details.get(item.nb_record.id, {})
        img_dir = self.export_dir / "module-images" / item.mfr_name
        ok = True
        for att_name, att in type_images.items():
            url_path = att.get("url") if isinstance(att, dict) else getattr(att, "url", None)
            if not url_path:
                continue

            # First pass: sanitize using URL suffix (no extra HTTP request).
            content_type_out: list[str] = []
            safe_name = _sanitize_attachment_filename(att_name, url_path, "")
            dest = img_dir / safe_name

            # Path-escape guard: resolved dest must remain under img_dir.
            try:
                dest.resolve().relative_to(img_dir.resolve())
            except ValueError:
                self.handle.log(f"[yellow]Skipping attachment with unsafe path: {att_name!r}[/yellow]")
                ok = False
                continue

            result = self._download_image(url_path, dest, content_type_out=content_type_out)

            # If extension was unknown and we now have a Content-Type from the response,
            # rename the written file to the correct extension.
            if result not in (None, _SKIP) and Path(safe_name).suffix.lower() not in IMAGE_EXTENSIONS:
                content_type = content_type_out[0] if content_type_out else ""
                new_name = _sanitize_attachment_filename(att_name, url_path, content_type)
                if new_name != safe_name:
                    new_dest = img_dir / new_name
                    try:
                        new_dest.resolve().relative_to(img_dir.resolve())
                        if new_dest.exists() and not self.force_overwrite:
                            # Respect the overwrite guard; discard the provisional file.
                            dest.unlink(missing_ok=True)
                        else:
                            dest.replace(new_dest)
                    except (ValueError, OSError) as exc:
                        self.handle.verbose_log(f"Could not rename {safe_name!r} → {new_name!r}: {exc}")
                        ok = False

            if result is None:  # actual failure
                ok = False
        return ok

    def _download_image(self, url_path: str, dest: Path, content_type_out: "Optional[list]" = None) -> "Optional[str]":
        """Download an image from NetBox and write to *dest*.

        Returns SHA-256 hex digest on success, None on failure, or the module-level
        ``_SKIP`` sentinel when the destination already exists and ``--force-export-overwrite``
        is not set (callers must compare ``result is None`` to distinguish failure from skip).
        Respects overwrite guard: skips if dest exists and --force-export-overwrite is not set.
        """
        if dest.exists() and not self.force_overwrite:
            return _SKIP

        full_url = self.base_url + url_path if not url_path.startswith("http") else url_path
        # Only send the auth header when the effective URL resolves to the same
        # host as base_url — prevents credential leakage to off-host storage
        # backends (e.g. S3 redirect, custom CDN).
        from urllib.parse import urlparse

        base = urlparse(self.base_url)
        target = urlparse(full_url)
        headers = {}
        if (base.scheme, base.netloc) == (target.scheme, target.netloc):
            headers["Authorization"] = _build_auth_header(self.token)
        try:
            resp = requests.get(
                full_url,
                headers=headers,
                verify=not self.ignore_ssl,
                timeout=30,
            )
        except requests.RequestException as exc:
            self.handle.log(f"[yellow]Image download failed {full_url}: {exc}[/yellow]")
            return None

        content_type = resp.headers.get("Content-Type", "")
        if not resp.ok or "text" in content_type or "json" in content_type:
            self.handle.log(f"[yellow]Image not available at {full_url} (status {resp.status_code})[/yellow]")
            return None

        if content_type_out is not None:
            content_type_out.append(content_type)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(resp.content)
        return hashlib.sha256(resp.content).hexdigest()
