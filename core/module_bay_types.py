"""Resolve module-bay-type reference names to NetBox ids.

A device type's bay says which classes of module it accepts, and a module type says
which classes it belongs to.  Both sides name those classes as plain strings, so
something has to turn a name into the id of one specific NetBox object, creating it
when the target instance has never seen it.

That is this module.  Callers pass the owning manufacturer and the names; they get
ids back.  The scope rule, the catalog files, the lookup, the creation, and the cache
stay in here, so the four call sites (device-type create, module-type create, change
detection, export) do not each restate them.
"""

import os
import re

import pynetbox
import requests
import yaml

from core.errors import FatalError

# Directory in the devicetype-library holding the catalog, one directory per manufacturer.
CATALOG_DIRNAME = "module-bay-types"

# Second resolution scope, for a class one vendor defines and another fills.
FALLBACK_MANUFACTURER = "Generic"


def manufacturer_slug(name):
    """Slugify a manufacturer name the way the library loader does.

    ``core.repo`` reduces every YAML ``manufacturer`` to this slug, because upstream data
    disagrees on case (RuggedCOM vs RuggedCom).  The catalog keys on the same slug so both
    sides meet on one value.
    """
    return re.sub(r"\W+", "-", (name or "").lower())


class ModuleBayTypeError(FatalError):
    """A reference could not be resolved to exactly one NetBox object.

    Raised per definition so the caller can log it and continue with the next one.
    Never raised for a difference this module could paper over: an unresolved name and
    a conflicting identity are both reported rather than guessed at.
    """


class ModuleBayCatalogError(FatalError):
    """The catalog itself could not be read, so no name in it can be trusted.

    A sibling of :class:`ModuleBayTypeError`, never a subclass: every caller recovers from
    that one per definition, which would turn a single unreadable catalog into one skipped
    component after another instead of ending the run once.
    """


class ModuleBayTypeCatalog:
    """Turn module-bay-type names into NetBox ids, creating what is missing.

    ``ids_for(manufacturer, names)`` resolves each name in the owning manufacturer's
    scope, then in ``Generic``, and raises :class:`ModuleBayTypeError` if neither has
    it.  Resolution creates the NetBox object, and the manufacturer that owns it, when
    they do not exist yet.  Returned order is not meaningful; callers compare as sets.

    Export does not use this class: it reads the names off the records NetBox returned,
    because an export run resolves nothing and so has no id-to-name mapping of its own.
    """

    def __init__(self, netbox, repo_path, handle):
        """Store the NetBox client, the library checkout to read the catalog from, and the log handle."""
        self._netbox = netbox
        self._catalog_dir = os.path.join(repo_path, CATALOG_DIRNAME)
        self._handle = handle
        self._entries = None
        self._load_error = None
        self._ids = {}
        self._manufacturer_ids = {}

    def ids_for(self, manufacturer, names):
        """Return the NetBox id for each name, resolved against *manufacturer* then Generic.

        *manufacturer* is a manufacturer slug, as produced by :func:`manufacturer_slug`.
        An empty list is a valid instruction to hold no classes; anything that is not a
        list of non-empty strings is refused rather than read as empty, because reading a
        malformed value as empty would drop a restriction the author asked for.
        """
        self._validate(names)
        # Duplicates collapse: the relationship is a set.
        return sorted({self._id_for(manufacturer, name) for name in names})

    def identities_for(self, manufacturer, names):
        """Return the identity each name resolves to, without touching NetBox.

        The identity is ``(manufacturer slug, slug)``: the object a reference means, not
        the name it is written as.  Two manufacturers may both define a class called
        ``X``, so a name alone cannot say which object is intended.

        This is the query half of the module.  :meth:`ids_for` is the command half and
        creates what is missing; this one reads only the catalog files, so change
        detection can ask what a reference means without causing anything to exist.
        """
        self._validate(names)
        return frozenset(
            (manufacturer_slug(entry["manufacturer"]), entry["slug"])
            for entry in (self._lookup(manufacturer, name) for name in names)
        )

    @staticmethod
    def _validate(names):
        """Reject anything that is not a list of non-empty names."""
        if names is None or not isinstance(names, list):
            raise ModuleBayTypeError(f"module_bay_types must be a list of names, got {names!r}")
        for name in names:
            if not isinstance(name, str) or not name.strip():
                raise ModuleBayTypeError(f"module_bay_types entries must be non-empty names, got {name!r}")

    def _id_for(self, manufacturer, name):
        entry = self._lookup(manufacturer, name)
        cache_key = (manufacturer_slug(entry["manufacturer"]), entry["name"])
        if cache_key not in self._ids:
            self._ids[cache_key] = self._netbox_id(entry)
        return self._ids[cache_key]

    def _lookup(self, manufacturer, name):
        """Find the catalog entry for *name*, owner scope first, then Generic."""
        entries = self._load_catalog()
        for scope in (manufacturer, manufacturer_slug(FALLBACK_MANUFACTURER)):
            entry = entries.get((scope, name))
            if entry is not None:
                return entry
        raise ModuleBayTypeError(
            f"Module bay type {name!r} is not in the catalog for manufacturer "
            f"{manufacturer!r} or {FALLBACK_MANUFACTURER!r}"
        )

    def _load_catalog(self):
        """Read every catalog file once, indexed by (manufacturer, name).

        A failure is cached too: it is terminal for the run, and re-walking the tree for
        every later lookup only repeats the same error more slowly.
        """
        if self._entries is not None:
            return self._entries
        if self._load_error is not None:
            raise self._load_error
        try:
            self._entries = self._read_catalog()
        except ModuleBayCatalogError as exc:
            self._load_error = exc
            raise
        return self._entries

    def _read_catalog(self):
        """Walk the catalog directory and return every entry, indexed by (manufacturer, name)."""
        entries = {}
        for root, _dirs, files in os.walk(self._catalog_dir):
            for filename in sorted(files):
                if not filename.endswith((".yaml", ".yml")):
                    continue
                path = os.path.join(root, filename)
                try:
                    with open(path, encoding="utf-8") as handle:
                        data = yaml.safe_load(handle)
                except (OSError, yaml.YAMLError) as exc:
                    raise ModuleBayCatalogError(
                        f"Module bay type catalog file {path!r} could not be read: {exc}"
                    ) from exc
                if not isinstance(data, dict):
                    continue
                # Reject a half-written entry here; the readers index on name and dereference slug.
                invalid = [
                    field
                    for field in ("name", "slug", "manufacturer")
                    if not isinstance(data.get(field), str) or not data[field].strip()
                ]
                if invalid:
                    raise ModuleBayCatalogError(
                        f"Module bay type in {path!r} is missing or malformed: {', '.join(invalid)}"
                    )
                key = (manufacturer_slug(data.get("manufacturer")), data.get("name"))
                if key in entries:
                    raise ModuleBayCatalogError(f"Duplicate module bay type {key[1]!r} for manufacturer {key[0]!r}")
                entries[key] = data
        return entries

    @staticmethod
    def _request(action, description):
        """Run one NetBox request, reporting a rejection as a catalog error.

        Callers resolve one definition at a time and recover from ModuleBayTypeError.  A
        raw RequestError or a dropped connection escapes that recovery and ends the run,
        which can leave a parent half created and every later definition unprocessed.
        """
        try:
            return action()
        except pynetbox.RequestError as exc:
            raise ModuleBayTypeError(f"NetBox rejected {description}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise ModuleBayTypeError(f"NetBox could not be reached for {description}: {exc}") from exc

    def _netbox_id(self, entry):
        """Return the id of the NetBox object for *entry*, creating it if absent."""
        manufacturer_id = self._manufacturer_id(entry["manufacturer"])
        existing = self._request(
            lambda: list(
                self._netbox.dcim.module_bay_types.filter(manufacturer_id=manufacturer_id, name=entry["name"])
            ),
            f"the lookup of module bay type {entry['name']!r}",
        )
        for record in existing:
            if record.slug != entry["slug"]:
                raise ModuleBayTypeError(
                    f"NetBox already has module bay type {entry['name']!r} for "
                    f"{entry['manufacturer']!r} with slug {record.slug!r}, but the catalog "
                    f"says {entry['slug']!r}. Resolve the conflict in NetBox; this import "
                    f"will not rename it."
                )
            return record.id

        payload = {"name": entry["name"], "slug": entry["slug"], "manufacturer": manufacturer_id}
        if entry.get("description"):
            payload["description"] = entry["description"]
        created = self._request(
            lambda: self._netbox.dcim.module_bay_types.create(payload),
            f"creating module bay type {entry['name']!r}",
        )
        self._handle.verbose_log(f"Module Bay Type Created: {entry['name']} ({entry['manufacturer']}) - {created.id}")
        return created.id

    def _manufacturer_id(self, name):
        """Return the id of *name*, creating the manufacturer when the catalog needs it.

        A Generic-scoped class is reachable from any vendor, so an import filtered to one
        manufacturer still has to create the manufacturer that owns the class.
        """
        if name in self._manufacturer_ids:
            return self._manufacturer_ids[name]
        found = self._request(
            lambda: list(self._netbox.dcim.manufacturers.filter(slug=manufacturer_slug(name))),
            f"the lookup of manufacturer {name!r}",
        )
        if found:
            self._manufacturer_ids[name] = found[0].id
        else:
            created = self._request(
                lambda: self._netbox.dcim.manufacturers.create({"name": name, "slug": manufacturer_slug(name)}),
                f"creating manufacturer {name!r}",
            )
            self._handle.verbose_log(f"Manufacturer Created: {name} - {created.id}")
            self._manufacturer_ids[name] = created.id
        return self._manufacturer_ids[name]
