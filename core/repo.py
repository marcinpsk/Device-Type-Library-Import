import os
from glob import glob
from re import sub as re_sub
from urllib.parse import urlparse
from git import Repo, exc
import yaml
import concurrent.futures


def validate_git_url(url):
    """Determine whether a Git remote URL is allowed (HTTPS, SSH, or file://).

    Args:
        url (str): Git remote URL to validate. Accepted formats are HTTPS URLs with a hostname
            (e.g., https://host/...), SSH scp-like form beginning with `git@host:`
            (e.g., git@host:org/repo.git), ssh URLs starting with `ssh://`, or file:// URLs
            for local repositories (CI/testing).

    Returns:
        (bool, str or None): `True, None` if the URL is allowed; otherwise `False` and a
            short error message explaining why.
    """
    if not url or not str(url).strip():
        return False, "Empty URL"
    url = str(url).strip()

    # Allow HTTPS URLs
    if url.startswith("https://"):
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.hostname:
            # Optional: enforce an allowlist if desired
            # if parsed.hostname not in ("github.com", "gitlab.com"):
            #     return False, f"Host not allowed: {parsed.hostname}"
            return True, None
        return False, "Invalid HTTPS URL"

    # Allow SSH scp-like syntax: git@host:org/repo.git
    if url.startswith("git@"):
        # Validate there's a colon after the host
        if ":" in url.split("@", 1)[-1]:
            return True, None
        return False, "Invalid git@ URL format"

    # Allow SSH URLs: ssh://user@host/path
    if url.startswith("ssh://"):
        parsed = urlparse(url)
        if parsed.scheme == "ssh" and parsed.hostname:
            return True, None
        return False, "Invalid SSH URL"

    # Allow file:// URLs for local repos (CI / testing)
    if url.startswith("file://"):
        parsed = urlparse(url)
        if parsed.path or parsed.netloc:
            return True, None
        return False, "Invalid file:// URL: path is empty"

    return False, "URL must use HTTPS, SSH, or file protocol"


def validate_repo_path(repo_path):
    """Check whether *repo_path* is usable for a git clone or pull operation.

    If the path already exists it must be a directory; the parent directory
    must be writable when the path does not yet exist so that a new clone can
    be created there.

    Args:
        repo_path (str): Filesystem path intended for the local repository clone.

    Returns:
        tuple[bool, str]: ``(True, "")`` when the path is usable, or
            ``(False, reason)`` with a human-readable explanation otherwise.
    """
    if os.path.exists(repo_path):
        if not os.path.isdir(repo_path):
            return False, f"REPO_PATH '{repo_path}' exists but is not a directory"
        if not os.access(repo_path, os.W_OK):
            return False, f"REPO_PATH '{repo_path}' is not writable"
    else:
        parent = os.path.dirname(os.path.abspath(repo_path)) or "."
        if not os.path.isdir(parent):
            return False, f"REPO_PATH parent directory '{parent}' does not exist"
        if not os.access(parent, os.W_OK):
            return False, f"REPO_PATH parent directory '{parent}' is not writable"
    return True, ""


def normalize_port_mappings(data):
    """Normalize port mapping definitions in a parsed YAML device/module type dict.

    Supports two input formats and converts both to a unified internal representation:

    **Old inline format** (``rear_port`` / ``rear_port_position`` on each front-port entry)::

        front-ports:
          - name: FP1
            type: 8p8c
            rear_port: RP1
            rear_port_position: 1   # optional, default 1

    **New NetBox 4.5 port-mappings stanza**::

        port-mappings:
          - front_port: FP1
            rear_port: RP1
            front_port_position: 1  # optional, default 1
            rear_port_position: 1   # optional, default 1

    In both cases the result is that each front-port entry gains a ``_mappings`` list::

        [{"rear_port": "<rear-port-name>", "front_port_position": 1, "rear_port_position": 1}]

    The inline ``rear_port`` / ``rear_port_position`` keys and the top-level
    ``port-mappings`` stanza are removed from *data* in-place.

    Args:
        data (dict): Parsed YAML dict.  Modified in-place.

    Returns:
        str | None: An ``"Error: ..."`` string describing a validation failure, or
            ``None`` on success.
    """
    front_ports = data.get("front-ports") or []
    port_mappings_stanza = data.get("port-mappings")

    if not front_ports and "port-mappings" not in data:
        return None

    front_by_name = {fp["name"]: fp for fp in front_ports if fp.get("name")}
    rear_ports_declared = "rear-ports" in data
    rear_ports = data.get("rear-ports") or []
    rear_by_name = {rp["name"]: rp for rp in rear_ports if rp.get("name")}

    # --- Old inline format ---
    # Collect rear_port references declared directly on front-port entries.
    inline_mappings = {}  # {front_port_name: [mapping_dict, ...]}
    for fp in front_ports:
        rp_name = fp.get("rear_port")
        if rp_name is None:
            continue
        fp_name = fp.get("name")
        if rear_ports_declared and rp_name not in rear_by_name:
            return f"Error: front-port '{fp_name}' references unknown rear_port '{rp_name}'"
        rp_pos = fp.pop("rear_port_position", 1)
        fp.pop("rear_port")
        inline_mappings.setdefault(fp_name, []).append(
            {
                "rear_port": rp_name,
                "front_port_position": 1,
                "rear_port_position": rp_pos,
            }
        )

    # --- New port-mappings stanza ---
    stanza_mappings = {}  # {front_port_name: [mapping_dict, ...]}
    if "port-mappings" in data:
        for entry in port_mappings_stanza or []:
            fp_name = entry.get("front_port")
            rp_name = entry.get("rear_port")
            if not fp_name or not rp_name:
                return f"Error: port-mappings entry missing front_port or rear_port: {entry!r}"
            if fp_name not in front_by_name:
                return f"Error: port-mappings references unknown front_port '{fp_name}'"
            if rear_ports_declared and rp_name not in rear_by_name:
                return f"Error: port-mappings references unknown rear_port '{rp_name}'"
            stanza_mappings.setdefault(fp_name, []).append(
                {
                    "rear_port": rp_name,
                    "front_port_position": entry.get("front_port_position", 1),
                    "rear_port_position": entry.get("rear_port_position", 1),
                }
            )
        del data["port-mappings"]

    # --- Conflict detection ---
    # Accept both formats simultaneously only when they describe identical mappings.
    if inline_mappings and stanza_mappings:
        all_names = set(inline_mappings) | set(stanza_mappings)
        for name in all_names:
            inline = sorted(
                (m["rear_port"], m["front_port_position"], m["rear_port_position"])
                for m in inline_mappings.get(name, [])
            )
            stanza = sorted(
                (m["rear_port"], m["front_port_position"], m["rear_port_position"])
                for m in stanza_mappings.get(name, [])
            )
            if inline != stanza:
                return (
                    f"Error: front port '{name}' has conflicting mapping definitions "
                    f"(inline: {inline}, port-mappings stanza: {stanza})"
                )

    effective = stanza_mappings if stanza_mappings else inline_mappings
    for fp_name, mappings in effective.items():
        if fp_name in front_by_name:
            front_by_name[fp_name]["_mappings"] = mappings

    return None


def parse_single_file(file):
    """Load a YAML device mapping, convert its `manufacturer` to a slug dictionary, and record the source path.

    Args:
        file (str): Path to a YAML file containing a device mapping. The mapping must include
            a "manufacturer" field.

    Returns:
        dict: Parsed mapping with `manufacturer` replaced by `{"slug": "<slugified-name>"}` and
            `src` set to the file path.
        str: Error string beginning with "Error:" describing YAML parsing or other failure.
    """
    with open(file, "r") as stream:
        try:
            data = yaml.safe_load(stream)
            manufacturer = data["manufacturer"]
            # Use only slug for manufacturer lookup - more resilient to case mismatches
            # (e.g., RuggedCOM vs RuggedCom in upstream data)
            data["manufacturer"] = {"slug": re_sub(r"\W+", "-", manufacturer.lower())}
            if "profile" in data and isinstance(data["profile"], str):
                data["profile"] = {"name": data["profile"]}
            data["src"] = file
            err = normalize_port_mappings(data)
            if err:
                return err
            return data
        except yaml.YAMLError as excep:
            return f"Error: {excep}"
        except Exception as e:
            return f"Error: {e}"


class DTLRepo:
    """Manages a local clone of the Device Type Library Git repository.

    Handles cloning or updating the repository on construction, provides helpers
    for locating YAML device and module type files, and exposes a parallel file parser.
    """

    def __init__(self, args, repo_path, exception_handler):
        """Initialize repository management, updating an existing clone or creating a new one.

        If the target path already exists as a directory, the repository will be updated from
        its configured remote; otherwise the provided URL is validated and a new clone is
        created. The initializer sets instance attributes used by other methods (handler,
        supported YAML extensions, URL, repo path, branch, repo reference, and current
        working directory).

        Args:
            args: An object with `url` (str) and `branch` (str) attributes specifying the
                remote repository URL and branch to use.
            repo_path (str): Filesystem path where the repository should be cloned or where
                an existing clone is located.
            exception_handler: An object exposing `exception(name, context, message)` used
                to report validation and Git errors.
        """
        self.handle = exception_handler
        self.yaml_extensions = ["yaml", "yml"]
        self.url = args.url
        self.repo_path = repo_path
        self.branch = args.branch
        self.repo = None
        self.cwd = os.getcwd()

        is_path_valid, path_error = validate_repo_path(self.repo_path)
        if not is_path_valid:
            self.handle.exception("InvalidRepoPath", self.repo_path, path_error)

        if os.path.isdir(self.repo_path):
            # Repo exists; pull from existing remote (pull_repo validates origin URL)
            self.pull_repo()
        else:
            # Validate URL only when cloning a new repo
            is_valid, error_msg = validate_git_url(self.url)
            if not is_valid:
                self.handle.exception("InvalidGitURL", self.url, error_msg)
            self.clone_repo()

    def get_relative_path(self):
        """Get the repository path configured for this instance relative to the current working directory.

        Returns:
            The stored relative repository path (`repo_path`).
        """
        return self.repo_path

    def get_absolute_path(self):
        """Return the absolute filesystem path to the repository directory.

        Returns:
            str: Absolute path combining the repository path with the repository object's
                current working directory.
        """
        return os.path.join(self.cwd, self.repo_path)

    def get_devices_path(self):
        """Return the absolute path to the ``device-types`` directory within the repository."""
        return os.path.join(self.get_absolute_path(), "device-types")

    def get_modules_path(self):
        """Return the absolute path to the ``module-types`` directory within the repository."""
        return os.path.join(self.get_absolute_path(), "module-types")

    def get_racks_path(self):
        """Return the absolute path to the ``rack-types`` directory within the repository."""
        return os.path.join(self.get_absolute_path(), "rack-types")

    def slug_format(self, name):
        """Convert *name* to a slug by lowercasing and replacing non-word characters with hyphens."""
        return re_sub(r"\W+", "-", name.lower())

    def pull_repo(self):
        """Pull the latest changes for the configured branch from the existing local repository.

        Opens the existing clone at ``self.repo_path``, validates the origin URL (updating it
        if REPO_URL has changed), fetches from origin, and checks out ``self.branch``.
        Reports errors via the configured exception handler.
        """
        try:
            self.handle.log(
                "Package devicetype-library is already installed, " + f"updating {self.get_absolute_path()}"
            )
            self.repo = Repo(self.repo_path)
            origin_url = self.repo.remotes.origin.url

            # If the configured URL differs from the current remote, update it so the
            # fetch pulls from the right place (e.g. user switched forks in .env).
            if self.url and origin_url != self.url:
                is_valid, error_msg = validate_git_url(self.url)
                if not is_valid:
                    self.handle.exception("InvalidGitURL", self.url, error_msg)
                self.handle.verbose_log(f"Remote URL changed ({origin_url} → {self.url}), updating origin")
                self.repo.remotes.origin.set_url(self.url)
            else:
                is_valid, error_msg = validate_git_url(origin_url)
                if not is_valid:
                    self.handle.exception("InvalidGitURL", origin_url, error_msg)

            self.repo.remotes.origin.fetch(prune=True)

            remote_branch_names = [ref.name for ref in self.repo.remotes.origin.refs]
            if f"origin/{self.branch}" not in remote_branch_names:
                self.handle.exception("GitBranchNotFound", self.branch)

            # -B creates the branch if absent or resets it to the remote ref if present
            self.repo.git.checkout("-B", self.branch, f"origin/{self.branch}")
            self.handle.verbose_log(f"Updated repo from {self.repo.remotes.origin.url}")
        except exc.GitCommandError as git_error:
            self.handle.exception("GitCommandError", self.repo.remotes.origin.url, git_error)
        except Exception as git_error:
            self.handle.exception("Exception", "Git Repository Error", git_error)

    def clone_repo(self):
        """Clone the configured Git repository into the configured local path and record the cloned Repo instance.

        Attempts to clone from the repository URL into the absolute repository path and set
        self.repo to the resulting Repo; on success logs the origin URL via the configured
        handler. If cloning or Git operations fail, the exception is reported to the
        configured exception handler.
        """
        try:
            self.repo = Repo.clone_from(self.url, self.get_absolute_path(), branch=self.branch)
            self.handle.log(f"Package Installed {self.repo.remotes.origin.url}")
        except exc.GitCommandError as git_error:
            self.handle.exception("GitCommandError", self.url, git_error)
        except Exception as git_error:
            self.handle.exception("Exception", "Git Repository Error", git_error)

    def get_devices(self, base_path, vendors: list = None):
        """Discover device YAML files and vendor directories under a base path.

        Args:
            base_path (str): Directory path containing vendor subdirectories (each vendor
                folder contains device YAML files).
            vendors (list, optional): List of vendor names (case-insensitive) to include;
                if omitted, all vendors are considered.

        Returns:
            tuple[list, list]: A pair of (files, discovered_vendors) where files is a list
                of file paths to discovered YAML files (extensions from self.yaml_extensions)
                under matching vendor folders, and discovered_vendors is a list of dicts with
                keys 'name' (str) and 'slug' (str) for each vendor.

        Note:
            The folder named "testing" (case-insensitive) is ignored.
        """
        files = []
        discovered_vendors = []
        vendor_dirs = os.listdir(base_path)

        for folder in [vendor for vendor in vendor_dirs if not vendors or vendor.casefold() in vendors]:
            if folder.casefold() != "testing":
                discovered_vendors.append({"name": folder, "slug": self.slug_format(folder)})
                for extension in self.yaml_extensions:
                    files.extend(glob(os.path.join(base_path, folder, f"*.{extension}")))
        return files, discovered_vendors

    def parse_files(self, files: list, slugs: list = None, progress=None):
        """Parse YAML device files into device type dicts, optionally filtering and tracking progress.

        Args:
            files (Iterable[str]): Paths of YAML files to parse.
            slugs (list[str], optional): Device-type slug or model substrings used to filter results;
                an item is included if any provided slug is a case-insensitive substring of the item's
                ``"slug"`` or ``"model"`` field. If omitted, no slug filtering is applied.
            progress (Iterable, optional): Iterable consumed in parallel with parsing to drive an
                external progress display; values are ignored but should yield once per file.

        Returns:
            list: Parsed device type dictionaries. Files that fail parsing (returned as strings
                beginning with ``"Error:"``) are logged and excluded. Parsed items that do not
                match the provided slug filters are also excluded.
        """
        deviceTypes = []

        # Use ThreadPoolExecutor for parallel parsing
        with concurrent.futures.ThreadPoolExecutor() as executor:
            try:
                # executor.map preserves order and processes the same files list
                # progress (if provided) is a progress wrapper over the same files list
                # Use strict=True to catch any length mismatch instead of silent truncation
                files_list = list(files)  # Ensure we have a concrete list
                items_iterator = progress if progress is not None else files_list
                results = executor.map(parse_single_file, files_list)

                for _, data in zip(items_iterator, results, strict=True):
                    if isinstance(data, str) and data.startswith("Error:"):
                        self.handle.verbose_log(data)
                        continue

                    if slugs:
                        slug_target = str(data.get("slug") or data.get("model") or "").casefold()
                        if not any(s.casefold() in slug_target for s in slugs):
                            self.handle.verbose_log(f"Skipping {data.get('model', 'Unknown')}")
                            continue

                    deviceTypes.append(data)
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

        return deviceTypes
