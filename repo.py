import os
from glob import glob
from re import sub as re_sub
from urllib.parse import urlparse
from git import Repo, exc
import yaml
import concurrent.futures


def validate_git_url(url):
    """
    Determine whether a Git remote URL is allowed (HTTPS or SSH).

    Parameters:
        url (str): Git remote URL to validate. Accepted formats are HTTPS URLs with a hostname (e.g., https://host/...),
            SSH scp-like form beginning with `git@host:` (e.g., git@host:org/repo.git), or ssh URLs starting with `ssh://`.

    Returns:
        (bool, str or None): `True, None` if the URL is allowed; otherwise `False` and a short error message explaining why.
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

    return False, "URL must use HTTPS or SSH protocol"


def parse_single_file(file):
    """
    Load a YAML device mapping, convert its `manufacturer` to a slug dictionary, and record the source path.

    Parameters:
        file (str): Path to a YAML file containing a device mapping. The mapping must include a "manufacturer" field.

    Returns:
        dict: Parsed mapping with `manufacturer` replaced by `{"slug": "<slugified-name>"}` and `src` set to the file path.
        str: Error string beginning with "Error:" describing YAML parsing or other failure.
    """
    with open(file, "r") as stream:
        try:
            data = yaml.safe_load(stream)
            manufacturer = data["manufacturer"]
            # Use only slug for manufacturer lookup - more resilient to case mismatches
            # (e.g., RuggedCOM vs RuggedCom in upstream data)
            data["manufacturer"] = {"slug": re_sub(r"\W+", "-", manufacturer.lower())}
            data["src"] = file
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

    def __new__(cls, *args, **kwargs):
        """
        Allocate and return a new instance of the class using the default object allocator.

        Returns:
            instance: A newly created instance of the class `cls`.
        """
        return super().__new__(cls)

    def __init__(self, args, repo_path, exception_handler):
        """
        Initialize repository management and ensure a local clone exists by either updating an existing clone or cloning the remote.

        If the target path already exists as a directory, the repository will be updated from its configured remote; otherwise the provided URL is validated and a new clone is created. The initializer sets instance attributes used by other methods (handler, supported YAML extensions, URL, repo path, branch, repo reference, and current working directory).

        Parameters:
            args: An object with `url` (str) and `branch` (str) attributes specifying the remote repository URL and branch to use.
            repo_path (str): Filesystem path where the repository should be cloned or where an existing clone is located.
            exception_handler: An object exposing `exception(name, context, message)` used to report validation and Git errors.
        """
        self.handle = exception_handler
        self.yaml_extensions = ["yaml", "yml"]
        self.url = args.url
        self.repo_path = repo_path
        self.branch = args.branch
        self.repo = None
        self.cwd = os.getcwd()

        if os.path.isdir(self.repo_path):
            # Repo exists, pull from existing remote (no URL validation needed)
            self.pull_repo()
        else:
            # Validate URL only when cloning a new repo
            is_valid, error_msg = validate_git_url(self.url)
            if not is_valid:
                self.handle.exception("InvalidGitURL", self.url, error_msg)
            self.clone_repo()

    def get_relative_path(self):
        """
        Get the repository path configured for this instance relative to the current working directory.

        Returns:
            The stored relative repository path (`repo_path`).
        """
        return self.repo_path

    def get_absolute_path(self):
        """
        Return the absolute filesystem path to the repository directory.

        Returns:
            str: Absolute path combining the repository path with the repository object's current working directory.
        """
        return os.path.join(self.cwd, self.repo_path)

    def get_devices_path(self):
        """Return the absolute path to the ``device-types`` directory within the repository."""
        return os.path.join(self.get_absolute_path(), "device-types")

    def get_modules_path(self):
        """Return the absolute path to the ``module-types`` directory within the repository."""
        return os.path.join(self.get_absolute_path(), "module-types")

    def slug_format(self, name):
        """Convert *name* to a slug by lowercasing and replacing non-word characters with hyphens."""
        return re_sub(r"\W+", "-", name.lower())

    def pull_repo(self):
        """Pull the latest changes for the configured branch from the existing local repository.

        Opens the existing clone at ``self.repo_path``, validates the origin URL, pulls from
        origin, and checks out ``self.branch``. Reports errors via the configured exception handler.
        """
        try:
            self.handle.log(
                "Package devicetype-library is already installed, " + f"updating {self.get_absolute_path()}"
            )
            self.repo = Repo(self.repo_path)
            if not self.repo.remotes.origin.url.endswith(".git"):
                self.handle.exception(
                    "GitInvalidRepositoryError",
                    self.repo.remotes.origin.url,
                    f"Origin URL {self.repo.remotes.origin.url} does not end with .git",
                )
            self.repo.remotes.origin.pull()
            self.repo.git.checkout(self.branch)
            self.handle.verbose_log(f"Pulled Repo {self.repo.remotes.origin.url}")
        except exc.GitCommandError as git_error:
            self.handle.exception("GitCommandError", self.repo.remotes.origin.url, git_error)
        except Exception as git_error:
            self.handle.exception("Exception", "Git Repository Error", git_error)

    def clone_repo(self):
        """
        Clone the configured Git repository into the configured local path and record the cloned Repo instance.

        Attempts to clone from the repository URL into the absolute repository path and set self.repo to the resulting Repo; on success logs the origin URL via the configured handler. If cloning or Git operations fail, the exception is reported to the configured exception handler.
        """
        try:
            self.repo = Repo.clone_from(self.url, self.get_absolute_path(), branch=self.branch)
            self.handle.log(f"Package Installed {self.repo.remotes.origin.url}")
        except exc.GitCommandError as git_error:
            self.handle.exception("GitCommandError", self.url, git_error)
        except Exception as git_error:
            self.handle.exception("Exception", "Git Repository Error", git_error)

    def get_devices(self, base_path, vendors: list = None):
        """
        Discover device YAML files and vendor directories under a base path.

        Parameters:
            base_path (str): Directory path containing vendor subdirectories (each vendor folder contains device YAML files).
            vendors (list, optional): List of vendor names (case-insensitive) to include; if omitted, all vendors are considered.

        Returns:
            tuple:
                files (list): List of file paths to discovered YAML files (extensions from self.yaml_extensions) under matching vendor folders.
                discovered_vendors (list): List of dicts for each discovered vendor with keys:
                    - name (str): Vendor directory name.
                    - slug (str): Slugified vendor name produced by self.slug_format.
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
        """
        Parse YAML device files into device type dictionaries, optionally filtering by vendor slugs and advancing a progress iterable.

        Parameters:
            files (Iterable[str]): Paths of YAML files to parse.
            slugs (list[str], optional): Vendor slug substrings used to filter results; an item is included if any provided slug is a case-insensitive substring of the item's `"slug"`. If omitted, no slug filtering is applied.
            progress (Iterable, optional): Iterable consumed in parallel with parsing to drive an external progress display; values are ignored but the iterable should yield once per file.

        Returns:
            list: Parsed device type dictionaries. Files that fail parsing (returned as strings beginning with `"Error:"`) are logged via the instance handler and excluded. Parsed items that do not match the provided slug filters are also excluded.
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
