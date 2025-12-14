import os
import re
from glob import glob
from re import sub as re_sub
from git import Repo, exc
import yaml
import concurrent.futures


def validate_git_url(url):
    """
    Validate that a git remote URL uses HTTPS or SSH and reject unsafe or local schemes.
    
    Returns:
        tuple: (bool, str or None) — (True, None) if the URL is allowed; (False, error_message) otherwise.
    """
    if not url:
        return False, "Empty URL"

    # Allow HTTPS
    if re.match(r"^https://[\w.-]+/", url):
        return True, None

    # Allow SSH patterns
    if re.match(r"^git@[\w.-]+:", url) or re.match(r"^ssh://", url):
        return True, None

    return False, f"URL must use HTTPS or SSH protocol, got: {url}"


def parse_single_file(file):
    """
    Load a YAML device file, replace its "manufacturer" value with a slug dictionary, add the source path, and return the parsed data or an error string.
    
    Parameters:
        file (str): Path to a YAML file containing device data. The file must include a "manufacturer" field.
    
    Returns:
        dict: The parsed YAML mapping with "manufacturer" replaced by {"slug": "<slugified-name>"} and "src" set to the file path.
        str: An error string beginning with "Error:" describing YAML parsing or other failures.
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
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, args, repo_path, exception_handler):
        """
        Initialize the repository manager, validate the repository URL, and ensure a local clone is present by cloning or pulling.
        
        Sets instance attributes (handler, yaml extensions, URL, repo path, branch, repo reference, and current working directory). Validates `args.url` using `validate_git_url` and, if invalid, reports the problem via `exception_handler.exception("InvalidGitURL", url, message)`. If `repo_path` exists as a directory, updates the repository by calling `pull_repo`; otherwise creates a local clone by calling `clone_repo`.
        
        Parameters:
            args: An object with `url` (str) and `branch` (str) attributes providing the remote repository URL and branch to use.
            repo_path (str): Filesystem path where the repository should be cloned or exists.
            exception_handler: An object exposing `exception(name, context, message)` used to report validation and Git errors as side effects.
        """
        self.handle = exception_handler
        self.yaml_extensions = ["yaml", "yml"]
        self.url = args.url
        self.repo_path = repo_path
        self.branch = args.branch
        self.repo = None
        self.cwd = os.getcwd()

        # Validate URL before cloning
        is_valid, error_msg = validate_git_url(self.url)
        if not is_valid:
            self.handle.exception("InvalidGitURL", self.url, error_msg)

        if os.path.isdir(self.repo_path):
            self.pull_repo()
        else:
            self.clone_repo()

    def get_relative_path(self):
        return self.repo_path

    def get_absolute_path(self):
        return os.path.join(self.cwd, self.repo_path)

    def get_devices_path(self):
        return os.path.join(self.get_absolute_path(), "device-types")

    def get_modules_path(self):
        return os.path.join(self.get_absolute_path(), "module-types")

    def slug_format(self, name):
        return re_sub(r"\W+", "-", name.lower())

    def pull_repo(self):
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
        try:
            self.repo = Repo.clone_from(self.url, self.get_absolute_path(), branch=self.branch)
            self.handle.log(f"Package Installed {self.repo.remotes.origin.url}")
        except exc.GitCommandError as git_error:
            self.handle.exception("GitCommandError", self.url, git_error)
        except Exception as git_error:
            self.handle.exception("Exception", "Git Repository Error", git_error)

    def get_devices(self, base_path, vendors: list = None):
        files = []
        discovered_vendors = []
        vendor_dirs = os.listdir(base_path)

        for folder in [vendor for vendor in vendor_dirs if not vendors or vendor.casefold() in vendors]:
            if folder.casefold() != "testing":
                discovered_vendors.append({"name": folder, "slug": self.slug_format(folder)})
                for extension in self.yaml_extensions:
                    files.extend(glob(base_path + folder + f"/*.{extension}"))
        return files, discovered_vendors

    def parse_files(self, files: list, slugs: list = None, progress=None):
        """
        Parse multiple YAML device files into device type dictionaries, optionally filtering by vendor slugs and integrating with a progress iterator.
        
        Parameters:
            files (list): Iterable of file paths to parse.
            slugs (list, optional): List of vendor slug substrings to filter results. A parsed item's "slug" is included if any slug from this list is a case-insensitive substring of the item's "slug". If omitted, no slug filtering is applied.
            progress (iterable, optional): Optional iterable used to drive a progress display (must yield one item per file). The function iterates this in parallel with parsing so the progress display can be advanced; the values from this iterable are ignored.
        
        Returns:
            list: A list of parsed device type dictionaries. Files that fail to parse (returned as strings beginning with "Error:") are logged via the instance handler and omitted from the returned list. Files whose parsed data do not match the provided slug filters are also omitted.
        """
        deviceTypes = []

        # Use ThreadPoolExecutor for parallel parsing
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Strategies for progress bar interop:
            # We iterate 'progress' if it's provided (which yields files and updates the bar)
            # AND we need to yield results from executor.
            # executor.map preserves order.

            items_iterator = progress if progress is not None else files
            results = executor.map(parse_single_file, files)

            for _, data in zip(items_iterator, results):
                if isinstance(data, str) and data.startswith("Error:"):
                    self.handle.verbose_log(data)
                    continue

                if slugs and True not in [True if s.casefold() in data["slug"].casefold() else False for s in slugs]:
                    self.handle.verbose_log(f"Skipping {data['model']}")
                    continue

                deviceTypes.append(data)

        return deviceTypes