import os
from dotenv import load_dotenv

load_dotenv()

REPO_URL = os.getenv("REPO_URL", default="https://github.com/netbox-community/devicetype-library.git")
REPO_BRANCH = os.getenv("REPO_BRANCH", default="master")
NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
IGNORE_SSL_ERRORS = os.getenv("IGNORE_SSL_ERRORS", default="False") == "True"
REPO_PATH = os.getenv(
    "REPO_PATH",
    default=f"{os.path.dirname(os.path.dirname(os.path.realpath(__file__)))}/repo",
)

# optionally load vendors through a comma separated list as env var
VENDORS = list(filter(None, os.getenv("VENDORS", "").split(",")))

# optionally load device types through a space separated list as env var
SLUGS = os.getenv("SLUGS", "").split()

NETBOX_FEATURES = {
    "modules": False,
    "rack_types": False,
}


def _parse_positive_int(var_name, default):
    """Parse an environment variable as a positive integer (>= 1).

    Returns *default* when the variable is unset.  Raises ``ValueError``
    with a clear message when the value is non-numeric or less than 1.
    """
    raw = os.getenv(var_name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{var_name} must be a positive integer, got {raw!r}") from None
    if value < 1:
        raise ValueError(f"{var_name} must be >= 1, got {value}")
    return value


GRAPHQL_PAGE_SIZE = _parse_positive_int("GRAPHQL_PAGE_SIZE", 5000)
PRELOAD_THREADS = _parse_positive_int("PRELOAD_THREADS", 8)

MANDATORY_ENV_VARS = ["REPO_URL", "NETBOX_URL", "NETBOX_TOKEN"]
