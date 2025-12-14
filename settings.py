import os
from dotenv import load_dotenv

load_dotenv()

REPO_URL = os.getenv("REPO_URL", default="https://github.com/netbox-community/devicetype-library.git")
REPO_BRANCH = os.getenv("REPO_BRANCH", default="master")
NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
IGNORE_SSL_ERRORS = os.getenv("IGNORE_SSL_ERRORS", default="False") == "True"
REPO_PATH = f"{os.path.dirname(os.path.realpath(__file__))}/repo"

# optionally load vendors through a comma separated list as env var
VENDORS = list(filter(None, os.getenv("VENDORS", "").split(",")))

# optionally load device types through a space separated list as env var
SLUGS = os.getenv("SLUGS", "").split()

NETBOX_FEATURES = {
    "modules": False,
}

MANDATORY_ENV_VARS = ["REPO_URL", "NETBOX_URL", "NETBOX_TOKEN"]
