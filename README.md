# Netbox Device Type Import

This library is intended to be your friend and help you import all the device-types defined within
the [NetBox Device Type Library Repository](https://github.com/netbox-community/devicetype-library).

> Tested working with 2.9.4, 2.10.4

## Description

This script will clone a copy of the `netbox-community/devicetype-library` repository to your
machine to allow it to import the device types you would like without copy and pasting them
into the Netbox UI.

## Getting Started

1. This script uses `uv` for dependency management.

   ```shell
   uv sync
   ```

1. There are two variables that are required when using this script to import device types
   into your NetBox installation. (1) Your Netbox instance URL and (2) a token with
   **write rights**.

Copy the existing `.env.example` to your own `.env` file, and fill in the variables.

```shell
cp .env.example .env
vim .env
```

Finally, we are able to execute the script and import some device templates!

## Usage

To use the script, simply execute the script as follows. `uv` will handle the virtual
environment.

```shell
uv run nb-dt-import.py
```

This will clone the latest master branch from the `netbox-community/devicetype-library`
from GitHub and install it into the `repo` subdirectory. If this directory already exists,
it will perform a `git pull` to update the repository instead.

Next, it will loop over every manufacturer and every device of every manufacturer and begin
checking if your Netbox install already has them, and if not, creates them. It will skip
preexisting manufacturers, devices, interfaces, etc. so as to not end up with duplicate
entries in your Netbox instance.

### Arguments

This script currently accepts a list of vendors as an argument, so that you can selectively
import devices.

To import only device by APC, for example:

```shell
./nb-dt-import.py --vendors apc
```

`--vendors` can also accept a comma-separated list of vendors if you want to import multiple.

```shell
./nb-dt-import.py --vendors apc,juniper
```

#### Update Mode

By default, the script only creates new device types and skips existing ones. To update
existing device types:

```shell
./nb-dt-import.py --update
```

This will:

- Add new components (interfaces, power ports, etc.) that are in YAML but missing from NetBox
- Update properties of existing components if they've changed
- Update device type properties (u_height, part_number, etc.) if they've changed
- **Report** components that exist in NetBox but are missing from YAML (won't delete by default)

#### Component Removal (Use with Caution)

> **WARNING**: Removing components can affect existing device instances in NetBox.

If you've changed a device type definition (for example, converting interfaces to module-bays
to support SFP modules), you can remove obsolete components with:

```shell
./nb-dt-import.py --update --remove-components
```

This will delete any components (interfaces, ports, bays, etc.) that exist in NetBox but are
no longer present in the YAML definition.

**Use cases**:

- Converting fixed interfaces to module-bays for modular devices
- Removing incorrectly defined components from device templates
- Cleaning up after major device type definition changes

**Important considerations**:

- Components attached to actual device instances may prevent deletion
- Review the change detection report before enabling component removal
- Test on a staging NetBox instance first if possible

## Docker build

It's possible to use this project as a docker container.

To build:

```shell
docker build -t netbox-devicetype-import-library .
```

Alternatively you can pull a pre-built image from GitHub Container Registry (ghcr.io):

```shell
docker pull ghcr.io/minitriga/netbox-device-type-library-import
```

The container supports the following env var as configuration:

- `REPO_URL`, the repo to look for device types
  (defaults to `https://github.com/netbox-community/devicetype-library.git`)
- `REPO_BRANCH`, the branch to check out if appropriate, defaults to master.
- `NETBOX_URL`, used to access netbox
- `NETBOX_TOKEN`, token for accessing netbox
- `VENDORS`, a comma-separated list of vendors to import (defaults to None)
- `REQUESTS_CA_BUNDLE`, path to a CA_BUNDLE for validation if you are using
  self-signed certificates (file must be included in the container)

To run:

```shell
docker run -e "NETBOX_URL=http://netbox:8080/" \
  -e "NETBOX_TOKEN=98765434567890" \
  ghcr.io/minitriga/netbox-device-type-library-import
```

## Contributing

We're happy about any pull requests!

## License

MIT
