# NetBox Device Type Import

[![Tests](https://github.com/marcinpsk/Device-Type-Library-Import/actions/workflows/tests.yml/badge.svg)](https://github.com/marcinpsk/Device-Type-Library-Import/actions/workflows/tests.yml)
[![NetBox main](https://github.com/marcinpsk/Device-Type-Library-Import/actions/workflows/test-netbox-main.yaml/badge.svg)](https://github.com/marcinpsk/Device-Type-Library-Import/actions/workflows/test-netbox-main.yaml)
[![NetBox](https://img.shields.io/badge/NetBox-3.2%2B_through_4.5%2B-blue)](https://netbox.dev)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org)

This library is intended to be your friend and help you import all the device-types defined within
the [NetBox Device Type Library Repository](https://github.com/netbox-community/devicetype-library).

> **Tested working with NetBox 3.2+ through 4.5+** (weekly CI run against NetBox `main`)

---

> ⚠️ **direnv users** — This repo ships a `.envrc.example` file.  If you use
> [direnv](https://direnv.net/), **review the file before enabling it**:
>
> ```shell
> cp .envrc.example .envrc
> cat .envrc          # confirm it only loads .env vars and syncs uv
> direnv allow
> ```
>
> The file exclusively loads variables from `.env` into your shell and runs
> `uv sync` to keep dependencies up to date.  Your `.envrc` is git-ignored.

## Description

This script will clone a copy of the `netbox-community/devicetype-library` repository to your
machine to allow it to import the device types you would like without copy and pasting them
into the NetBox UI.

## Getting Started

1. Install dependencies with `uv`:

   ```shell
   uv sync
   ```

1. Copy `.env.example` to `.env` and fill in your NetBox URL and API token
   (the token needs **write rights**):

   ```shell
   cp .env.example .env
   vim .env
   ```

1. Run the script:

   ```shell
   uv run nb-dt-import.py
   ```

## Usage

Running the script clones (or updates) the `netbox-community/devicetype-library` repository
into the `repo` subdirectory, then loops over every manufacturer and device, creating anything
that is missing from NetBox while skipping entries that already exist.

### Arguments

This script currently accepts a list of vendors as an argument, so that you can selectively
import devices.

To import only device by APC, for example:

```shell
uv run nb-dt-import.py --vendors apc
```

`--vendors` can also accept a comma-separated list of vendors if you want to import multiple.

```shell
uv run nb-dt-import.py --vendors apc,juniper
```

#### Update Mode

By default, the script only creates new device types and skips existing ones. To update
existing device types:

```shell
uv run nb-dt-import.py --update
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
uv run nb-dt-import.py --update --remove-components
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

## Contributing

We're happy about any pull requests!

## License

MIT
