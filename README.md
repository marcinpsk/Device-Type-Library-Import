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
into the `repo` subdirectory (configurable via `REPO_PATH`), then loops over every manufacturer
and device, creating anything that is missing from NetBox while skipping entries that already exist.

### Environment Variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `NETBOX_URL` | ✅ | — | URL of your NetBox instance |
| `NETBOX_TOKEN` | ✅ | — | API token with write access |
| `REPO_URL` | | community library | Git URL of the device-type library to clone |
| `REPO_BRANCH` | | `master` | Branch to check out |
| `REPO_PATH` | | `./repo` | Local path where the library is cloned. Accepts absolute or relative paths. |
| `IGNORE_SSL_ERRORS` | | `False` | Set `True` to skip TLS verification (dev only) |
| `GRAPHQL_PAGE_SIZE` | | `5000` | Items per GraphQL page |
| `PRELOAD_THREADS` | | `8` | Threads for concurrent component preloading |

> ⚠️ **Tokens:** Please note there is a difference in setting the token based on whether you are using v1 or v2 tokens
>
> For v1, your token will simply be the secret part generated when you create the api token in netbox:
>
> `NETBOX_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
>
> For v2 tokens, you need to include prefix "nbt_", the bearer key (represented here by capital
> X-es), a dot, and finally the secret token (represented by lowercase x-es):
>
>`NETBOX_TOKEN=nbt_XXXXXXXXXXXX.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

### Arguments

This script provides ways to selectively import devices via `--vendors` and `--slugs` arguments.

To import only devices from one vendor, or multiple vendors:

```shell
uv run nb-dt-import.py --vendors apc
uv run nb-dt-import.py --vendors apc,juniper
```

`--slugs` does partial matching on each device type's slug and supports multiple values:

```shell
uv run nb-dt-import.py --slugs x440-g2            # Imports 11 network switch device type variations
uv run nb-dt-import.py --slugs ap4433a,ap7526     # Imports two specific PDUs
```

`--vendors` and `--slugs` can be combined:

```shell
uv run nb-dt-import.py --vendors "Palo Alto" --slugs 440
```

#### All Arguments

| Argument | Default | Description |
| --- | --- | --- |
| `--vendors` | all | Comma- or space-separated list of vendors to import (e.g. `apc cisco`) |
| `--slugs` | all | Comma- or space-separated device-type slug substrings to filter (partial match) |
| `--url` / `--git` | community library | Git URL of the device-type library to clone |
| `--branch` | `master` | Git branch to check out from the repo |
| `--verbose` | off | Print verbose output (individual create/update messages) |
| `--show-remaining-time` | off | Show estimated remaining time in progress bars |
| `--only-new` | off | Only create new types, skip all existing ones (mutually exclusive with `--update`) |
| `--update` | off | Update existing types with changes from the repo (mutually exclusive with `--only-new`) |
| `--remove-components` | off | Delete components missing from YAML when used with `--update`. **Destructive.** |
| `--remove-unmanaged-types` | off | Also delete components whose entire YAML section is missing (e.g. NetBox has interfaces but YAML defines none). Requires `--remove-components`. **Aggressive.** |
| `--force-resolve-conflicts` | off | Automatically resolve NetBox constraint failures during `--update`. **Destructive.** See below. |
| `--verify-images` | off | Verify images recorded in NetBox are physically present on the server. Uses an HTTP presence check per image and a local SHA-256 cache to detect local file changes (does not hash the remote file). Re-uploads any image that is missing on the server or whose local file has changed. Useful after recreating a devcontainer or updating local image files. **Makes one HTTP request per image.** |

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
- By default, `--remove-components` only removes components from YAML sections that are
  *present but no longer list a given component*. If a YAML omits an entire section
  (for example, a chassis with no `interfaces:` key), pre-existing NetBox interfaces are
  left untouched. Add `--remove-unmanaged-types` to treat a missing section the same as an
  empty list and remove every component of that type from NetBox.

```shell
uv run nb-dt-import.py --update --remove-components --remove-unmanaged-types
```

#### Conflict Resolution (Use with Caution)

> **WARNING**: `--force-resolve-conflicts` performs destructive NetBox operations automatically.

Some NetBox business-logic constraints block updates even when no live device instances use the
affected type. For example, changing a device type's `subdevice_role` from `parent` to `child`
requires deleting all device-bay templates first. To allow the script to perform that remediation
automatically:

```shell
uv run nb-dt-import.py --update --force-resolve-conflicts
```

**What it does**:

- When a PATCH fails with a constraint error, the script checks whether any live devices
  reference the affected type
- If **no** live devices reference it, the blocking objects (e.g. device-bay templates) are
  deleted and the PATCH is retried
- If live devices **do** reference it, the update is skipped and logged as a failure — no
  destructive action is taken

**Safety guarantees**:

- Never deletes blocking objects when live device instances exist
- Requires `--update` (will error without it)
- All auto-resolved and skipped items appear in the run summary

**When to use**:

- After converting device types from parent to child (or vice versa)
- When the script reports constraint failures that block property updates

#### Image Verification (`--verify-images`)

By default, the script skips uploading images that already have a URL recorded in the NetBox
database. This means physically missing images (e.g. after recreating a devcontainer) or updated
local image files are not re-uploaded. Use `--verify-images` to re-check:

```shell
uv run nb-dt-import.py --vendors nokia --verify-images
```

**What it does**:

- For each device type / module type whose image is already recorded in NetBox, issues an HTTP
  GET to verify the file is physically accessible on the server
- Compares the local file's SHA-256 hash against a persistent local cache (the remote file is
  **not** downloaded or hashed; a 2xx HTTP response is treated as "present")
- Re-uploads the image if it is **missing** (server returned a non-2xx response) or
  **changed** (the local file's hash differs from the cached value recorded at last upload)

**When to use**:

- After recreating a devcontainer or restoring NetBox without its media volume — the database
  still knows about images, but the files are gone
- After replacing a local image file with a higher-quality version and wanting NetBox to pick
  it up

We're happy about any pull requests!

### Keeping import paths in sync

`create_device_types` in `core/netbox_api.py` has three branches that run per device type: the
`only_new` early-return path, the `update` path, and the default (creation) path. Each branch
has its own image-progress block. The same three-branch pattern repeats in `create_module_types`.
`create_rack_types` follows a similar existing/update/create structure but does **not** handle
images, so image-handling changes only need to be applied to `create_device_types` and
`create_module_types`.

## License

MIT
