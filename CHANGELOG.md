# CHANGELOG

<!-- version list -->

## v1.0.2 (2026-03-01)

### Bug Fixes

- Exclude already-uploaded images from progress bar total
  ([#24](https://github.com/marcinpsk/Device-Type-Library-Import/pull/24),
  [`a7c8d9b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/a7c8d9b5021046432248e5e46309479dcaaaac4a))

- Show proper image upload progress bar with total count
  ([#24](https://github.com/marcinpsk/Device-Type-Library-Import/pull/24),
  [`a7c8d9b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/a7c8d9b5021046432248e5e46309479dcaaaac4a))

### Chores

- Updated dependencies ([#24](https://github.com/marcinpsk/Device-Type-Library-Import/pull/24),
  [`a7c8d9b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/a7c8d9b5021046432248e5e46309479dcaaaac4a))

## v1.0.1 (2026-02-28)

### Bug Fixes

- Use python directly instead of uv run in Dockerfile CMD
  ([`3d8a808`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3d8a8089cff8a0bde716864bbe5dc15ad9a0085d))
- Fix Dockerfile missing core copy @Pa0x43 ([`b562177`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/b56217755e9235b652b34d461f0733b975567de8))

## v1.0.0 (2026-02-23)

### Bug Fixes

- Correct NetBox configuration path and heredoc indentation in CI
  ([#21](https://github.com/marcinpsk/Device-Type-Library-Import/pull/21),
  [`3ff48ec`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3ff48ec4bff5f9785991d9a1f58fd0efd01da9ff))

- NetBox 4.5+ compatibility with v2 token auth for CI improvements
  ([#22](https://github.com/marcinpsk/Device-Type-Library-Import/pull/22),
  [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))

- Restore Checkov suppression comments and add explicit UTF-8 encoding
  ([#21](https://github.com/marcinpsk/Device-Type-Library-Import/pull/21),
  [`3ff48ec`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3ff48ec4bff5f9785991d9a1f58fd0efd01da9ff))

- Update semantic-release config to v8+ and fix validate_git_url docstring
  ([#22](https://github.com/marcinpsk/Device-Type-Library-Import/pull/22),
  [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))

- Validate file:// URLs have a non-empty path
  ([#22](https://github.com/marcinpsk/Device-Type-Library-Import/pull/22),
  [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))

- Weekly CI, core/ restructure, v2 token auth, and release workflow
  ([#22](https://github.com/marcinpsk/Device-Type-Library-Import/pull/22),
  [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))

## v0.4.0 (2026-02-22)

### Bug Fixes

- 1. Module-type progress tracking — wrapped files with get_progress_wrapper(progress, files,
  desc=Parsing Module Types) before
  ([`0fde990`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0fde990bb1f551261e00d9e0faf7d41b18ccd5c9))

### Build System

- **deps**: Bump rich from 14.3.2 to 14.3.3
  ([#20](https://github.com/marcinpsk/Device-Type-Library-Import/pull/20),
  [`e8366ca`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/e8366ca9d71f533f1f612e248f06c269f5a0ed1f))

- **deps-dev**: Bump ruff from 0.15.1 to 0.15.2
  ([#19](https://github.com/marcinpsk/Device-Type-Library-Import/pull/19),
  [`584011f`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/584011fa6e472ce5dde77bf00e47f62d04279cc5))

### Features

- Migrate read queries from REST to GraphQL with configurable tuning
  ([#18](https://github.com/marcinpsk/Device-Type-Library-Import/pull/18),
  [`7f63a0f`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/7f63a0f6b0bb65563b9a9a2c3aeefd46884a5f48))

## v0.2.0 (2026-02-17)

- Initial Release
