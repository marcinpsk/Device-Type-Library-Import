# CHANGELOG

<!-- version list -->

## v1.1.0 (2026-03-01)

### Bug Fixes

- Address code review findings (src_file in error msg, empty env vars, slug guard, test assertions, docstrings, coverage xml) (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Coerce float strings via float() in _values_equal to avoid false updates (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Strip trailing newlines in _values_equal to handle yaml literal blocks (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Numeric coercion, missing exception key, deterministic glob, docs (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Address code review findings in log_handler and netbox_api (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))


### Build System

- **deps**: Bump python from 3.12-slim to 3.14-slim (#26, [`ab23bcf`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/ab23bcf3cadd4950227da6d30c6041cba6863960))
- **deps-dev**: Bump ruff from 0.15.2 to 0.15.4 (#25, [`4946d44`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/4946d44013e55997881f38beb257c67610045520))


### Documentation

- Add contribution attribution to changelog and fix markdownlint (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))


### Features

- Add rack-type, reduce complexity, add option to configure repo_path location (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Add ci coverage check, semantic-release contributor attribution (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Repo_path env var, move default back to project root, add path validation (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Add rack-types import support (netbox >= 4.1) (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))


### Refactoring

- Reduce log_change_report complexity below 15 (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Reduce netbox_api.py complexity below 15 (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))
- Reduce main() complexity below 15 (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))


### Testing

- Achieve 100% coverage of nb-dt-import.py (#27, [`de988fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/de988fc76a6b8e19651686e308d31703130c4651))



### Contributors

@dependabot[bot], @marcinpsk

## v1.0.2 (2026-03-01)

### Bug Fixes

- Show proper image upload progress bar with total count (#24, [`a7c8d9b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/a7c8d9b5021046432248e5e46309479dcaaaac4a))
- Show proper image upload progress bar with total count (#24, [`a7c8d9b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/a7c8d9b5021046432248e5e46309479dcaaaac4a))
- Exclude already-uploaded images from progress bar total (#24, [`a7c8d9b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/a7c8d9b5021046432248e5e46309479dcaaaac4a))


### Chores

- Updated dependencies (#24, [`a7c8d9b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/a7c8d9b5021046432248e5e46309479dcaaaac4a))



### Contributors

@marcinpsk

## v1.0.1 (2026-02-28)

### Bug Fixes

- Use python directly instead of uv run in dockerfile cmd ([`3d8a808`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3d8a8089cff8a0bde716864bbe5dc15ad9a0085d))



### Contributors

@Pa0x43

## v1.0.0 (2026-02-23)

### Bug Fixes

- Netbox 4.5+ compatibility with v2 token auth for ci improvements (#22, [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))
- Weekly ci, core/ restructure, v2 token auth, and release workflow (#22, [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))
- Update semantic-release config to v8+ and fix validate_git_url docstring (#22, [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))
- Validate file:// urls have a non-empty path (#22, [`0ba1006`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0ba1006344587ca0fb78effa0cbef03393aa386b))
- Correct netbox configuration path and heredoc indentation in ci (#21, [`3ff48ec`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3ff48ec4bff5f9785991d9a1f58fd0efd01da9ff))
- Correct netbox configuration path and heredoc indentation in ci (#21, [`3ff48ec`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3ff48ec4bff5f9785991d9a1f58fd0efd01da9ff))
- Restore checkov suppression comments and add explicit utf-8 encoding (#21, [`3ff48ec`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3ff48ec4bff5f9785991d9a1f58fd0efd01da9ff))



### Contributors

@marcinpsk

## v0.4.0 (2026-02-22)

### Build System

- **deps-dev**: Bump ruff from 0.15.1 to 0.15.2 (#19, [`584011f`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/584011fa6e472ce5dde77bf00e47f62d04279cc5))
- **deps**: Bump rich from 14.3.2 to 14.3.3 (#20, [`e8366ca`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/e8366ca9d71f533f1f612e248f06c269f5a0ed1f))


### Features

- Migrate read queries from rest to graphql with configurable tuning (#18, [`7f63a0f`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/7f63a0f6b0bb65563b9a9a2c3aeefd46884a5f48))



### Contributors

@dependabot[bot], @marcinpsk

## v0.3.0 (2026-02-20)

### Bug Fixes

- 1. module-type progress tracking — wrapped files with get_progress_wrapper(progress, files, desc=parsing module types) before ([`0fde990`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0fde990bb1f551261e00d9e0faf7d41b18ccd5c9))



### Contributors

@marcinpsk

## v0.2.0 (2026-02-17)

### Bug Fixes

- Skip absent yaml properties in change detection, remove unused method, fix update cache ([`17d3561`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/17d3561d36f7a5dded12698be6d3586317f1476a))
- Detect property removals, guard component removal detection, and fix null yaml values ([`641ff69`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/641ff6954d64c264dbdffde16193bc51172b8dac))
- Updated progress on compare ([`1f229f8`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/1f229f87f56ac053e16f5e59a955a0b41383be7c))
- Use _get_cached_or_fetch in _create_generic to fix module component detection ([`abb1c87`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/abb1c875be48ec3a66f0d74e3998887265d60b8c))
- Invalidate component cache after successful removal in remove_components ([`8a21f19`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/8a21f19308613fdd7217691b181b3f4ed8609fe2))
- Invalidate component cache after successful creation in _create_generic ([`50b7ba3`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/50b7ba3abb5de3e51fa55f8fe2fc70c83b451fff))
- Use item.name instead of str(item) for component cache keys ([`28c3eae`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/28c3eaec4edf7ce62eca6d8031f5b48e0def8a58))
- Use _get_cached_or_fetch in update/remove_components, fix endpoint.delete call ([`86a2e30`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/86a2e30cfe0cc8466a456116e778911eaccfe174))
- Respect empty cache in _get_cached_or_fetch, fix netbox capitalization ([`04d1510`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/04d1510a0590b7ce3ade016f23ddb9de1d8d84e7))
- Correct module counter keys, alias-aware component additions, per-item updates, readme typos ([`c981780`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/c98178078ff28793501f52a2f79ba3edea437a8d))
- Changed black to ruff format ([`3883d97`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3883d979c84e492910c1cedef260118432f0dd99))
- Added --remove-components to remove components from models when yaml changed - for example conversion from interfaces to module-bays ([`69fc19a`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/69fc19a2735223f00918b586225ada45b588d4cf))
- Updated new device creation ([`07962a6`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/07962a660e3741bd622f66a00924559c802ec26e))
- Normalize trailing whitespace in change detection ([`498529b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/498529b19f4576a9a5f2e40ffccf257d61a5b399))
- Handle pynetbox record objects in change detection ([`04a1592`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/04a1592cfa5a829db112becac3b320b6b699e27c))
- Image handling ([`681d4cb`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/681d4cb12258d815969496fb9af6456db37b5025))
- Image handling ([`287bfb1`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/287bfb1db2551a7d39d6805c0eef8fef1fbca1b9))
- Reformatted ([`0bf196c`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0bf196cb8a18103a05bb657bebe7895389e4ba04))
- Defensive checks ([`db6dcb0`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/db6dcb0916ee5e07bd772e09845bf5f7108cbdea))
- Update logging ([`4d3cbf0`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/4d3cbf0ecee5972291a00db10cc7ab7240402ac9))
- Update url handling ([`9f80fdf`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/9f80fdf88519a540e4fbb86e54c74330ecfca6de))
- Image handling - closing files, simple url verification ([`92fea33`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/92fea33022635298afd7b8df564c323cfe70976e))
- Wording ([`965ad5c`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/965ad5cc6544440c1ec563e85f76fd590062a048))
- Remove old versions that dont work anymore ([`602f9d4`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/602f9d43895b0cb435f5b9eecdad792ac72ac159))
- Create poweroutlet with unambiguous powerport ([`16b922b`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/16b922b38388583be89ffa8cb0785aa02cdfc1a0))


### Build System

- **deps-dev**: Bump ruff from 0.14.9 to 0.15.1 ([`b8bc0fc`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/b8bc0fc02ce201a0fe5ef300e46202e69900773b))
- **deps**: Bump gitpython from 3.1.45 to 3.1.46 ([`b075e9d`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/b075e9df13caf936e39bbf377edc49679f59674a))
- **deps-dev**: Bump black from 25.12.0 to 26.1.0 ([`2885114`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/28851142c8dcb1a7acc24d184f6414dfb0b2f73d))
- **deps**: Bump pynetbox from 7.5.0 to 7.6.1 ([`016a4c2`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/016a4c2de1afca53c23de032a5aab4843dafaf9b))
- **deps-dev**: Bump pre-commit from 4.5.0 to 4.5.1 ([`f926447`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/f92644749f09efdb58c110386183237328c2e9f1))
- **deps**: Bump tqdm from 4.67.1 to 4.67.3 ([`0654d46`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/0654d46bae9cdfcc1f6714ccd556d2c7eeef663d))
- **deps**: Bump the uv group across 1 directory with 3 updates ([`8aa7283`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/8aa7283cd39ce8bea0dc01a9824d984c8d657a7a))
- **deps**: Bump actions/setup-python from 5 to 6 ([`7ea0b09`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/7ea0b090eb36a5333dda960294388ba42c6bbda7))
- **deps**: Bump astral-sh/setup-uv from 4 to 7 ([`3114e77`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3114e77846e65cb325a41d230b90ec3d9424557e))
- **deps**: Bump actions/stale from 5 to 10 ([`e643eb2`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/e643eb275138720aff0d7f3824ad452413eaac55))
- **deps**: Bump actions/checkout from 4 to 6 ([`2a5618f`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/2a5618fe07a2c5d0514506724591456bf1496f33))
- **deps**: Bump urllib3 from 1.25.8 to 1.26.5 ([`3c12cb5`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/3c12cb5bb0d3b0eb8577233244e89df2e719bc60))
- **deps**: Bump pyyaml from 5.3 to 5.4 ([`4c1a412`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/4c1a412a44e57adee4ebb7cfef41d43423520ee4))


### Chores

- Added dependabot.yml, updated tests.yml and removed stale.yml ([`45fd416`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/45fd416f94d6079e1e8ec9a23eac7b50cc5bda05))
- Added .envrc ([`887585c`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/887585cc7dd228c5cb42066da6ef1e5f644f471b))
- Updated python deps ([`c6c422d`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/c6c422da3f8669f1cc45a6c8a0f4b1729eb88287))
- Updated python deps ([`d54e492`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/d54e492b83fd05a1a105b3a6b80eccdef4fa3e8c))
- Updated python deps ([`5a48621`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/5a48621bfd523035fe8760f9c12401335f656cd2))
- Formatting ([`da2859c`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/da2859c451f832e26a032ec7cd92bbb1ff627dab))
- Image lowercase ([`ce8dcb7`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/ce8dcb726764cf776fd16c4577ab7b99c4654dac))
- Update test ([`ce83e66`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/ce83e667b2d5b637eb1eca85e734c09c0866ef2c))
- Update test ([`e24b985`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/e24b985d1ac6cec7d1a214d278e599748550cc2e))
- Update test workflow - debug test hang ([`9c72fa4`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/9c72fa4aa0bf94a0f7260a306a61bc6bc2ccd5f3))
- Update test workflow - debug test hang ([`82a2f17`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/82a2f17152440c51e54a67a9b9dc1dbbca383ac2))
- Update ci workflow ([`176f31f`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/176f31f3b6c0ab7406fb0aa0e3afb2d0fbb0ee70))


### Features

- Add change detection and --update flag for device types ([`89994b1`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/89994b111a5137d9510ee0c29795327efc44cd28))
- Refactored part of it, added progress and caching to speed up updates ([`fafc0ab`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/fafc0abac0337245503246831f27f1862cac3810))


### Performance Improvements

- Scope component preload by vendor, global fetch when no vendors specified ([`c6d19d8`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/c6d19d834836e08653c396a915b3bf70a50498db))
- Scope component preload to relevant device types when vendors are filtered ([`45ddfe6`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/45ddfe6d3043bc32f68ea4cac97648b04e180d3c))


### Refactoring

- Consolidate change detection, dry up netbox_api, add markdownlint ([`aa21e48`](https://github.com/marcinpsk/Device-Type-Library-Import/commit/aa21e485b330feadd9b27db6059cc863d71f8dbf))



### Contributors

@dependabot[bot], Marcin Zieba, ndom91
