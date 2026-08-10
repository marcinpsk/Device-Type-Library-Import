#!/bin/sh
# Check that a built image actually runs. CI builds the image on every push; without
# this, a broken entrypoint or a root-owned /app/repo only shows up for users.
set -eu

IMAGE="${1:?usage: docker-smoke-test.sh <image>}"

fail() {
    echo "smoke test failed: $*" >&2
    exit 1
}

# Flags reach the importer's argument parser.
docker run --rm "$IMAGE" --help | grep -q "usage: nb-dt-import.py" || fail "--help did not reach the importer"

# Unknown flags are rejected by argparse rather than swallowed by the entrypoint.
docker run --rm "$IMAGE" --not-a-real-flag 2>&1 | grep -q "unrecognized arguments" ||
    fail "unknown flags did not reach the importer"

# No arguments still starts the importer. These are the ways a broken ENTRYPOINT shows up:
# a missing file, a lost executable bit, or a wrong interpreter.
no_args_output=$(docker run --rm "$IMAGE" 2>&1 || true)
case "$no_args_output" in
*"executable file not found"* | *"exec format error"* | *"permission denied"* | *"no such file or directory"*)
    fail "no-argument run did not start the importer: $no_args_output"
    ;;
esac

# The pre-entrypoint invocation stays supported for anyone who worked it out from the
# Dockerfile before the image was documented.
for legacy in "python -u nb-dt-import.py" "python nb-dt-import.py" "python3 -u nb-dt-import.py"; do
    # shellcheck disable=SC2086  # deliberate word splitting: $legacy is a command prefix
    docker run --rm "$IMAGE" $legacy --help | grep -q "usage: nb-dt-import.py" ||
        fail "legacy invocation '$legacy' no longer works"
done

# Arguments that are not flags run as commands, which keeps the image debuggable.
[ "$(docker run --rm "$IMAGE" sh -c 'echo passthrough-ok')" = "passthrough-ok" ] ||
    fail "command passthrough is broken"
[ "$(docker run --rm "$IMAGE" python -c 'print("python-ok")')" = "python-ok" ] ||
    fail "python command passthrough is broken"

# A volume mounted at /app/repo inherits this ownership; root here means the importer
# cannot clone into it.
[ "$(docker run --rm "$IMAGE" stat -c '%U' /app/repo)" = "appuser" ] || fail "/app/repo is not owned by appuser"
[ "$(docker run --rm "$IMAGE" id -un)" = "appuser" ] || fail "the container does not run as appuser"

echo "smoke test passed"
