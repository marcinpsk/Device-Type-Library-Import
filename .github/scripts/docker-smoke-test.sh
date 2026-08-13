#!/bin/sh
# Check that a built image actually runs. CI builds the image on every push; without
# this, a broken entrypoint or a root-owned /app/repo only shows up for users.
set -eu

IMAGE="${1:?usage: docker-smoke-test.sh <image>}"

fail() {
    echo "smoke test failed: $*" >&2
    exit 1
}

# Sets $out and $status. Piping straight into grep would test only grep, so the exit
# status of the container has to be captured separately.
run_image() {
    out=$(docker run --rm "$@" 2>&1) && status=0 || status=$?
}

# Assert $out holds $1, quoting the whole output when it does not.
expect_output() {
    case "$out" in
    *"$1"*) ;;
    *) shift && fail "$*: $out" ;;
    esac
}

# Flags reach the importer's argument parser.
run_image "$IMAGE" --help
[ "$status" -eq 0 ] || fail "--help exited $status: $out"
expect_output "usage: nb-dt-import.py" "--help did not reach the importer"

# Unknown flags are rejected by argparse rather than swallowed by the entrypoint.
run_image "$IMAGE" --not-a-real-flag
[ "$status" -eq 2 ] || fail "an unknown flag exited $status, expected argparse's 2: $out"
expect_output "unrecognized arguments" "unknown flags did not reach the importer"

# No arguments still starts the importer. Assert its own missing-variable error, because
# an entrypoint that silently does nothing also produces no Docker error.
run_image "$IMAGE"
[ "$status" -eq 1 ] || fail "the no-argument run exited $status, expected the importer's 1: $out"
expect_output 'Environment variable "NETBOX_URL" is not set.' "the no-argument run did not start the importer"

# The pre-entrypoint invocation stays supported for anyone who worked it out from the
# Dockerfile before the image was documented.
for legacy in "python -u nb-dt-import.py" "python nb-dt-import.py" "python3 -u nb-dt-import.py"; do
    # shellcheck disable=SC2086  # deliberate word splitting: $legacy is a command prefix
    run_image "$IMAGE" $legacy --help
    [ "$status" -eq 0 ] || fail "legacy invocation '$legacy' exited $status: $out"
    expect_output "usage: nb-dt-import.py" "legacy invocation '$legacy' no longer works"
done

# Arguments that are not flags run as commands, which keeps the image debuggable.
run_image "$IMAGE" sh -c 'echo passthrough-ok'
[ "$status" -eq 0 ] && [ "$out" = "passthrough-ok" ] || fail "command passthrough is broken: $out"
run_image "$IMAGE" python -c 'print("python-ok")'
[ "$status" -eq 0 ] && [ "$out" = "python-ok" ] || fail "python command passthrough is broken: $out"

# A fresh named volume inherits the image directory's ownership. Root there is what stopped
# the importer cloning, so assert against a real mount rather than the image filesystem.
# The daemon generates the name, so a stale volume is never adopted and then deleted.
volume=$(docker volume create)
cleanup() { docker volume rm -f "$volume" >/dev/null 2>&1 || true; }
# EXIT alone leaks the volume when CI cancels the job, which sends TERM rather than exiting.
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' INT
trap 'trap - EXIT; cleanup; exit 129' HUP
trap 'trap - EXIT; cleanup; exit 143' TERM
mount="type=volume,source=$volume,target=/app/repo"

run_image --mount "$mount" "$IMAGE" stat -c '%U' /app/repo
[ "$status" -eq 0 ] && [ "$out" = "appuser" ] ||
    fail "a volume mounted at /app/repo is not owned by appuser: $out"
run_image --mount "$mount" "$IMAGE" sh -c 'touch /app/repo/.smoke && echo writable'
[ "$status" -eq 0 ] && [ "$out" = "writable" ] ||
    fail "appuser cannot write into a volume mounted at /app/repo: $out"
run_image "$IMAGE" id -un
[ "$status" -eq 0 ] && [ "$out" = "appuser" ] || fail "the container does not run as appuser: $out"

echo "smoke test passed"
