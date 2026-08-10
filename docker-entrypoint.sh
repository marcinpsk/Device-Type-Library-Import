#!/bin/sh
set -e

# Images before this entrypoint had no ENTRYPOINT, so the only way to pass a flag was to
# repeat the whole command. Accept that form and drop the interpreter prefix.
case "$1 $2 $3" in
"python -u nb-dt-import.py" | "python3 -u nb-dt-import.py") shift 3 ;;
esac
case "$1 $2" in
"python nb-dt-import.py" | "python3 nb-dt-import.py") shift 2 ;;
esac

# Flags, or no arguments at all, run the importer. Anything else runs as given, so
# `docker run … bash` and `docker run … python -c …` still work for debugging.
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
    set -- python -u /app/nb-dt-import.py "$@"
fi

exec "$@"
