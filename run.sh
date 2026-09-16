#!/bin/sh
# Serve the acl-report database for browsing at http://127.0.0.1:8000
#
# Usage: ./run.sh [DATABASE]   (default: report.db beside this script)
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
db=${1:-"$script_dir/report.db"}

if command -v python3 >/dev/null 2>&1; then
    py=python3
else
    py=python
fi

exec "$py" "$script_dir/server.py" --database "$db"
