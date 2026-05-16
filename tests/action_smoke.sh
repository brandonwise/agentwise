#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

export GITHUB_ACTION_PATH="$repo_root"
export RUNNER_TEMP="$tmpdir/runner temp"
mkdir -p "$RUNNER_TEMP"
export GITHUB_PATH="$tmpdir/github-path"
: > "$GITHUB_PATH"

export INPUT_INSTALL_MODE="source"
export INPUT_VERSION="latest"

bash "$repo_root/scripts/action-install.sh"

while IFS= read -r path_line; do
  if [[ -n "$path_line" ]]; then
    export PATH="$path_line:$PATH"
  fi
done < "$GITHUB_PATH"

agentwise --version >/dev/null

workspace="$tmpdir/workspace with spaces"
mkdir -p "$workspace"
cp "$repo_root/testdata/clean-mcp.json" "$workspace/clean fixture.json"

output_dir="$tmpdir/output with spaces"
mkdir -p "$output_dir"
report_path="$output_dir/report with spaces.json"

export INPUT_PATH="$workspace/clean fixture.json"
export INPUT_FORMAT="json"
export INPUT_OUTPUT="$report_path"
export INPUT_FAIL_ON="critical"
export INPUT_LIVE="false"
export INPUT_SUPPLY_CHAIN="false"

bash "$repo_root/scripts/action-scan.sh"

python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["servers_scanned"] == 1, data; assert data["score"] > 50, data' "$report_path"

echo "action smoke passed"
