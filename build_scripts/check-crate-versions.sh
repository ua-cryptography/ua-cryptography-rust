#!/usr/bin/env bash
# Checks that every crate of the workspace in [workspace.dependencies] names the workspace version: crates.io reads
# that version, cargo only the path, so a forgotten bump builds here and publishes against the previous release.
#
#   build_scripts/check-crate-versions.sh
set -euo pipefail

manifest="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/Cargo.toml"
workspace_version="$(awk -F'"' '/^\[workspace.package\]/ { inside = 1 } inside && /^version = / { print $2; exit }' \
  "$manifest")"
stale_dependencies="$(grep -E '^ua-[a-z0-9-]+ = \{ path = ' "$manifest" \
  | grep -v "version = \"$workspace_version\"" || true)"
if [[ -n "$stale_dependencies" ]]; then
  echo "Workspace version $workspace_version, but these dependencies name another one:" >&2
  echo "$stale_dependencies" >&2
  exit 1
fi
echo "Every crate of the workspace is named at version $workspace_version."
