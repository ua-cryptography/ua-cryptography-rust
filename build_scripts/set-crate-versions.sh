#!/usr/bin/env bash
# Spreads the version set by hand in [workspace.package] of Cargo.toml: names it in every crate of
# [workspace.dependencies] and brings Cargo.lock along. Commits nothing.
#
#   build_scripts/set-crate-versions.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$root/Cargo.toml"
version="$(awk -F'"' '/^\[workspace.package\]/ { inside = 1 } inside && /^version = / { print $2; exit }' \
  "$manifest")"
if [[ -z "$version" ]]; then
  echo "No version in [workspace.package] of $manifest." >&2
  exit 1
fi
if git -C "$root" rev-parse --quiet --verify "refs/tags/v$version" > /dev/null; then
  echo "Tag v$version already exists: set a new version in [workspace.package] first." >&2
  exit 1
fi

# The same lines build_scripts/check-crate-versions.sh reads: crates.io takes this version, cargo only the path.
VERSION="$version" perl -pi -e \
  's/^(ua-[a-z0-9-]+ = \{ path = "[^"]+", version = )"[^"]*"/$1"$ENV{VERSION}"/' "$manifest"
"$root/build_scripts/check-crate-versions.sh"

# Only the workspace's own entries of Cargo.lock change; third-party crates stay where they are.
cargo update --workspace --manifest-path "$manifest"
