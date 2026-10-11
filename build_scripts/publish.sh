#!/usr/bin/env bash
# Builds ua-sign as one release executable for this machine (or for TARGET, a Rust target triple such as
# x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc, aarch64-apple-darwin; its standard library must be installed):
#
#   build_scripts/publish.sh [TARGET]
#
# The result is artifacts/ua-sign/TARGET/ua-sign.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"
target="${1:-$host}"
if [[ "$target" == "$host" ]]; then
  cargo build --release --manifest-path "$root/Cargo.toml" -p ua-sign
  built="$root/target/release"
else
  cargo build --release --manifest-path "$root/Cargo.toml" -p ua-sign --target "$target"
  built="$root/target/$target/release"
fi
out="$root/artifacts/ua-sign/$target"
mkdir -p "$out"
for name in ua-sign ua-sign.exe; do
  [[ -f "$built/$name" ]] && cp "$built/$name" "$out/"
done
echo "Published: $out"
