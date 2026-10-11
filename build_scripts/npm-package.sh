#!/usr/bin/env bash
# Builds the npm package ua-cryptography (crates/ua-cryptography-wasm for browsers and Node.js) at the workspace version
# and packs it (needs wasm-pack, jq and npm):
#
#   build_scripts/npm-package.sh [OUT_DIRECTORY]     (default: artifacts/npm)
#
# OUT_DIRECTORY/ua-cryptography holds the package, OUT_DIRECTORY/ua-cryptography-VERSION.tgz is what npm publishes.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$root/crates/ua-cryptography-wasm"
out="${1:-$root/artifacts/npm}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
package="$out/ua-cryptography"
version="$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "ua-cryptography-wasm") | .version')"

rm -rf "$package" "$out/ua-cryptography-$version.tgz"
wasm-pack build "$crate" --release --target web --out-dir "$package" --out-name ua_cryptography
# wasm-pack writes its own package.json and README from Cargo.toml; the package's are in npm/.
rm -f "$package/.gitignore" "$package/package.json" "$package/README.md"
cp "$crate/npm/package.json" "$crate/npm/node.js" "$crate/npm/README.md" "$package/"
cp "$root/LICENSE" "$root/THIRD-PARTY-NOTICES.md" "$package/"
(cd "$package" && npm pkg set version="$version")
(cd "$package" && npm pack --pack-destination "$out" > /dev/null)
echo "Built: $out/ua-cryptography-$version.tgz"
