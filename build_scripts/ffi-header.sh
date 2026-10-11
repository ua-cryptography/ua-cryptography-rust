#!/usr/bin/env bash
# Regenerates the C header of the ua_cryptography library from crates/ua-cryptography-ffi
# (needs `cargo install cbindgen`):
#
#   build_scripts/ffi-header.sh           # writes crates/ua-cryptography-ffi/include/ua_cryptography.h
#   build_scripts/ffi-header.sh --check   # fails when the committed header is out of date
#
# --quiet: cbindgen warns about every private constant it skips, which is intended.
set -euo pipefail

crate="$(cd "$(dirname "${BASH_SOURCE[0]}")/../crates/ua-cryptography-ffi" && pwd)"
header="$crate/include/ua_cryptography.h"
if [[ "${1:-}" == "--check" ]]; then
  fresh="$(mktemp)"
  trap 'rm -f "$fresh"' EXIT
  (cd "$crate" && cbindgen --quiet --config cbindgen.toml --output "$fresh")
  if ! diff -u "$header" "$fresh"; then
    echo "The header is out of date: run build_scripts/ffi-header.sh" >&2
    exit 1
  fi
  echo "The header is current."
else
  (cd "$crate" && cbindgen --quiet --config cbindgen.toml --output "$header")
  echo "Written: $header"
fi
