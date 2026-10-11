#!/usr/bin/env bash
# Writes the system libraries a program that links the static ua_cryptography library of TARGET needs, as rustc
# reports them (its standard library's and ring's), to FILE; the release packages carry it next to the library:
#
#   build_scripts/ffi-static-libs.sh TARGET FILE
set -euo pipefail

if [[ $# -ne 2 ]]; then
  sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
target="$1"; file="$2"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo rustc --release --locked --manifest-path "$root/Cargo.toml" -p ua-cryptography-ffi --target "$target" \
  --crate-type staticlib -- --print native-static-libs 2>&1 \
  | sed -n 's/.*native-static-libs: //p' > "$file"
if [[ ! -s "$file" ]]; then
  echo "rustc reported no native-static-libs for $target" >&2
  exit 1
fi
echo "Static link flags for $target: $(cat "$file")"
