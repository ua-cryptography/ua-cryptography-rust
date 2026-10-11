#!/usr/bin/env bash
# Runs ua-sign with all arguments passed through.
# Uses $UA_SIGN when set, else the release binary target/release/ua-sign when it is built, otherwise builds and runs
# it with `cargo run --release`.
# If UA_SIGN_PASSWORD is set, the key store password is taken from it (--password-env UA_SIGN_PASSWORD).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${UA_SIGN:-}"
if [[ -z "$binary" && -x "$root/target/release/ua-sign" ]]; then
  binary="$root/target/release/ua-sign"
fi

args=("$@")
if [[ -n "${UA_SIGN_PASSWORD:-}" && $# -gt 0 && "$1" =~ ^(keygen|info|sign)$ ]]; then
  has_password=false
  for a in "$@"; do
    [[ "$a" == --password* ]] && has_password=true
  done
  $has_password || args+=(--password-env UA_SIGN_PASSWORD)
fi

if [[ -n "$binary" ]]; then
  exec "$binary" ${args[@]+"${args[@]}"}
else
  exec cargo run --quiet --release --manifest-path "$root/Cargo.toml" -p ua-cryptography-sign -- ${args[@]+"${args[@]}"}
fi
