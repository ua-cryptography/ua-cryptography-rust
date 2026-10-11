#!/usr/bin/env bash
# Installs a packed ua-cryptography into an empty project and runs signOnline and verifyOnline there against the test
# PKI server (crates/ua-cryptography-sign/tests/pki_server.rs): time-stamps, OCSP and caIssuers over Node.js fetch
# (needs Node.js 20.19+ and npm):
#
#   build_scripts/npm-online-test.sh TARBALL     (made by build_scripts/npm-package.sh)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tarball="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
consumer="$(mktemp -d)"
pki="$consumer/pki"
mkdir -p "$pki"

cargo test --quiet --manifest-path "$root/Cargo.toml" -p ua-cryptography-sign --test pki_server --no-run 2> /dev/null
UA_SIGN_TEST_PKI_DIRECTORY="$pki" \
  cargo test --quiet --manifest-path "$root/Cargo.toml" -p ua-cryptography-sign --test pki_server -- --ignored \
  > "$pki/server.log" 2>&1 &
server=$!
trap 'touch "$pki/stop"; wait $server 2> /dev/null || true; rm -rf "$consumer"' EXIT
for _ in $(seq 1 600); do
  [[ -f "$pki/ready" ]] && break
  sleep 0.1
done
if [[ ! -f "$pki/ready" ]]; then
  echo "The test PKI server did not start:" >&2
  cat "$pki/server.log" >&2
  exit 2
fi

cd "$consumer"
npm init --yes > /dev/null
npm install --no-audit --no-fund "$tarball" > /dev/null
# A bare specifier resolves from the importing file, so the test runs from inside the project.
cp "$root/crates/ua-cryptography-wasm/tests/js/online_test.mjs" .
UA_SIGN_TEST_PKI_DIRECTORY="$pki" node online_test.mjs
