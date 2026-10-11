#!/usr/bin/env bash
# Installs a packed ua-cryptography into an empty project and runs the JavaScript smoke test there, as a user's code
# imports it, then loads it with require() (needs Node.js 20.19+ and npm):
#
#   build_scripts/npm-smoke-test.sh TARBALL     (made by build_scripts/npm-package.sh)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tarball="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
consumer="$(mktemp -d)"
trap 'rm -rf "$consumer"' EXIT

cd "$consumer"
npm init --yes > /dev/null
npm install --no-audit --no-fund "$tarball" > /dev/null
# A bare specifier resolves from the importing file, so the test runs from inside the project.
cp "$root/crates/ua-cryptography-ffi/tests/js/smoke_test.mjs" .
node smoke_test.mjs
node --eval "
  const ua = require('ua-cryptography');
  if (ua.dstu7564CalculateHash(new Uint8Array(0), 256).length !== 32) throw new Error('require() gave a broken module');
  console.log('require(\"ua-cryptography\") works.');
"
