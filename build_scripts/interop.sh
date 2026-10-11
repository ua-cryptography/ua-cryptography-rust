#!/usr/bin/env bash
# Interoperability with the C# ua-sign (the reference implementation):
#   - each side creates a key store and reads the other's (info);
#   - each side signs one document in every format (cades enveloped and detached, xades, asic-s, asic-e) with both
#     hashes at level B, and both sides verify every signature (--trust the signer's certificate);
#   - levels T and LT with the synthetic hierarchy's signer, its time-stamping service and OCSP responders served by
#     the Rust test PKI server (crates/ua-cryptography-sign/tests/pki_server.rs), verified by both sides
#     (--trust its root);
#   - a tampered copy of every signature is rejected by both sides;
#   - both sides write the INI report of every signature; the differences (other than verified_at) are listed.
#
#   build_scripts/interop.sh [CSHARP_REPOSITORY]     (default: ../ua-cryptography-csharp; needs the .NET SDK)
#
# Everything is written to artifacts/interop (git-ignored): results.md (the table), ini-diff/*.diff.
# Exit code: 0 when every verdict is the expected one.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
csharp="$(cd "${1:-$root/../ua-cryptography-csharp}" && pwd)"
dir="$root/artifacts/interop"
work="$dir/work"
export UA_SIGN_PASSWORD="${UA_SIGN_PASSWORD:-interop-password}"
document_text="Interop document / Документ для перевірки сумісності"

echo "Building the Rust ua-sign (release) and publishing the C# ua-sign (framework-dependent)..."
cargo build --quiet --release --manifest-path "$root/Cargo.toml" -p ua-cryptography-sign
cargo test --quiet --manifest-path "$root/Cargo.toml" -p ua-cryptography-sign --test pki_server --no-run 2> /dev/null
dotnet publish "$csharp/src/UA.Cryptography.Cli" -c Release -o "$dir/csharp-ua-sign" -v quiet > /dev/null
rust_binary="$root/target/release/ua-sign"
csharp_binary="$dir/csharp-ua-sign/ua-sign"

# Each side through its own wrapper script, pinned to the binary just built.
rust() { UA_SIGN="$rust_binary" "$root/build_scripts/ua-sign.sh" "$@"; }
csharp() { UA_SIGN="$csharp_binary" "$csharp/scripts/ua-sign.sh" "$@"; }
side() { if [[ "$1" == rust ]]; then shift; rust "$@"; else shift; csharp "$@"; fi; }

rm -rf "$work" "$dir/ini-diff" && mkdir -p "$work" "$dir/ini-diff"
results="$dir/results.md"
{
  echo "| Signed by | Format | Hash | Level | Verified by | Copy | Expected | Exit code | |"
  echo "|---|---|---|---|---|---|---|---|---|"
} > "$results"
status=0
ini_differences=0

# record SIGNER FORMAT HASH LEVEL VERIFIER COPY EXPECTED CODE
record() {
  local mark="ok"
  if [[ "$7" != "$8" ]]; then mark="MISMATCH"; status=1; fi
  echo "| $1 | $2 | $3 | $4 | $5 | $6 | $7 | $8 | $mark |" >> "$results"
  printf '%-7s %-15s %-10s %-3s -> %-7s %-9s expected %s, got %s  %s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$mark"
}

# verify_both SIGNER FORMAT HASH LEVEL COPY EXPECTED SIGNATURE [verify options...]: both sides verify, text and INI.
verify_both() {
  local signer="$1" format="$2" hash="$3" level="$4" copy="$5" expected="$6" signature="$7"
  shift 7
  local verifier code
  for verifier in rust csharp; do
    code=0
    side "$verifier" verify --in "$signature" "$@" > "$signature.$verifier.txt" 2>&1 || code=$?
    record "$signer" "$format" "$hash" "$level" "$verifier" "$copy" "$expected" "$code"
    side "$verifier" verify --in "$signature" "$@" --format ini > "$signature.$verifier.ini" 2>&1 || true
  done
  if [[ "$copy" == original ]]; then
    local name="$signer.$level.$format.$hash"
    if ! diff <(grep -v '^verified_at=' "$signature.csharp.ini") <(grep -v '^verified_at=' "$signature.rust.ini") \
      > "$dir/ini-diff/$name.diff"; then
      ini_differences=$((ini_differences + 1))
      echo "        INI reports differ: ini-diff/$name.diff"
    else
      rm "$dir/ini-diff/$name.diff"
    fi
  fi
}

# tamper FORMAT SIGNATURE OUT_DIR: a copy with the signed document changed, inside the signature or next to it.
tamper() {
  local format="$1" signature="$2" out="$3"
  mkdir -p "$out"
  local base
  base="$(basename "$signature")"
  case "$format" in
    cades)
      python3 - "$signature" "$out/$base" "$document_text" << 'PY'
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
at = data.find(sys.argv[3].encode())
data[at] ^= 1
open(sys.argv[2], 'wb').write(data)
PY
      ;;
    cades-detached | xades)
      cp "$signature" "$out/$base"
      printf '%s (changed)\n' "$document_text" > "$out/doc.txt"
      ;;
    asic-s | asic-e)
      python3 - "$signature" "$out/$base" << 'PY'
import sys, zipfile
source = zipfile.ZipFile(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], 'w') as target:
    for info in source.infolist():
        content = source.read(info)
        if info.filename == 'doc.txt':
            content += b' (changed)'
        target.writestr(info, content)
PY
      ;;
  esac
  echo "$out/$base"
}

extension() {
  case "$1" in
    cades | cades-detached) echo p7s ;;
    xades) echo xml ;;
    asic-s) echo asics ;;
    asic-e) echo asice ;;
  esac
}

# sign_and_verify SIGNER FORMAT HASH LEVEL KEYSTORE TRUST_OPTIONS... -- SIGN_OPTIONS...
sign_and_verify() {
  local signer="$1" format="$2" hash="$3" level="$4" keystore="$5"
  shift 5
  local trust=()
  while [[ "$1" != "--" ]]; do trust+=("$1"); shift; done
  shift
  local folder="$work/$signer-$level-$format-$hash"
  mkdir -p "$folder"
  printf '%s\n' "$document_text" > "$folder/doc.txt"
  local signature="$folder/doc.txt.$(extension "$format")"
  local format_options=(--format "$format")
  [[ "$format" == cades-detached ]] && format_options=(--format cades --detached)
  if ! side "$signer" sign --keystore "$keystore" ${format_options[@]+"${format_options[@]}"} --hash "$hash" \
    --level "$level" --in "$folder/doc.txt" --out "$signature" "$@" > "$signature.sign.txt" 2>&1; then
    record "$signer" "$format" "$hash" "$level" "-" "sign" "0" "failed"
    return
  fi
  verify_both "$signer" "$format" "$hash" "$level" original 0 "$signature" "${trust[@]}"
  local tampered
  tampered="$(tamper "$format" "$signature" "$folder/tampered")"
  verify_both "$signer" "$format" "$hash" "$level" tampered 1 "$tampered" "${trust[@]}"
}

echo
echo "Key stores:"
rust keygen --keystore "$work/rust.jks" --subject "CN=Rust Interop Signer,O=UA Cryptography Interop,C=UA" \
  --cert "$work/rust.cer" > "$work/rust.keygen.txt"
csharp keygen --keystore "$work/csharp.jks" --subject "CN=CSharp Interop Signer,O=UA Cryptography Interop,C=UA" \
  --cert "$work/csharp.cer" > "$work/csharp.keygen.txt"
for pair in "rust csharp" "csharp rust"; do
  read -r reader owner <<< "$pair"
  code=0
  side "$reader" info --keystore "$work/$owner.jks" > "$work/$reader-reads-$owner.jks.txt" 2>&1 || code=$?
  mark="ok"; [[ $code -eq 0 ]] || { mark="FAILED"; status=1; }
  echo "  $reader reads the $owner JKS: exit $code $mark"
  echo "| $owner | JKS | | | $reader (info) | key store | 0 | $code | $mark |" >> "$results"
done

echo
echo "Level B, self-signed keys:"
for signer in rust csharp; do
  for hash in dstu7564 gost34311; do
    for format in cades cades-detached xades asic-s asic-e; do
      sign_and_verify "$signer" "$format" "$hash" B "$work/$signer.jks" --trust "$work/$signer.cer" --
    done
  done
done

echo
echo "Levels T and LT, the hierarchy's signer and the Rust test PKI server:"
pki="$work/pki"
mkdir -p "$pki"
UA_SIGN_TEST_PKI_DIRECTORY="$pki" UA_SIGN_TEST_PKI_PASSWORD="$UA_SIGN_PASSWORD" \
  cargo test --quiet --manifest-path "$root/Cargo.toml" -p ua-cryptography-sign --test pki_server -- --ignored \
  > "$pki/server.log" 2>&1 &
server=$!
trap 'touch "$pki/stop"; wait $server 2> /dev/null || true' EXIT
for _ in $(seq 1 600); do
  [[ -f "$pki/ready" ]] && break
  sleep 0.1
done
if [[ ! -f "$pki/ready" ]]; then
  echo "The test PKI server did not start (see $pki/server.log)"; exit 2
fi
base_url="$(cat "$pki/ready")"
for signer in rust csharp; do
  for level in T LT; do
    for format in cades xades asic-s asic-e; do
      sign_and_verify "$signer" "$format" dstu7564 "$level" "$pki/signer.jks" \
        --trust "$pki/root.cer" --certs "$pki/ca.cer" -- --tsa "$base_url/tsp" --ocsp "$base_url/ocsp"
    done
  done
done

echo
echo "Table: $results"
echo "INI reports that differ (other than verified_at): $ini_differences (artifacts/interop/ini-diff)"
exit $status
