# Runs ua-sign with all arguments passed through (Windows PowerShell 5.1 and PowerShell 7).
# Uses $env:UA_SIGN when set, else the release binary target/release/ua-sign(.exe) when it is built, otherwise builds
# and runs it with `cargo run --release`.
# If UA_SIGN_PASSWORD is set, the key store password is taken from it (--password-env UA_SIGN_PASSWORD).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$binary = $env:UA_SIGN
if (-not $binary) {
    $binary = @('ua-sign.exe', 'ua-sign') | ForEach-Object { Join-Path $root "target/release/$_" } |
        Where-Object { Test-Path $_ -PathType Leaf } | Select-Object -First 1
}

$arguments = @($args)
if ($env:UA_SIGN_PASSWORD -and $arguments.Count -gt 0 -and $arguments[0] -in 'keygen', 'info', 'sign' -and
    -not ($arguments | Where-Object { "$_" -like '--password*' })) {
    $arguments += @('--password-env', 'UA_SIGN_PASSWORD')
}

if ($binary) {
    & $binary @arguments
} else {
    & cargo run --quiet --release --manifest-path (Join-Path $root 'Cargo.toml') -p ua-cryptography-sign -- @arguments
}
exit $LASTEXITCODE
