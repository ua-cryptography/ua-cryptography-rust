<#
.SYNOPSIS
Builds ua-sign as one release executable: artifacts/ua-sign/TARGET/ua-sign(.exe).

.EXAMPLE
build_scripts/publish.ps1
build_scripts/publish.ps1 -Target x86_64-pc-windows-msvc
#>
param([string] $Target)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'Cargo.toml'
$hostTarget = (& rustc -vV | Select-String '^host:\s*(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $Target) { $Target = $hostTarget }
if ($Target -eq $hostTarget) {
    & cargo build --release --manifest-path $manifest -p ua-cryptography-sign
    $built = Join-Path $root 'target/release'
} else {
    & cargo build --release --manifest-path $manifest -p ua-cryptography-sign --target $Target
    $built = Join-Path $root "target/$Target/release"
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$out = Join-Path $root "artifacts/ua-sign/$Target"
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($name in 'ua-sign.exe', 'ua-sign') {
    $file = Join-Path $built $name
    if (Test-Path $file -PathType Leaf) { Copy-Item $file $out }
}
Write-Output "Published: $out"
