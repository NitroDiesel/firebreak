# Build the release binary, the NSIS setup, and a portable zip.
# Intended to run on GitHub Actions (windows-latest). NSIS comes from that job.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = $env:SIMPLEWALL_VERSION
if ($version) { $version = $version -replace '^v', '' }
if (-not $version) {
    $cargo = Get-Content (Join-Path $root "Cargo.toml") -Raw
    if ($cargo -match 'version\s*=\s*"([^"]+)"') { $version = $Matches[1] } else { $version = "0.0.0" }
}

cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$payload = Join-Path $PSScriptRoot "payload"
$dist = Join-Path $root "dist"
Remove-Item $payload -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $payload, $dist | Out-Null

Copy-Item (Join-Path $root "target\release\simplewall.exe") $payload
Copy-Item (Join-Path $PSScriptRoot "simplewall.exe.manifest") $payload
Copy-Item (Join-Path $root "LICENSE") $payload
Copy-Item (Join-Path $root "README.md") $payload

$makensis = @(
    (Get-Command makensis -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
    "$env:ProgramFiles\NSIS\makensis.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $makensis) { throw "makensis.exe was not found. Install NSIS on the runner." }

& $makensis "/DVERSION=$version" (Join-Path $PSScriptRoot "simplewall.nsi")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$portable = Join-Path $dist "simplewall-$version-bin.zip"
if (Test-Path $portable) { Remove-Item $portable -Force }
Compress-Archive -Path (Join-Path $payload "*") -DestinationPath $portable
Write-Host "setup: $(Join-Path $dist "simplewall-$version-setup.exe")"
Write-Host "portable: $portable"
