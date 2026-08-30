<#
.SYNOPSIS
Orchestrates a local development scan by building plugins and executing the CLI.

.DESCRIPTION
This script builds all `.vpa` plugins in the sibling `valayam-plugins` workspace, 
injects the `VALAYAM_PLUGINS_DIR` environment variable, and then runs the 
`valayam-cli` with a pure plugin-driven execution model.

.EXAMPLE
.\dev.ps1 -Target "https://example.com"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Target = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"

# Paths
$valayamPluginsDir = Resolve-Path "..\valayam-plugins"
$buildScript = Join-Path $valayamPluginsDir "package_vpa.ps1"
$distDir = Join-Path $valayamPluginsDir "dist"

Write-Host "[*] Building plugins in valayam-plugins..." -ForegroundColor Cyan
& $buildScript

if ($LASTEXITCODE -ne 0) {
    Write-Host "[✗] Plugin build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[+] Plugins built successfully into $distDir" -ForegroundColor Green

# Set environment variable so Valayam discovers the newly built plugins
$env:VALAYAM_PLUGINS_DIR = $distDir

Write-Host "[*] Starting Valayam CLI against $Target..." -ForegroundColor Cyan
cargo run --bin valayam-cli -- -u $Target
