Write-Host "1. Building CORS plugin to WASM..." -ForegroundColor Cyan
cargo build --manifest-path plugins-wasm/cors-audit/Cargo.toml --target wasm32-unknown-unknown
if ($LASTEXITCODE -ne 0) { throw "Plugin build failed" }

Write-Host "2. Copying plugin to plugins-wasm directory (where CLI orchestrator looks)..." -ForegroundColor Cyan
Copy-Item target\wasm32-unknown-unknown\debug\cors_audit.wasm plugins-wasm\ -Force

Write-Host "3. Building CLI Orchestrator..." -ForegroundColor Cyan
cargo build --bin valayam-cli
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

Write-Host "4. Creating mock scan template..." -ForegroundColor Cyan
$template = @"
id: cors_audit_demo
info:
  name: "CORS Audit Test"
  severity: "Medium"
  description: "E2E Test for CORS plugin"
requests: []
"@
if (-not (Test-Path templates_repo)) { New-Item -ItemType Directory -Force -Path templates_repo }
Set-Content -Path "templates_repo\cors.yaml" -Value $template

Write-Host "5. Starting dummy python server on port 8111..." -ForegroundColor Cyan
$server = Start-Process python -ArgumentList "scripts\dummy_cors_server.py" -PassThru
Start-Sleep -Seconds 2

Write-Host "6. Running CLI Scan..." -ForegroundColor Cyan
$output = target\debug\valayam-cli.exe -t templates_repo\cors.yaml -u http://127.0.0.1:8111 2>&1

Write-Host "`n--- CLI OUTPUT ---"
Write-Host $output
Write-Host "------------------`n"

if ($output -match "Insecure CORS Policy detected") {
    Write-Host "[+] E2E Test Passed! The Extism WASM plugin successfully executed and found the vulnerability." -ForegroundColor Green
} else {
    Write-Host "[-] E2E Test Failed! The vulnerability was not found in the output." -ForegroundColor Red
}

Write-Host "7. Cleaning up dummy server..." -ForegroundColor Cyan
Stop-Process -Id $server.Id -Force
