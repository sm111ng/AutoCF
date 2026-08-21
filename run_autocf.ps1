$ErrorActionPreference = "Stop"

Set-Location "I:\AutoCF"

$PY = "I:\AutoCF\.venv\Scripts\python.exe"

Write-Host ""
Write-Host "============================================================"
Write-Host " AutoCF ONE-CLICK RUN"
Write-Host "============================================================"
Write-Host ""

if (!(Test-Path $PY)) {
    throw "Python not found: $PY"
}

if (!(Test-Path ".\xray.exe")) {
    throw "xray.exe not found: I:\AutoCF\xray.exe"
}

if (!(Test-Path ".\decoded_sub.txt")) {
    throw "decoded_sub.txt not found: I:\AutoCF\decoded_sub.txt"
}

Write-Host "[1/3] Network / SNI scan"
& $PY ".\scanner_v4.py"

if ($LASTEXITCODE -ne 0) {
    throw "scanner_v4.py failed"
}

Write-Host ""
Write-Host "[2/3] Real VLESS test with Xray"
& $PY ".\vless_real_test.py"

if ($LASTEXITCODE -ne 0) {
    throw "vless_real_test.py failed"
}

Write-Host ""
Write-Host "[3/3] Generate final regional subscription"
& $PY ".\finalize_results.py"

if ($LASTEXITCODE -ne 0) {
    throw "finalize_results.py failed"
}

Write-Host ""
Write-Host "============================================================"
Write-Host " DONE"
Write-Host "============================================================"
Write-Host ""

Write-Host "FINAL nodes:"
Write-Host "  I:\AutoCF\output\FINAL_nodes.txt"

Write-Host ""
Write-Host "FINAL subscription:"
Write-Host "  I:\AutoCF\output\FINAL_subscription.txt"

Write-Host ""
Write-Host "Regional files:"
Write-Host "  I:\AutoCF\output\regions\"

Write-Host ""
Write-Host "Summary:"
Write-Host "  I:\AutoCF\output\FINAL_summary.txt"

Write-Host ""
