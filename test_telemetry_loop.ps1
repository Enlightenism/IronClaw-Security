# test_telemetry_loop.ps1
# Watches ALL IronClaw install keys for changes in units_consumed / blocked_attacks
# after you run a real prompt through any installed platform.

$BaseUrl = "https://ironclaw-security.onrender.com"   # <-- change to your deployed app URL
$ApiKey = "ic_7TZWdOlVBKtOnmDwmfHbMc5n7i9HuKAHFyWtdw01M"          # <-- paste a real API key (or use an auth token)

function Get-AllInstallKeys {
    $headers = @{ "Authorization" = "Bearer $ApiKey" }
    $url = "$BaseUrl/api/dashboard/install-keys"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        return $response
    }
    catch {
        Write-Host "ERROR calling $url : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Show-KeyState {
    param($Key, [string]$Label)
    Write-Host "[$Label] key=$($Key.key_prefix) units_consumed=$($Key.units_consumed) blocked_attacks=$($Key.blocked_attacks)" -ForegroundColor Cyan
}

Write-Host "=== IronClaw Telemetry Loop Test (ALL KEYS) ===" -ForegroundColor Green

$keysBefore = Get-AllInstallKeys
if ($null -eq $keysBefore) { return }

foreach ($key in $keysBefore) {
    Show-KeyState -Key $key -Label "BEFORE"
}

Write-Host ""
Write-Host "Run a real prompt through any installed platform now, then press Enter to re-check."
Read-Host "Press Enter when ready"

$keysAfter = Get-AllInstallKeys
if ($null -eq $keysAfter) { return }

Write-Host ""
Write-Host "=== RESULT ===" -ForegroundColor Yellow
foreach ($key in $keysAfter) {
    $before = $keysBefore | Where-Object { $_.id -eq $key.id }
    if ($null -eq $before) { continue }
    $unitsDelta = $key.units_consumed - $before.units_consumed
    $blocksDelta = $key.blocked_attacks - $before.blocked_attacks
    Show-KeyState -Key $key -Label "AFTER"
    Write-Host "  -> units delta: $unitsDelta, blocks delta: $blocksDelta"
    if ($unitsDelta -gt 0 -or $blocksDelta -gt 0) {
        Write-Host "  -> SUCCESS: telemetry loop working for this key." -ForegroundColor Green
    }
    else {
        Write-Host "  -> no change for this key." -ForegroundColor Red
    }
}
