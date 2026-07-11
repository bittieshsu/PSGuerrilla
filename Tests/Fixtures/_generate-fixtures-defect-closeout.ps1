#requires -version 7.0
<#
    Close-out fixtures proving the two ledger-flagged "defects" are resolved at 2.38.0:
      - ADMIN-001 (Test-ADMIN001): function now exists + works (was "no impl fn" at 2.35.0 airgap).
      - M365EXO-044 (Test-M365EXO044): empty-array trap gone — zero protection alerts must FAIL, not SKIP/WARN.
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-defect-closeout.ps1
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family, [string]$CheckId, [string]$Platform, [string]$Scenario, [string]$ExpectedStatus, [string]$Description, [hashtable]$AuditData)
    $obj = [ordered]@{ checkId = $CheckId; platform = $Platform; scenario = $Scenario; expectedStatus = $ExpectedStatus; description = $Description; objectShape = $false; auditData = $AuditData }
    $obj | ConvertTo-Json -Depth 16 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}

# ADMIN-001 super-admin inventory (GWS) — PASS with an active admin / FAIL with none / SKIP on error
New-Fixture GoogleWorkspace ADMIN-001 GWS clean PASS 'Active super admin present' @{ Errors = @{}; Users = @(@{ primaryEmail = 'admin@contoso.com'; isAdmin = $true; suspended = $false }, @{ primaryEmail = 'user@contoso.com'; isAdmin = $false; suspended = $false }) }
New-Fixture GoogleWorkspace ADMIN-001 GWS known-bad FAIL 'No active super admins (only a suspended one)' @{ Errors = @{}; Users = @(@{ primaryEmail = 'user@contoso.com'; isAdmin = $false; suspended = $false }, @{ primaryEmail = 'old-admin@contoso.com'; isAdmin = $true; suspended = $true }) }
New-Fixture GoogleWorkspace ADMIN-001 GWS throttled SKIP 'User inventory not collected' @{ Errors = @{ Users = 'Directory API 429' } }

# M365EXO-044 required EXO protection alerts (Entra) — trap-sensitive: zero alerts on a connected tenant must FAIL
New-Fixture Entra M365EXO-044 Entra empty FAIL 'Zero protection alert policies on a connected tenant (empty-array trap regression)' @{ Errors = @{}; M365Services = @{ Errors = @{}; Exchange = @{ ProtectionAlerts = @() } } }

Write-Host "`nDone (defect close-out fixtures)."
