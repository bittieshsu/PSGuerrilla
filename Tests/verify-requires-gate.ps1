#requires -version 7.0
<#
.SYNOPSIS
    Proves the central prerequisite gate (Test-GuerrillaPrerequisite) drives a
    consistent Not Assessed verdict from the dispatch loop when a check's declared
    `requires` are unmet — and stays out of the way otherwise.

    Exercised at the LOOP level (Invoke-GoogleTradecraftChecks), because the gate
    lives in the dispatcher, not in the per-check Test-* functions. GTRADE-004
    declares requires{Users}, GTRADE-005 declares requires{Roles}; GTRADE-001 has
    no requires block and must be unaffected.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Import-Module (Join-Path $root 'Helpers' 'TestHelpers.psm1') -Force
Import-Guerrilla

$fail = 0
function Assert($label, $cond) {
    if ($cond) { Write-Host "  [ok] $label" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $label" -ForegroundColor Red; $script:fail++ }
}
function Get-Finding($findings, $id) { $findings | Where-Object CheckId -eq $id | Select-Object -First 1 }

Write-Host 'verify: central prerequisite gate' -ForegroundColor Cyan

# --- Case 1: required data entirely absent -> gate emits Not Assessed SKIP ---
$empty = Invoke-GoogleTradecraftChecks -AuditData @{ Errors = @{} } -OrgUnitPath '/'
$g4 = Get-Finding $empty 'GTRADE-004'
$g5 = Get-Finding $empty 'GTRADE-005'
Assert 'GTRADE-004 (no Users) => SKIP'                 ($g4.Status -eq 'SKIP')
Assert 'GTRADE-004 flagged NotAssessed by the engine'  ($g4.Details.NotAssessed -eq $true)
Assert 'GTRADE-004 reason names the missing dataPath'  ($g4.Details.UnmetRequirement -eq 'dataPath:Users')
Assert 'GTRADE-004 reason carries the absence-of-evidence wording' ($g4.CurrentValue -match 'Absence of evidence is not compliance')
Assert 'GTRADE-005 (no Roles) => SKIP'                 ($g5.Status -eq 'SKIP')
Assert 'GTRADE-005 flagged NotAssessed by the engine'  ($g5.Details.NotAssessed -eq $true)

# --- Case 2: collector reported an error -> gate emits Not Assessed SKIP ---
$errd = Invoke-GoogleTradecraftChecks -AuditData @{
    Errors = @{ Users = 'HTTP 429 throttled' }
    Users  = @(@{ primaryEmail = 'a@x.com'; isAdmin = $true })  # data present, but collector errored
} -OrgUnitPath '/'
$g4e = Get-Finding $errd 'GTRADE-004'
Assert 'GTRADE-004 (Users collector errored) => SKIP'  ($g4e.Status -eq 'SKIP')
Assert 'GTRADE-004 unmet requirement names the collector' ($g4e.Details.UnmetRequirement -eq 'collector:Users')

# --- Case 3: required data present -> gate lets the check run (real verdict) ---
$ok = Invoke-GoogleTradecraftChecks -AuditData @{
    Errors = @{}
    Users  = @(@{ primaryEmail = 'a@x.com'; isAdmin = $true; suspended = $false })
    Roles  = @(@{ roleName = 'SystemRole'; isSystemRole = $true })
} -OrgUnitPath '/'
$g4ok = Get-Finding $ok 'GTRADE-004'
$g5ok = Get-Finding $ok 'GTRADE-005'
Assert 'GTRADE-004 (1 super admin) runs => PASS'       ($g4ok.Status -eq 'PASS')
Assert 'GTRADE-004 not flagged NotAssessed when it ran' (-not $g4ok.Details.NotAssessed)
Assert 'GTRADE-005 (only system role) runs => PASS'    ($g5ok.Status -eq 'PASS')

# --- Case 4: a check WITHOUT a requires block is unaffected by the gate ---
$g1 = Get-Finding $empty 'GTRADE-001'
Assert 'GTRADE-001 (no requires) not gated to Not Assessed' (-not $g1.Details.NotAssessed)

# --- Unit-level: the helper itself ---
$none = Test-GuerrillaPrerequisite -CheckDefinition @{ id = 'X' } -AuditData @{}
Assert 'no requires block => Met'                      ($none.Met -eq $true)
$empty2 = Test-GuerrillaPrerequisite -CheckDefinition @{ id = 'X'; requires = @{ dataPaths = @('Users') } } -AuditData @{ Users = @() }
Assert 'empty array dataPath => not Met'               ($empty2.Met -eq $false)
$scalar = Test-GuerrillaPrerequisite -CheckDefinition @{ id = 'X'; requires = @{ dataPaths = @('Count') } } -AuditData @{ Count = 0 }
Assert 'scalar 0 counts as present (not empty)'        ($scalar.Met -eq $true)
$nested = Resolve-GuerrillaDataPath -AuditData @{ A = @{ B = 'v' } } -Path 'A.B'
Assert 'dotted path resolves nested value'             ($nested -eq 'v')

if ($fail -gt 0) { Write-Host "`nFAILED ($fail)" -ForegroundColor Red; exit 1 }
Write-Host "`nAll prerequisite-gate assertions passed." -ForegroundColor Green
