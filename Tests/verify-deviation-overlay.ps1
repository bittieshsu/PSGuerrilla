#requires -version 7.0
<#
.SYNOPSIS
    Proves the deviation overlay: Read-GuerrillaDeviation validation, the four
    deviation types, the safety guardrails (never waive a SKIP, expired stops
    applying, nothing silently dropped), and that accepted/suppressed findings
    leave the posture math while raw findings still score identically.
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
function Throws([scriptblock]$sb) { try { & $sb; return $false } catch { return $true } }

function New-F($id, $status, $severity = 'High', $ou = '/') {
    New-AuditFinding -CheckDefinition @{ id = $id; name = $id; severity = $severity; description = 'd'; recommendedValue = 'r' } `
        -Status $status -CurrentValue "cv-$id" -OrgUnitPath $ou
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("guerrilla-dev-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
function Write-Dev($name, $obj) { $p = Join-Path $tmp $name; ($obj | ConvertTo-Json -Depth 8) | Set-Content -Path $p -Encoding UTF8; $p }

Write-Host 'verify: deviation overlay' -ForegroundColor Cyan

# --------------------------------------------------------------------------
Write-Host ' Read-GuerrillaDeviation validation' -ForegroundColor DarkCyan
$good = Write-Dev 'good.json' @{
    version = '1.0'
    deviations = @(
        @{ checkId = 'GTRADE-004'; type = 'accept-risk'; justification = 'BTG admins intentional'; approvedBy = 'jim'; expires = '2999-01-01' }
    )
}
$parsed = @(Read-GuerrillaDeviation -Path $good)
Assert 'valid file parses to 1 deviation'          ($parsed.Count -eq 1)
Assert 'expires parsed to datetime'                ($parsed[0].Expires -is [datetime])
Assert 'type normalized to lower-case'             ($parsed[0].Type -eq 'accept-risk')

Assert 'missing file throws'          (Throws { Read-GuerrillaDeviation -Path (Join-Path $tmp 'nope.json') })
$noVer = Write-Dev 'nover.json' @{ deviations = @(@{ checkId = 'X'; type = 'annotate' }) }
Assert 'missing version throws'       (Throws { Read-GuerrillaDeviation -Path $noVer })
$badType = Write-Dev 'badtype.json' @{ version = '1.0'; deviations = @(@{ checkId = 'X'; type = 'ignore-forever' }) }
Assert 'unknown type throws'          (Throws { Read-GuerrillaDeviation -Path $badType })
$noJust = Write-Dev 'nojust.json' @{ version = '1.0'; deviations = @(@{ checkId = 'X'; type = 'accept-risk' }) }
Assert 'accept-risk w/o justification throws' (Throws { Read-GuerrillaDeviation -Path $noJust })
$badExp = Write-Dev 'badexp.json' @{ version = '1.0'; deviations = @(@{ checkId = 'X'; type = 'annotate'; expires = 'someday' }) }
Assert 'unparseable expires throws'   (Throws { Read-GuerrillaDeviation -Path $badExp })
$empty = Write-Dev 'empty.json' @{ version = '1.0'; deviations = @() }
Assert 'empty deviations => empty array' (@(Read-GuerrillaDeviation -Path $empty).Count -eq 0)

# --------------------------------------------------------------------------
Write-Host ' Merge-GuerrillaDeviation behaviors + guardrails' -ForegroundColor DarkCyan
$dev = @(
    @{ CheckId='A'; Type='accept-risk'; Justification='ok'; ApprovedBy='jim'; Expires=$null; OrgUnitPath=$null }
    @{ CheckId='B'; Type='suppress';    Justification='ok'; ApprovedBy='jim'; Expires=$null; OrgUnitPath=$null }
    @{ CheckId='C'; Type='annotate';    Justification='note text'; ApprovedBy=''; Expires=$null; OrgUnitPath=$null }
    @{ CheckId='D'; Type='accept-risk'; Justification='ok'; ApprovedBy='jim'; Expires=$null; OrgUnitPath=$null }  # target is SKIP
    @{ CheckId='Z'; Type='accept-risk'; Justification='ok'; ApprovedBy='jim'; Expires=$null; OrgUnitPath=$null }  # unmatched
)
$findings = @( (New-F 'A' 'FAIL'), (New-F 'B' 'WARN'), (New-F 'C' 'PASS'), (New-F 'D' 'SKIP') )
$res = Merge-GuerrillaDeviation -Findings $findings -Deviations $dev
$fa = $res.Findings | Where-Object CheckId -eq 'A'
$fb = $res.Findings | Where-Object CheckId -eq 'B'
$fc = $res.Findings | Where-Object CheckId -eq 'C'
$fd = $res.Findings | Where-Object CheckId -eq 'D'
Assert 'accept-risk flags Details.Accepted'        ($fa.Details.Accepted -eq $true)
Assert 'accept-risk leaves Status = FAIL (no false PASS)' ($fa.Status -eq 'FAIL')
Assert 'accept-risk records OriginalStatus + approver'    ($fa.Details.Deviation.OriginalStatus -eq 'FAIL' -and $fa.Details.Deviation.ApprovedBy -eq 'jim')
Assert 'suppress flags Details.Suppressed'         ($fb.Details.Suppressed -eq $true)
Assert 'annotate adds note, no accept/suppress flag' ($fc.Details.DeviationNote -eq 'note text' -and -not $fc.Details.Accepted -and -not $fc.Details.Suppressed)
Assert 'GUARDRAIL: accept-risk on a SKIP is ignored'  (-not $fd.Details.Accepted)
Assert 'summary counts accepted=1 suppressed=1 annotated=1' ($res.Summary.Accepted -eq 1 -and $res.Summary.Suppressed -eq 1 -and $res.Summary.Annotated -eq 1)
Assert 'summary counts the unmatched deviation'    ($res.Summary.Unmatched -eq 1)

# expect-fail: satisfied vs drift
$ef = @( @{ CheckId='E'; Type='expect-fail'; Justification='known bad'; ApprovedBy=''; Expires=$null; OrgUnitPath=$null } )
$efSat = Merge-GuerrillaDeviation -Findings @((New-F 'E' 'FAIL')) -Deviations $ef
Assert 'expect-fail on FAIL => accepted + satisfied' (($efSat.Findings[0].Details.Accepted -eq $true) -and $efSat.Summary.ExpectFailSatisfied -eq 1)
$efDrift = Merge-GuerrillaDeviation -Findings @((New-F 'E' 'PASS')) -Deviations $ef
Assert 'expect-fail on PASS => drift note, not accepted' (($efDrift.Summary.ExpectFailDrifted -eq 1) -and -not $efDrift.Findings[0].Details.Accepted -and ($efDrift.Findings[0].Details.DeviationNote -match 'DRIFT'))

# expiry: an expired accept-risk does not apply, but leaves a visible note
$expDev = @( @{ CheckId='F'; Type='accept-risk'; Justification='was ok'; ApprovedBy='jim'; Expires=([datetime]'2020-01-01'); OrgUnitPath=$null } )
$expRes = Merge-GuerrillaDeviation -Findings @((New-F 'F' 'FAIL')) -Deviations $expDev -ReferenceTime ([datetime]'2026-07-30')
Assert 'GUARDRAIL: expired deviation does NOT accept'  (-not $expRes.Findings[0].Details.Accepted)
Assert 'expired deviation leaves a visible note'       ($expRes.Findings[0].Details.DeviationNote -match 'EXPIRED')
Assert 'summary counts the expired deviation'          ($expRes.Summary.Expired -eq 1)

# scope: OU narrowing
$ouDev = @( @{ CheckId='G'; Type='accept-risk'; Justification='ok'; ApprovedBy='jim'; Expires=$null; OrgUnitPath='/Students' } )
$ouRes = Merge-GuerrillaDeviation -Findings @((New-F 'G' 'FAIL' 'High' '/'), (New-F 'G' 'FAIL' 'High' '/Students')) -Deviations $ouDev
$gRoot = $ouRes.Findings | Where-Object { $_.CheckId -eq 'G' -and $_.OrgUnitPath -eq '/' }
$gStu  = $ouRes.Findings | Where-Object { $_.CheckId -eq 'G' -and $_.OrgUnitPath -eq '/Students' }
Assert 'scope: root OU finding NOT accepted'   (-not $gRoot.Details.Accepted)
Assert 'scope: /Students finding accepted'     ($gStu.Details.Accepted -eq $true)

# no-deviations short-circuit
$none = Merge-GuerrillaDeviation -Findings @((New-F 'A' 'FAIL')) -Deviations @()
Assert 'empty deviation set => findings unchanged' (-not $none.Findings[0].Details.Accepted)

# --------------------------------------------------------------------------
Write-Host ' Scoring impact' -ForegroundColor DarkCyan
$rawFindings = @(
    [pscustomobject]@{ CheckId='S1'; Category='Cat'; Severity='High'; Status='FAIL'; Details=@{} }
    [pscustomobject]@{ CheckId='S2'; Category='Cat'; Severity='High'; Status='PASS'; Details=@{} }
)
$rawScore = (Get-AuditPostureScore -Findings $rawFindings).OverallScore
# Same set, but the FAIL is accepted -> should score strictly higher (waived).
$accFindings = @(
    [pscustomobject]@{ CheckId='S1'; Category='Cat'; Severity='High'; Status='FAIL'; Details=@{ Accepted = $true } }
    [pscustomobject]@{ CheckId='S2'; Category='Cat'; Severity='High'; Status='PASS'; Details=@{} }
)
$accScore = (Get-AuditPostureScore -Findings $accFindings).OverallScore
Assert "accepted FAIL raises posture ($rawScore -> $accScore)" ($accScore -gt $rawScore)
Assert 'Test-GuerrillaDeviated true for accepted'  (Test-GuerrillaDeviated $accFindings[0])
Assert 'Test-GuerrillaDeviated false for plain'    (-not (Test-GuerrillaDeviated $rawFindings[1]))

Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue

if ($fail -gt 0) { Write-Host "`nFAILED ($fail)" -ForegroundColor Red; exit 1 }
Write-Host "`nAll deviation-overlay assertions passed." -ForegroundColor Green
