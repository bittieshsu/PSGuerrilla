# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Apply a validated deviation overlay to a finding set.
#
# Deviations are expressed as flags/notes on each finding's Details, NEVER as a
# new Status value: the run-record verdict mapper refuses unknown statuses, and
# any consumer that hasn't learned about deviations must keep treating an
# accepted FAIL as a FAIL (conservative — a deviation can never manufacture a
# false PASS). Only the posture scorer opts in to reading these flags.
#
# Guardrails baked in:
#   * accept-risk / suppress apply ONLY to a real FAIL/WARN. A SKIP ("Not
#     Assessed") is never turned into an accepted or hidden finding — absence of
#     evidence can't be waived into compliance.
#   * an expired deviation does not apply; instead the finding gets a visible
#     note that its exception lapsed, so nothing silently reverts.
#   * suppressed findings stay in the set flagged Details.Suppressed — the report
#     counts them in a dedicated section rather than dropping them silently.
#
# Returns { Findings = <same objects, mutated>; Summary = <counts> }.
function Merge-GuerrillaDeviation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [PSCustomObject[]]$Findings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [hashtable[]]$Deviations,
        [datetime]$ReferenceTime = [datetime]::UtcNow
    )

    $summary = [ordered]@{
        Accepted            = 0
        Suppressed          = 0
        Annotated           = 0
        ExpectFailSatisfied = 0
        ExpectFailDrifted   = 0
        Expired             = 0
        Unmatched           = 0
    }

    if (-not $Deviations -or $Deviations.Count -eq 0) {
        return [pscustomobject]@{ Findings = @($Findings); Summary = [pscustomobject]$summary }
    }

    # Index deviations by checkId (case-insensitive), preserving order.
    $byCheck = @{}
    foreach ($d in $Deviations) {
        $k = $d.CheckId.ToUpperInvariant()
        if (-not $byCheck.ContainsKey($k)) { $byCheck[$k] = [System.Collections.Generic.List[hashtable]]::new() }
        $byCheck[$k].Add($d)
    }
    $matched = [System.Collections.Generic.HashSet[object]]::new()

    foreach ($f in $Findings) {
        $k = "$($f.CheckId)".ToUpperInvariant()
        if (-not $byCheck.ContainsKey($k)) { continue }

        foreach ($d in $byCheck[$k]) {
            # Scope narrowing: if the deviation names an OU, only apply to that OU.
            if ($d.OrgUnitPath -and "$($f.OrgUnitPath)" -ne $d.OrgUnitPath) { continue }
            [void]$matched.Add($d)

            if ($d.Expires -and $ReferenceTime -gt $d.Expires) {
                $summary.Expired++
                Add-GuerrillaDeviationNote -Finding $f -Note ("A '$($d.Type)' deviation for this finding EXPIRED on {0} and no longer applies. Re-review or renew it." -f $d.Expires.ToString('yyyy-MM-dd'))
                continue
            }

            switch ($d.Type) {
                'annotate' {
                    Add-GuerrillaDeviationNote -Finding $f -Note $d.Justification
                    $summary.Annotated++
                }
                'suppress' {
                    if ($f.Status -in @('FAIL', 'WARN')) {
                        Set-GuerrillaDeviationFlag -Finding $f -Flag 'Suppressed' -Deviation $d
                        $summary.Suppressed++
                    }
                }
                'accept-risk' {
                    if ($f.Status -in @('FAIL', 'WARN')) {
                        Set-GuerrillaDeviationFlag -Finding $f -Flag 'Accepted' -Deviation $d
                        $summary.Accepted++
                    }
                }
                'expect-fail' {
                    if ($f.Status -eq 'FAIL') {
                        Set-GuerrillaDeviationFlag -Finding $f -Flag 'Accepted' -Deviation $d
                        Add-GuerrillaDeviationNote -Finding $f -Note "Expected-fail: this is a known, accepted failure. $($d.Justification)"
                        $summary.ExpectFailSatisfied++
                    } elseif ($f.Status -eq 'PASS') {
                        Add-GuerrillaDeviationNote -Finding $f -Note "CONFIG DRIFT: an 'expect-fail' deviation is registered for this check but it now PASSes. The underlying condition changed — confirm the deviation is still needed."
                        $summary.ExpectFailDrifted++
                    }
                }
            }
        }
    }

    $summary.Unmatched = @($Deviations | Where-Object { -not $matched.Contains($_) }).Count
    return [pscustomobject]@{ Findings = @($Findings); Summary = [pscustomobject]$summary }
}

# True when a finding has been waived out of the posture math (accepted or
# suppressed). The scorer uses this; everything else keeps seeing the raw Status.
function Test-GuerrillaDeviated {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Finding)
    $det = $Finding.Details
    if ($det -isnot [System.Collections.IDictionary]) { return $false }
    return [bool]($det['Suppressed'] -or $det['Accepted'])
}

function Set-GuerrillaDeviationFlag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)] [string]$Flag,
        [Parameter(Mandatory)] [hashtable]$Deviation
    )
    if ($Finding.Details -isnot [System.Collections.IDictionary]) {
        $Finding | Add-Member -NotePropertyName Details -NotePropertyValue @{} -Force
    }
    $Finding.Details[$Flag] = $true
    $Finding.Details['Deviation'] = @{
        Type           = $Deviation.Type
        Justification  = $Deviation.Justification
        ApprovedBy     = $Deviation.ApprovedBy
        Expires        = if ($Deviation.Expires) { $Deviation.Expires.ToString('yyyy-MM-dd') } else { $null }
        OriginalStatus = $Finding.Status
    }
}

function Add-GuerrillaDeviationNote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)] [string]$Note
    )
    if ($Finding.Details -isnot [System.Collections.IDictionary]) {
        $Finding | Add-Member -NotePropertyName Details -NotePropertyValue @{} -Force
    }
    $existing = $Finding.Details['DeviationNote']
    $Finding.Details['DeviationNote'] = if ($existing) { "$existing`n$Note" } else { $Note }
}
