# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Central prerequisite gate for the dispatch loop.
#
# A check definition may declare an optional `requires` block:
#
#     "requires": {
#         "collectors": ["Users"],          # AuditData.Errors[key] must be clear
#         "dataPaths":  ["Users"]           # dotted path must resolve to non-empty
#     }
#
# The dispatch loop calls this BEFORE invoking the check function. When a
# requirement is unmet the loop emits a single, consistently-worded SKIP finding
# flagged NotAssessed, instead of relying on every check to hand-roll its own
# "empty data => SKIP" guard. This is the engine-level enforcement of the rule
# that absence of evidence is never scored as compliance: a check whose evidence
# was not collected physically cannot run, so it cannot accidentally PASS.
#
# Checks without a `requires` block are unaffected (gate returns Met = $true), so
# this is a no-op for the other definitions until they are migrated.
function Test-GuerrillaPrerequisite {
    [CmdletBinding()]
    param(
        # Hashtable or PSCustomObject check definition (may carry a `requires` block).
        [Parameter(Mandatory)] $CheckDefinition,

        [Parameter(Mandatory)] [hashtable]$AuditData
    )

    $requires = $CheckDefinition.requires
    if (-not $requires) {
        return [pscustomobject]@{ Met = $true; Reason = ''; Failed = $null }
    }

    # 1) Collector health. A named collector whose key is present in AuditData.Errors
    #    failed to gather evidence, so anything downstream of it is unknown.
    foreach ($c in @($requires.collectors)) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $err = if ($AuditData.ContainsKey('Errors') -and $AuditData.Errors) { $AuditData.Errors[$c] } else { $null }
        if ($err) {
            return [pscustomobject]@{
                Met    = $false
                Failed = "collector:$c"
                Reason = "Not Assessed: the '$c' collector reported an error ($err), so this check has no evidence to evaluate. Absence of evidence is not compliance — re-run once the collector succeeds."
            }
        }
    }

    # 2) Data presence. Every declared path must resolve to a non-empty value.
    foreach ($p in @($requires.dataPaths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $val = Resolve-GuerrillaDataPath -AuditData $AuditData -Path $p
        if (Test-GuerrillaValueEmpty $val) {
            return [pscustomobject]@{
                Met    = $false
                Failed = "dataPath:$p"
                Reason = "Not Assessed: required data '$p' was not collected (missing or empty), so this check cannot run. Absence of evidence is not compliance."
            }
        }
    }

    return [pscustomobject]@{ Met = $true; Reason = ''; Failed = $null }
}

# Walk a dotted path (e.g. "M365Services.Exchange.MalwarePolicies") into the
# AuditData graph, tolerating both hashtable and PSCustomObject nodes. Returns
# $null the moment a segment is missing.
function Resolve-GuerrillaDataPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$AuditData,
        [Parameter(Mandatory)] [string]$Path
    )

    $node = $AuditData
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $node) { return $null }
        if ($node -is [System.Collections.IDictionary]) {
            if (-not $node.Contains($seg)) { return $null }
            $node = $node[$seg]
        } elseif ($node.PSObject.Properties[$seg]) {
            $node = $node.$seg
        } else {
            return $null
        }
    }
    return $node
}

# "Empty" for prerequisite purposes: $null, blank string, empty dictionary, or
# empty list. A scalar (number, bool, non-blank string) counts as present.
# Deliberately does NOT treat @($null) specially — callers pass the resolved
# node, not a splatted collection, so the @($null).Count == 1 trap never arises.
function Test-GuerrillaValueEmpty {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)] $Value)

    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) { return [string]::IsNullOrWhiteSpace($Value) }
    if ($Value -is [System.Collections.IDictionary]) { return $Value.Count -eq 0 }
    if ($Value -is [System.Collections.IList]) { return $Value.Count -eq 0 }
    return $false
}
