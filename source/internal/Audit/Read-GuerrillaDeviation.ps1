# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Read and validate a local deviation-overlay file (guerrilla-deviations.json).
#
# A deviation file is the customer's own, source-controllable record of
# accepted exceptions to the shipped checks. It lives OUTSIDE the check universe
# so it survives module updates, and it never edits the check definitions. Shape:
#
#     {
#       "version": "1.0",
#       "deviations": [
#         {
#           "checkId": "GTRADE-004",
#           "type": "accept-risk",          // accept-risk | suppress | annotate | expect-fail
#           "justification": "6 break-glass super admins are intentional",
#           "approvedBy": "jim@contoso.com",
#           "expires": "2026-12-31",         // optional; an expired deviation stops applying
#           "scope": { "orgUnitPath": "/" }  // optional; narrows to one OU
#         }
#       ]
#     }
#
# Returns a normalized hashtable[] (empty array if the file has no deviations).
# Throws on structural problems — a malformed exception file must fail loudly,
# never be half-applied.
function Read-GuerrillaDeviation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Deviation file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw
    try {
        $cfg = $raw | ConvertFrom-Json -AsHashtable
    } catch {
        throw "Deviation file is not valid JSON ($Path): $($_.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace("$($cfg.version)")) {
        throw "Deviation file missing 'version' field ($Path). Is this a guerrilla-deviations.json file?"
    }

    $validTypes = @('accept-risk', 'suppress', 'annotate', 'expect-fail')
    $out = [System.Collections.Generic.List[hashtable]]::new()

    $i = 0
    foreach ($d in @($cfg.deviations)) {
        $i++
        if ([string]::IsNullOrWhiteSpace("$($d.checkId)")) {
            throw "Deviation #$i in $Path is missing 'checkId'."
        }
        $type = "$($d.type)".Trim().ToLowerInvariant()
        if ($type -notin $validTypes) {
            throw "Deviation for '$($d.checkId)' has unknown type '$($d.type)'. Valid types: $($validTypes -join ', ')."
        }
        # accept-risk and suppress change the score / hide a real finding, so they
        # must carry a written reason. annotate/expect-fail are lower-stakes.
        if ($type -in @('accept-risk', 'suppress') -and [string]::IsNullOrWhiteSpace("$($d.justification)")) {
            throw "Deviation for '$($d.checkId)' (type '$type') requires a non-empty 'justification'."
        }

        $expires = $null
        if (-not [string]::IsNullOrWhiteSpace("$($d.expires)")) {
            $parsed = [datetime]::MinValue
            $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
            if (-not [datetime]::TryParse("$($d.expires)", [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
                throw "Deviation for '$($d.checkId)' has an unparseable 'expires' value '$($d.expires)' (use an ISO date, e.g. 2026-12-31)."
            }
            $expires = $parsed
        }

        $ou = $null
        if ($d.scope -and -not [string]::IsNullOrWhiteSpace("$($d.scope.orgUnitPath)")) {
            $ou = "$($d.scope.orgUnitPath)"
        }

        $out.Add(@{
            CheckId       = "$($d.checkId)".Trim()
            Type          = $type
            Justification = "$($d.justification)"
            ApprovedBy    = "$($d.approvedBy)"
            Expires       = $expires
            OrgUnitPath   = $ou
        })
    }

    # Typed array contract. A single-deviation result unrolls to a scalar on
    # return (PowerShell), but every consumer either casts to [hashtable[]]
    # (Merge-GuerrillaDeviation) or wraps with @(), so 0/1/n all behave.
    return [hashtable[]]$out.ToArray()
}
