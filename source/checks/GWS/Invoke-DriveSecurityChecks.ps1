# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-DriveSecurityChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'DriveSecurityChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_" -OrgUnitPath $OrgUnitPath))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented' -OrgUnitPath $OrgUnitPath))
        }
    }

    return @($findings)
}

# ── DRIVE-001: External Sharing Defaults ──────────────────────────────────
function Test-DRIVE001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Drive sharing settings are OU-level policies not fully exposed via Directory API
    # Check if OrgUnitPolicies contain Drive sharing configuration
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('OrgUnits', 'CloudIdentityPolicies') -Subject 'Drive external-sharing policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveExternalSharing) {
        $status = switch ($policy.driveExternalSharing) {
            'OFF'                { 'PASS' }
            'ALLOWLISTED_DOMAINS' { 'PASS' }
            'ON_WITH_WARNING'    { 'WARN' }
            'ON'                 { 'FAIL' }
            default              { 'WARN' }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "External sharing policy: $($policy.driveExternalSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    # GWS-1: drive_and_docs.external_sharing { externalSharingMode=enum }. Grade WEAKEST-OU-WINS.
    # 'ALLOWED' is unrestricted external sharing (insecure) -> FAIL; restrictive values are better.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.external_sharing' -Field 'externalSharingMode')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No drive_and_docs.external_sharing policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $note = "External sharing mode: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    # Known-insecure: unrestricted external sharing.
    $insecure = @($vals | Where-Object { "$_" -match '(?i)^ALLOWED$' })
    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Unrestricted external sharing permitted — $note" -OrgUnitPath $OrgUnitPath
    }
    # Known-restrictive values pass; anything unrecognized -> WARN (never PASS on unknown enum).
    $known = @($vals | Where-Object { "$_" -match '(?i)^(DISALLOWED|ALLOWED_WITH_WARNING|ALLOWLISTED_DOMAINS)$' })
    if ($known.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "External sharing restricted — $note" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Unrecognized external sharing mode — verify intent — $note" -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-002: Link Sharing Default Settings ─────────────────────────────
function Test-DRIVE002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Drive link-sharing policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.defaultLinkSharing) {
        $status = if ($policy.defaultLinkSharing -eq 'RESTRICTED') { 'PASS' }
                  elseif ($policy.defaultLinkSharing -eq 'DOMAIN') { 'WARN' }
                  else { 'FAIL' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Default link sharing: $($policy.defaultLinkSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Default link sharing setting not available via API. Verify in Admin Console that default is set to Restricted (specific people)' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'OU-level Drive link sharing defaults require manual verification in Admin Console' }
}

# ── DRIVE-003: Anyone With the Link Sharing Audit ────────────────────────
function Test-DRIVE003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Drive anyone-with-link policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.anyoneWithLinkEnabled) {
        $status = if ($policy.anyoneWithLinkEnabled -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.anyoneWithLinkEnabled) {
            "'Anyone with the link' sharing is enabled - files can be exposed to the internet"
        } else {
            "'Anyone with the link' sharing is disabled"
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Verify in Admin Console that 'Anyone with the link' sharing is disabled or restricted to 'Domain users with the link'" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'This setting controls whether users can create public links accessible by anyone on the internet' }
}

# ── DRIVE-004: Shared Drive Creation Restrictions ────────────────────────
function Test-DRIVE004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: drive_and_docs.shared_drive_creation { allowSharedDriveCreation=bool }.
    # Insecure (weaker) when shared-drive creation is unrestricted anywhere. Weakest-OU-wins.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.shared_drive_creation' -Field 'allowSharedDriveCreation')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No drive_and_docs.shared_drive_creation policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $allowed = @($vals | Where-Object { $_ -eq $true })
    if ($allowed.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Shared Drive creation unrestricted in $($allowed.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Shared Drive creation restricted' -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-005: Shared Drive Member Management ────────────────────────────
function Test-DRIVE005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Shared Drive member management settings not available via API. Verify in Admin Console that only managers can add members and change access levels' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Shared Drive member management policies are OU-level settings requiring manual verification' }
}

# ── DRIVE-006: Shared Drive External Sharing ─────────────────────────────
function Test-DRIVE006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Shared Drive external-sharing policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.sharedDriveExternalSharing) {
        $status = if ($policy.sharedDriveExternalSharing -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.sharedDriveExternalSharing) {
            'External sharing on Shared Drives is enabled'
        } else {
            'External sharing on Shared Drives is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Shared Drive external sharing settings not available via API. Verify in Admin Console > Apps > Drive > Sharing settings > Shared drive sharing' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Shared Drive external sharing is an OU-level policy requiring manual verification' }
}

# ── DRIVE-007: File Ownership Transfer Settings ──────────────────────────
function Test-DRIVE007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'File ownership transfer settings not available via API. Verify in Admin Console that ownership transfer is restricted appropriately' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Ownership transfer policies are OU-level settings requiring manual verification' }
}

# ── DRIVE-008: Drive for Desktop Allowed/Blocked ─────────────────────────
function Test-DRIVE008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('OrgUnits', 'CloudIdentityPolicies') -Subject 'Drive for Desktop policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveForDesktopEnabled) {
        $status = if ($policy.driveForDesktopEnabled -eq $false) { 'PASS' }
                  else { 'WARN' }
        $currentValue = if ($policy.driveForDesktopEnabled) {
            'Drive for Desktop is enabled - files may be synced to local devices'
        } else {
            'Drive for Desktop is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    # GWS-1: drive_and_docs.drive_for_desktop { allowDriveForDesktop=bool; restrictToAuthorizedDevices=bool }.
    # Enabled allows local file sync; weaker when unrestricted to authorized devices. Weakest-OU-wins.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $allowVals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.drive_for_desktop' -Field 'allowDriveForDesktop')
    if ($allowVals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No drive_and_docs.drive_for_desktop policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $restrictVals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.drive_for_desktop' -Field 'restrictToAuthorizedDevices')
    $enabled = @($allowVals | Where-Object { $_ -eq $true })
    if ($enabled.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Drive for Desktop is disabled' -OrgUnitPath $OrgUnitPath
    }
    # Enabled somewhere. If every targeted policy restricts to authorized devices, that's the safer posture.
    $restrictedAll = ($restrictVals.Count -gt 0 -and @($restrictVals | Where-Object { $_ -ne $true }).Count -eq 0)
    if ($restrictedAll) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Drive for Desktop enabled but restricted to authorized devices ($($enabled.Count) of $($allowVals.Count) targeted policies)" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Drive for Desktop enabled without authorized-device restriction in $($enabled.Count) of $($allowVals.Count) targeted policy/policies — files may sync to unmanaged devices" `
        -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-009: Third-Party App Drive Access ──────────────────────────────
function Test-DRIVE009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OAuthApps' -Subject 'OAuth app inventory'
    if ($na) { return $na }

    # Check OAuthApps for apps with Drive scopes
    if ($AuditData.OAuthApps) {
        $driveScopes = @('drive', 'drive.file', 'drive.readonly', 'drive.metadata')
        $driveApps = [System.Collections.Generic.List[string]]::new()

        foreach ($event in $AuditData.OAuthApps) {
            $appName = $event.Params.app_name
            $scope = $event.Params.scope
            if ($scope) {
                foreach ($ds in $driveScopes) {
                    if ($scope -match $ds) {
                        if ($appName -and -not $driveApps.Contains($appName)) {
                            $driveApps.Add($appName)
                        }
                        break
                    }
                }
            }
        }

        if ($driveApps.Count -gt 0) {
            $status = if ($driveApps.Count -gt 10) { 'FAIL' }
                      elseif ($driveApps.Count -gt 5) { 'WARN' }
                      else { 'PASS' }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
                -CurrentValue "$($driveApps.Count) third-party app(s) have Drive access" `
                -OrgUnitPath $OrgUnitPath `
                -Details @{ AppsWithDriveAccess = @($driveApps) }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No third-party apps with Drive access detected' `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'OAuth app data not available. Verify third-party app Drive access in Admin Console > Security > API controls' `
        -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-010: Drive DLP Rules Audit ─────────────────────────────────────
function Test-DRIVE010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: rule.dlp value objects { state=enum(ACTIVE/INACTIVE), action={ gmailAction|driveAction|alertCenterAction } }.
    # PASS if >= 1 ACTIVE rule whose action object is Drive-scoped (has a driveAction); WARN if none.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'rule.dlp')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No rule.dlp policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    # Count ACTIVE rules whose action object is Drive-scoped (anchored state match; action must have a driveAction).
    $activeDrive = @($vals | Where-Object {
        ($_.state -eq 'ACTIVE') -and
        $_.action -and
        ($_.action.PSObject.Properties.Name -contains 'driveAction')
    })
    if ($activeDrive.Count -ge 1) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "$($activeDrive.Count) active Drive DLP rule(s) configured (of $($vals.Count) DLP rule(s))" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "No active Drive-scoped DLP rule found ($($vals.Count) DLP rule(s) present). Configure a Drive DLP rule in Admin Console > Security > Data protection > Manage rules" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'DLP rules should cover sensitive data types including PII, financial data, and health records' }
}

# ── DRIVE-011: Target Audience Settings ──────────────────────────────────
function Test-DRIVE011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Target audience settings not available via API. Verify in Admin Console > Directory > Target audiences that sharing suggestions are properly scoped' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Target audiences control suggested recipients when sharing files and should be configured to prevent accidental broad sharing' }
}

# ── DRIVE-012: Drive Add-ons Settings ────────────────────────────────────
function Test-DRIVE012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Drive add-ons settings not available via API. Verify in Admin Console > Apps > Drive > Add-ons that installation is restricted to approved add-ons' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Uncontrolled Drive add-ons can access file content and metadata' }
}

# ── DRIVE-013: Offline Access Settings ───────────────────────────────────
function Test-DRIVE013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Drive offline-access policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveOfflineEnabled) {
        $status = if ($policy.driveOfflineEnabled -eq $false) { 'PASS' }
                  else { 'WARN' }
        $currentValue = if ($policy.driveOfflineEnabled) {
            'Offline access is enabled - files may be cached on local devices'
        } else {
            'Offline access is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Offline access setting not available via API. Verify in Admin Console > Apps > Drive > Features and Applications > Offline that offline access is controlled' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Offline access caches files locally and should be disabled on shared or unmanaged devices' }
}

# ── DRIVE-014: GWS.DRIVEDOCS.4.1 — Drive SDK API access disabled ───────────
function Test-DRIVE014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.drive_sdk' -Field 'enableDriveSdkApiAccess' -SecureValue $false -Status 'FAIL' `
        -BadMsg 'Drive SDK API access is enabled (third-party API read/write to Drive)' -GoodMsg 'Drive SDK API access is disabled'
}

# ── DRIVE-015: GWS.DRIVEDOCS.1.9 — External-file sharing warning enabled ───
function Test-DRIVE015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.external_file_warning' -Field 'highlightingEnabled' -SecureValue $true -Status 'WARN' `
        -BadMsg 'External-file sharing warning is off' -GoodMsg 'External-file sharing warning is on'
}

# ── DRIVE-016: GWS.DRIVEDOCS.3.1 — File security update enforced ───────────
function Test-DRIVE016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.file_security_update' -Field 'allowUsersToManageUpdate' -SecureValue $false -Status 'WARN' `
        -BadMsg 'Users are allowed to remove the file security update' -GoodMsg 'Users cannot remove the file security update'
}

# ── DRIVE-017: Default file access set to private to owner (GWS.DRIVEDOCS.1.8) ──
function Test-DRIVE017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyEnum -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.general_access_default' -Field 'defaultFileAccess' -CompliantValues @('PRIVATE_TO_OWNER') -Status 'FAIL' `
        -BadMsg 'Default file access is not private to owner' -GoodMsg 'Default file access is private to owner'
}

# ── DRIVE-018: Shared Drive External-Sharing Exposure ─────────────────────
# Enumerates every shared drive (collected via domain-admin access in
# Get-GWSAuditData) and flags drives whose restrictions permit sharing outside
# the organization. domainUsersOnly = true means access is confined to org
# members; false or absent means items can be shared externally (and, with the
# domain sharing setting on, made publicly accessible). Confirming an actual
# public file link would need a per-file permission scan, which this does not do.
function Test-DRIVE018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'SharedDrives' -Subject 'shared drives'
    if ($na) { return $na }

    $drives = @($AuditData.SharedDrives | Where-Object { $null -ne $_ })
    if ($drives.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No shared drives were returned by the domain-admin enumeration; there is no shared-drive external-sharing exposure to report.' `
            -OrgUnitPath $OrgUnitPath -Details @{ DriveCount = 0 }
    }

    # domainUsersOnly enforced (true) = confined to the org. Missing or false =
    # external sharing permitted; an unrecognized value is never assumed safe.
    $exposed = foreach ($d in $drives) {
        $r = $d.restrictions
        $domainOnly = if ($r -and $null -ne $r.domainUsersOnly) { [bool]$r.domainUsersOnly } else { $false }
        if (-not $domainOnly) {
            [pscustomobject]@{
                Name  = if ("$($d.name)") { "$($d.name)" } else { "(unnamed)" }
                Id    = "$($d.id)"
                Label = "$(if ("$($d.name)") { "$($d.name)" } else { "(unnamed)" }) (id $($d.id))"
            }
        }
    }
    $exposed = @($exposed)

    if ($exposed.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue ("All $($drives.Count) shared drive(s) restrict access to organization members " +
                '(domainUsersOnly enforced); none permits sharing outside the organization.') `
            -OrgUnitPath $OrgUnitPath -Details @{ DriveCount = $drives.Count; ExposedCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue ("$($exposed.Count) of $($drives.Count) shared drive(s) permit sharing outside the " +
            "organization (domainUsersOnly not enforced): $((@($exposed.Label) | Select-Object -First 10) -join '; '). " +
            "Their contents can be shared with external accounts, and made publicly accessible if the domain sharing " +
            'setting allows it. Restrict external sharing on each drive or document the exception. This reflects the ' +
            "drive-level restriction; confirming a live public link requires a per-file permission scan not performed here.") `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            DriveCount    = $drives.Count
            ExposedCount  = $exposed.Count
            AffectedItems = @($exposed.Label)
            AffectedLabel = 'Shared drives permitting external sharing'
        }
}

# ── GWS.DRIVEDOCS.1.3 / 1.4 / 1.5 / 1.7 shared evaluator ──────────────────
# These four SCuBA policies are all conditional on external sharing: each one
# constrains a sub-setting of drive_and_docs.external_sharing that only has any
# effect when externalSharingMode permits sharing outside the organization. All
# of them live on the SAME policy value object as externalSharingMode, so the
# mode and the sub-setting can be paired per targeted policy without needing the
# policyQuery OU — reading the fields separately would let one OU's mode answer
# for another OU's sub-setting.
#
# -Applies is a scriptblock over the mode; -Evaluate is a scriptblock over the
# whole value object returning 'ok', 'bad', or 'missing'. Grading is
# weakest-OU-wins. A value object where the policy applies but the sub-setting is
# absent grades 'missing' and the whole check reports Not Assessed: an unreadable
# setting is not a passing setting (an earlier generation of these checks read a
# missing field as compliant, which is how a tenant scored a clean report on a
# setting nobody had ever looked at).
function Test-GwsDriveSharingSubSetting {
    param(
        [hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath,
        [scriptblock]$Applies, [scriptblock]$Evaluate,
        [string]$Status, [string]$BadMsg, [string]$GoodMsg
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CloudIdentityPolicies' -Subject 'Drive external-sharing policy'
    if ($na) { return $na }

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $objs = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.external_sharing')
    if ($objs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No drive_and_docs.external_sharing policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $bad = 0; $missing = 0; $applicable = 0
    foreach ($o in $objs) {
        $mode = if ($o.PSObject.Properties.Name -contains 'externalSharingMode') { "$($o.externalSharingMode)" } else { $null }
        # Mode itself unreadable: the policy's applicability is unknown, so it is
        # not assessed rather than assumed inapplicable (which would read as a pass).
        if (-not $mode) { $missing++; continue }
        if (-not (& $Applies $mode)) { continue }
        $applicable++
        switch (& $Evaluate $o) {
            'bad'     { $bad++ }
            'missing' { $missing++ }
        }
    }

    if ($bad -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $Status `
            -CurrentValue "$BadMsg in $bad of $($objs.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath `
            -Details @{ PolicyCount = $objs.Count; ApplicableCount = $applicable; ViolatingCount = $bad }
    }
    if ($missing -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue ("External sharing is permitted but the setting this policy constrains was not returned " +
                "in $missing of $($objs.Count) targeted policy/policies — not assessed rather than assumed compliant") `
            -OrgUnitPath $OrgUnitPath -Details @{ PolicyCount = $objs.Count; UnreadableCount = $missing }
    }
    if ($applicable -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue ("Not applicable: external sharing is disallowed in all $($objs.Count) targeted policy/policies, " +
                'so this setting cannot expose content outside the organization') `
            -OrgUnitPath $OrgUnitPath -Details @{ PolicyCount = $objs.Count; ApplicableCount = 0 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$GoodMsg in all $applicable of $($objs.Count) targeted policy/policies where external sharing is permitted" `
        -OrgUnitPath $OrgUnitPath -Details @{ PolicyCount = $objs.Count; ApplicableCount = $applicable }
}

# Reads a field off a policy value object as 'ok' / 'bad' / 'missing'.
function Get-GwsPolicyFieldVerdict {
    param($Object, [string]$Field, $SecureValue)
    if ($Object.PSObject.Properties.Name -notcontains $Field) { return 'missing' }
    if ($Object.$Field -eq $SecureValue) { return 'ok' }
    return 'bad'
}

# ── DRIVE-019: GWS.DRIVEDOCS.1.3 — Warn when sharing outside allowlisted domains ──
# Two modes, two different fields: an allowlisted-domains tenant is governed by
# warnForSharingOutsideAllowlistedDomains, an open-sharing tenant by
# warnForExternalSharing. Reading only one of them would score half the tenants
# against a setting that does not apply to them.
function Test-DRIVE019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsDriveSharingSubSetting -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Applies { param($mode) $mode -in @('ALLOWED', 'ALLOWLISTED_DOMAINS') } `
        -Evaluate {
            param($o)
            $field = if ("$($o.externalSharingMode)" -eq 'ALLOWLISTED_DOMAINS') { 'warnForSharingOutsideAllowlistedDomains' } else { 'warnForExternalSharing' }
            Get-GwsPolicyFieldVerdict -Object $o -Field $field -SecureValue $true
        } `
        -Status 'FAIL' `
        -BadMsg 'Users are not warned when sharing Drive content outside the organization' `
        -GoodMsg 'Users are warned when sharing Drive content outside the organization'
}

# ── DRIVE-020: GWS.DRIVEDOCS.1.4 — No sharing with non-Google accounts ────
function Test-DRIVE020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsDriveSharingSubSetting -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Applies { param($mode) $mode -in @('ALLOWED', 'ALLOWLISTED_DOMAINS') } `
        -Evaluate {
            param($o)
            $field = if ("$($o.externalSharingMode)" -eq 'ALLOWLISTED_DOMAINS') { 'allowNonGoogleInvitesInAllowlistedDomains' } else { 'allowNonGoogleInvites' }
            Get-GwsPolicyFieldVerdict -Object $o -Field $field -SecureValue $false
        } `
        -Status 'WARN' `
        -BadMsg 'Drive content can be shared with recipients who have no Google account (visitor sharing, PIN-based access)' `
        -GoodMsg 'Drive sharing is limited to Google accounts'
}

# ── DRIVE-021: GWS.DRIVEDOCS.1.5 — Publishing to the web disabled ─────────
function Test-DRIVE021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsDriveSharingSubSetting -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Applies { param($mode) $mode -ne 'DISALLOWED' } `
        -Evaluate { param($o) Get-GwsPolicyFieldVerdict -Object $o -Field 'allowPublishingFiles' -SecureValue $false } `
        -Status 'WARN' `
        -BadMsg 'Users can publish Drive content to the web, making it readable by anyone with the link' `
        -GoodMsg 'Publishing Drive content to the web is disabled'
}

# ── DRIVE-022: GWS.DRIVEDOCS.1.7 — No distributing content to outside drives ──
function Test-DRIVE022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsDriveSharingSubSetting -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Applies { param($mode) $mode -ne 'DISALLOWED' } `
        -Evaluate { param($o) Get-GwsPolicyFieldVerdict -Object $o -Field 'allowedPartiesForDistributingContent' -SecureValue 'NONE' } `
        -Status 'WARN' `
        -BadMsg 'Users can upload or move content into shared drives owned by another organization' `
        -GoodMsg 'Content cannot be moved into shared drives owned by another organization'
}
