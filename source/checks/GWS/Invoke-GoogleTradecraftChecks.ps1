# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-GoogleTradecraftChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'GoogleTradecraftChecks'
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

# Returns the non-metadata group-settings entries from $AuditData.GroupSettings, or $null if
# the collector didn't run (so checks SKIP rather than report a false clean).
function Get-TradecraftGroupSettings {
    param([hashtable]$AuditData)
    $gs = $AuditData.GroupSettings
    if (-not $gs -or $gs.Count -eq 0) { return $null }
    $entries = @()
    foreach ($k in $gs.Keys) {
        if ($k -eq '__truncated') { continue }
        $entries += $gs[$k]
    }
    if ($entries.Count -eq 0) { return $null }
    return @($entries)
}

# ── GTRADE-001: Domain-Wide Delegation org-takeover exposure (DeleFriend precondition) ──
function Test-GTRADE001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # NOTE: there is no reliable GA Directory API to LIST domain-wide-delegation grants (the
    # legacy /domainwidedelegation path 404s on many tenants; DeleFriend itself enumerates grants
    # by brute-forcing client-id/scope pairs). So an empty collection means "could not enumerate",
    # NOT "no grants" — never report PASS on emptiness, or the check gives a false all-clear on the
    # exact attack surface it exists for.
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainWideDelegation' -Subject 'domain-wide delegation grants'
    if ($na) { return $na }

    # Filter $null (a missing key makes @($null).Count == 1, which would slip past an empty check).
    $grants = @($AuditData.DomainWideDelegation | Where-Object { $null -ne $_ })
    if ($grants.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Domain-wide delegation grants could not be enumerated via the Directory API (no GA list endpoint) — this is NOT a confirmation that none exist' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Verify manually: Admin Console > Security > API controls > Domain-wide delegation. Treat any grant holding full mail.google.com / drive / admin.directory / cloud-platform scopes as a DeleFriend takeover precondition — a new key on that service account grants org-wide impersonation.' }
    }

    # High-risk = scopes that let a delegated SA impersonate org-wide (the DeleFriend impact).
    $isHighRisk = {
        param([string]$s)
        $s = $s.ToLower()
        if ($s -match 'mail\.google\.com') { return $true }
        if ($s -match 'gmail\.(modify|settings|compose|insert)') { return $true }
        if ($s -match 'auth/drive($|[^.])' -and $s -notmatch 'drive\.(readonly|file|metadata|appdata|photos)') { return $true }
        if ($s -match 'admin\.directory' -and $s -notmatch '\.readonly') { return $true }
        if ($s -match 'cloud-platform') { return $true }
        if ($s -match 'auth/apps\.groups($|[^.])') { return $true }
        return $false
    }

    $risky = [System.Collections.Generic.List[string]]::new()
    foreach ($grant in $grants) {
        $clientId = $grant.clientId ?? $grant.ClientId ?? 'Unknown'
        $scopes = @($grant.scopes ?? $grant.Scopes ?? @())
        $hits = @($scopes | Where-Object { & $isHighRisk "$_" })
        if ($hits.Count -gt 0) {
            $risky.Add("$clientId (org-impersonation scope: $((@($hits) | Select-Object -First 2) -join ', '))")
        }
    }

    if ($risky.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($risky.Count) of $($grants.Count) domain-wide delegation grant(s) hold org-impersonation scopes — each is a DeleFriend takeover target if its service account gets a new key" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                RiskyGrants   = @($risky)
                AffectedItems = @($risky)
                AffectedLabel = 'Domain-wide delegation grants with org-impersonation scopes'
                Note          = 'Full DeleFriend confirmation (a user-managed key on the delegated service account) requires GCP IAM access — not yet collected. Treat any broad-scope grant as a takeover precondition.'
            }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($grants.Count) domain-wide delegation grant(s); none hold full mail/drive/directory/cloud-platform impersonation scopes" `
        -OrgUnitPath $OrgUnitPath
}

# ── GTRADE-002: Internet-readable Google Groups ──────────────────────────────
function Test-GTRADE002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupSettings' -Subject 'group settings'
    if ($na) { return $na }

    $entries = Get-TradecraftGroupSettings -AuditData $AuditData
    if ($null -eq $entries) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group settings not collected (run without -Quick, and ensure the apps.groups.settings scope is delegated)' `
            -OrgUnitPath $OrgUnitPath
    }
    $public = @($entries | Where-Object { "$($_.whoCanViewGroup)" -match '(?i)ANYONE_CAN_VIEW' })
    if ($public.Count -gt 0) {
        $emails = @($public | ForEach-Object { $_.email })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($public.Count) of $($entries.Count) group(s) are viewable by anyone on the internet" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ AffectedItems = $emails; AffectedLabel = 'Internet-readable groups' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No internet-readable groups ($($entries.Count) inspected)" -OrgUnitPath $OrgUnitPath
}

# ── GTRADE-003: Open-join / external-member groups ───────────────────────────
function Test-GTRADE003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupSettings' -Subject 'group settings'
    if ($na) { return $na }

    $entries = Get-TradecraftGroupSettings -AuditData $AuditData
    if ($null -eq $entries) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group settings not collected (run without -Quick, and ensure the apps.groups.settings scope is delegated)' `
            -OrgUnitPath $OrgUnitPath
    }
    $open = @($entries | Where-Object {
        "$($_.whoCanJoin)" -match '(?i)ANYONE_CAN_JOIN|ALL_IN_DOMAIN_CAN_JOIN' -or
        "$($_.allowExternalMembers)" -match '(?i)^true$'
    })
    if ($open.Count -gt 0) {
        $emails = @($open | ForEach-Object { $_.email })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($open.Count) of $($entries.Count) group(s) allow open join or external members" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                AffectedItems = $emails
                AffectedLabel = 'Open-join / external-member groups'
                Note          = 'If any such group holds resource or IAM access, joining it inherits that access (a privilege-escalation path Google treats as intended behavior).'
            }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No open-join or external-member groups ($($entries.Count) inspected)" -OrgUnitPath $OrgUnitPath
}

# ── GTRADE-004: Super-admin sprawl ───────────────────────────────────────────
function Test-GTRADE004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    if (-not $AuditData.Users -or @($AuditData.Users).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No user data available' -OrgUnitPath $OrgUnitPath
    }
    $supers = @($AuditData.Users | Where-Object { $_.isAdmin -eq $true -and -not $_.suspended })
    $n = $supers.Count
    $status = if ($n -le 4) { 'PASS' } elseif ($n -le 10) { 'WARN' } else { 'FAIL' }
    $details = @{ SuperAdminCount = $n }
    if ($n -gt 4) {
        $details.AffectedItems = @($supers | ForEach-Object { $_.primaryEmail })
        $details.AffectedLabel = 'Super administrators'
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$n active super administrator(s) (best practice: fewer than 5)" `
        -OrgUnitPath $OrgUnitPath -Details $details
}

# ── GTRADE-005: Super-admin-equivalent custom roles ──────────────────────────
function Test-GTRADE005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Roles' -Subject 'admin roles'
    if ($na) { return $na }

    if (-not $AuditData.Roles -or @($AuditData.Roles).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No role data available' -OrgUnitPath $OrgUnitPath
    }
    $custom = @($AuditData.Roles | Where-Object { $_.isSystemRole -ne $true -and $_.isSuperAdminRole -ne $true })
    if ($custom.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No custom admin roles defined' -OrgUnitPath $OrgUnitPath
    }

    # Real Google admin privilege vocabulary for super-admin-equivalent power. Match WRITE/MANAGE
    # privileges (and the catch-all _ALL), and explicitly EXCLUDE read-only (_RETRIEVE) — a
    # directory-reader role (e.g. USERS_RETRIEVE / GROUPS_RETRIEVE) is NOT super-admin-equivalent.
    $writePriv = '(?i)(_ALL$|_CREATE$|_DELETE$|_UPDATE$|_SUSPEND$|_MOVE$|RESET_PASSWORD|FORCE_PASSWORD_CHANGE|DOMAIN_MANAGEMENT|APP_ADMIN|ROLE_MANAGEMENT|MANAGE_|SECURITY)'

    $flagged = [System.Collections.Generic.List[string]]::new()
    foreach ($role in $custom) {
        $privs = @($role.rolePrivileges ?? $role.RolePrivileges ?? @())
        $names = @($privs | ForEach-Object { "$($_.privilegeName ?? $_.PrivilegeName)" })
        $hits = @($names | Where-Object { $_ -match $writePriv -and $_ -notmatch '(?i)_RETRIEVE$' } | Select-Object -Unique)
        if ($hits.Count -gt 0) {
            $roleName = $role.roleName ?? $role.name ?? 'Unknown'
            $flagged.Add("$roleName ($((@($hits) | Select-Object -First 3) -join ', '))")
        }
    }

    if ($flagged.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($flagged.Count) of $($custom.Count) custom role(s) carry super-admin-equivalent privileges" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ AffectedItems = @($flagged); AffectedLabel = 'Custom roles with high-power privileges' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No custom role carries super-admin-equivalent privileges ($($custom.Count) custom role(s) reviewed)" `
        -OrgUnitPath $OrgUnitPath
}

# ── GTRADE-006: Persistent / over-scoped OAuth grants (GhostToken-class) ──────
function Test-GTRADE006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OAuthApps' -Subject 'OAuth token activity'
    if ($na) { return $na }

    if (-not $AuditData.OAuthApps -or @($AuditData.OAuthApps).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'OAuth token activity not available (collect from Reports API to enumerate third-party grants)' `
            -OrgUnitPath $OrgUnitPath
    }

    # Aggregate scopes per app across token events.
    $apps = @{}
    foreach ($event in $AuditData.OAuthApps) {
        # Prefer the friendly app name; where Google has none, label the client ID clearly
        # (rather than surfacing a bare numeric/platform string) so the finding stays actionable.
        $name = if ($event.Params.app_name) { "$($event.Params.app_name)" }
                elseif ($event.Params.client_id) { "unnamed app ($($event.Params.client_id))" }
                else { $null }
        if (-not $name) { continue }
        $scope = "$($event.Params.scope)"
        if (-not $apps.ContainsKey($name)) { $apps[$name] = [System.Collections.Generic.HashSet[string]]::new() }
        foreach ($s in ($scope -split '\s+')) { if ($s) { [void]$apps[$name].Add($s.ToLower()) } }
    }

    $isHighRisk = {
        param([string]$s)
        ($s -match 'mail\.google\.com') -or
        ($s -match 'auth/drive($|[^.])' -and $s -notmatch 'drive\.(readonly|file|metadata|appdata|photos)') -or
        ($s -match 'admin\.directory' -and $s -notmatch '\.readonly') -or
        ($s -match 'cloud-platform')
    }

    $risky = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $apps.Keys) {
        $hit = @($apps[$name] | Where-Object { & $isHighRisk $_ })
        if ($hit.Count -gt 0) { $risky.Add("$name") }
    }

    if ($risky.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($risky.Count) of $($apps.Count) third-party OAuth app(s) hold full mail/drive/admin scopes (persist across password reset)" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                AffectedItems = @($risky)
                AffectedLabel = 'Over-scoped OAuth grants'
                Note          = 'These grants bypass MFA and survive a password reset (Apps Script / app passwords / IMAP-OAuth are not revoked by a reset) — revoke the tokens explicitly.'
            }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No third-party OAuth app holds full mail/drive/admin scopes ($($apps.Count) app(s) reviewed)" `
        -OrgUnitPath $OrgUnitPath
}

# ── GTRADE-007: Admin Role Granted Through a Group ───────────────────────────
# Workspace analogue of an AD nested-group-to-privileged-group path. An admin
# role assigned to a security group is held by every member (direct or nested),
# so whoever controls the group's membership effectively controls the role.
function Test-GTRADE007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('Roles', 'RoleAssignments', 'Groups') -Subject 'admin roles, assignments, and groups'
    if ($na) { return $na }

    $roles = @($AuditData.Roles)
    $assignments = @($AuditData.RoleAssignments)
    $groups = @($AuditData.Groups)
    if ($roles.Count -eq 0 -or $assignments.Count -eq 0) {
        # A tenant always has system roles and at least one super-admin
        # assignment; an empty result is a collection gap, not a clean tenant.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue ('Not Assessed: the roles or role-assignments list came back empty, which no real tenant ' +
                'produces. This control was not evaluated; absence of evidence is not compliance.') `
            -OrgUnitPath $OrgUnitPath -Details @{ NotAssessed = $true }
    }

    $rolesById = @{}
    foreach ($r in $roles) { $rolesById["$($r.roleId)"] = $r }
    $groupsById = @{}
    foreach ($g in $groups) { if ($g.id) { $groupsById["$($g.id)"] = $g } }

    # Privileges whose reach over identities, security, OUs, roles, or groups
    # makes a group-mediated grant a real escalation (not merely a read role).
    $broadPattern = '(?i)^(SUPER_ADMIN|USERS?_|SECURITY_|ORGANIZATION_UNITS?_|GROUPS?_|ROLE_MANAGEMENT)'
    $rgm = $AuditData.RoleGroupMembers

    $records = [System.Collections.Generic.List[object]]::new()
    $highImpact = 0
    foreach ($a in $assignments) {
        $to = "$($a.assignedTo)"
        if (-not $to) { continue }
        $isGroup = ("$($a.assigneeType)" -eq 'GROUP') -or $groupsById.ContainsKey($to)
        if (-not $isGroup) { continue }

        $role = $rolesById["$($a.roleId)"]
        if (-not $role) { continue }
        $group = $groupsById[$to]
        $groupLabel = if ($group) { "$($group.email ?? $group.name ?? $to)" } else { "group id $to" }

        $isSuper = [bool]$role.isSuperAdminRole
        $broad = @(@($role.rolePrivileges) | Where-Object { "$($_.privilegeName)" -match $broadPattern })
        $high = $isSuper -or $broad.Count -gt 0

        # Membership: RoleGroupMembers is keyed by group id; a per-group error
        # means the surface exists but the roster was not enumerated.
        $members = if ($rgm) { @($rgm[$to]) } else { @() }
        $memberErr = $AuditData.Errors["RoleGroupMembers:$to"]
        $userMembers = @($members | Where-Object { "$($_.type)" -eq 'USER' })
        $subGroups   = @($members | Where-Object { "$($_.type)" -eq 'GROUP' })

        $reach = if ($memberErr) {
            'membership not enumerated'
        } elseif ($members.Count -eq 0) {
            'no members enumerated'
        } else {
            $bits = @("$($userMembers.Count) user member(s)")
            if ($subGroups.Count -gt 0) { $bits += "$($subGroups.Count) nested subgroup(s) whose members also inherit" }
            $bits -join ', '
        }

        $scope = if ("$($a.scopeType)" -eq 'ORG_UNIT') { "OU-scoped" } else { 'domain-wide' }
        $roleName = if ("$($role.roleName)") { "$($role.roleName)" } else { "role $($a.roleId)" }
        $priv = if ($isSuper) { 'SUPER_ADMIN' } elseif ($broad.Count) { (@($broad | ForEach-Object { "$($_.privilegeName)" } | Select-Object -Unique -First 3) -join ', ') } else { 'narrow privileges' }

        if ($high) { $highImpact++ }
        $records.Add([pscustomobject]@{
            High  = $high
            Label = "$roleName ($priv, $scope) -> group '$groupLabel': $reach"
        })
    }

    if ($records.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue ("No admin role is assigned to a group; all $($assignments.Count) role assignment(s) target " +
                'individual users. There is no group-membership escalation path into an admin role.') `
            -OrgUnitPath $OrgUnitPath -Details @{ GroupGrants = 0 }
    }

    $labels = @($records | ForEach-Object { $_.Label })
    if ($highImpact -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue ("$highImpact of $($records.Count) group-mediated admin-role grant(s) carry broad " +
                "(user-management, security, OU, role, group, or super-admin) privileges: $(($labels | Select-Object -First 8) -join '; '). " +
                'Every member of each group — including members of nested subgroups — holds the role, and anyone who ' +
                'can edit the group inherits it. Assign privileged roles to named individuals, or tightly control who ' +
                'can add members to these groups and their subgroups.') `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                GroupGrants   = $records.Count
                HighImpact    = $highImpact
                AffectedItems = @($labels)
                AffectedLabel = 'Admin roles reachable through group membership'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue ("$($records.Count) admin-role grant(s) target a group rather than a named individual, though " +
            "none carries broad privileges: $(($labels | Select-Object -First 8) -join '; '). Each is still a " +
            'membership-based grant: whoever can edit the group (or a nested subgroup) inherits the role. Confirm ' +
            'each group grant is intended and its membership is controlled.') `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            GroupGrants   = $records.Count
            HighImpact    = 0
            AffectedItems = @($labels)
            AffectedLabel = 'Admin roles reachable through group membership'
        }
}
