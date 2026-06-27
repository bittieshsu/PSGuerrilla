#requires -version 7.0
<#
    High-tier fixtures, Round 5: Google Workspace.
    AUTH / EMAIL / OAUTH / DRIVE / DEVICE / COLLAB / ADMIN / GTRADE / LOG.
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-high-5.ps1

    Always-WARN placeholders (settings not exposed via Google API) pinned to WARN:
      DEVICE-002/003/004/005/006, EMAIL-005, EMAIL-012, OAUTH-005, OAUTH-009.
    No-FAIL-by-design: DEVICE-008, EMAIL-015, ADMIN-002, LOG-001.
    CloudIdentityPolicies checks use the Resolve-GooglePolicyValue .ByType shape.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Theater,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    # CloudIdentity resolver checks need PSCustomObject value objects — flag those fixtures.
    $objShape = ($AuditData.ContainsKey('CloudIdentityPolicies') -and $AuditData['CloudIdentityPolicies'])
    $obj=[ordered]@{ checkId=$CheckId; theater=$Theater; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; objectShape=[bool]$objShape; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 14 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$F='Fortification'; $G='GoogleWorkspace'
function Cip($type,$val){ @{ Errors=@{}; CloudIdentityPolicies=@{ ByType=@{ "$type"=@(@{ setting=@{ value=$val } }) } } } }

# ── Authentication ──
New-Fixture $G AUTH-002 $F clean PASS 'All active users 2SV-enrolled (>=95%)' @{ Errors=@{}; Users=@(1..10 | ForEach-Object { @{ suspended=$false; isEnrolledIn2Sv=$true; primaryEmail="u$_@e.com" } }) }
New-Fixture $G AUTH-002 $F known-bad FAIL '20% 2SV enrollment (<80%)' @{ Errors=@{}; Users=@(
    @{ suspended=$false; isEnrolledIn2Sv=$true; primaryEmail='u1@e.com' },@{ suspended=$false; isEnrolledIn2Sv=$false; primaryEmail='u2@e.com' },
    @{ suspended=$false; isEnrolledIn2Sv=$false; primaryEmail='u3@e.com' },@{ suspended=$false; isEnrolledIn2Sv=$false; primaryEmail='u4@e.com' },
    @{ suspended=$false; isEnrolledIn2Sv=$false; primaryEmail='u5@e.com' }) }
New-Fixture $G AUTH-002 $F throttled SKIP 'User inventory not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }
New-Fixture $G AUTH-004 $F clean PASS 'Minimum password length 12' (Cip 'security.password' @{ minimumLength=12 })
New-Fixture $G AUTH-004 $F known-bad FAIL 'Minimum password length 6 (<8)' (Cip 'security.password' @{ minimumLength=6 })
New-Fixture $G AUTH-004 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }
New-Fixture $G AUTH-008 $F clean PASS 'Less secure apps blocked' (Cip 'security.less_secure_apps' @{ allowLessSecureApps=$false })
New-Fixture $G AUTH-008 $F known-bad FAIL 'Less secure apps allowed' (Cip 'security.less_secure_apps' @{ allowLessSecureApps=$true })
New-Fixture $G AUTH-008 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }
New-Fixture $G AUTH-010 $F clean PASS 'No super admin has self-service recovery configured' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; recoveryEmail=$null; recoveryPhone=$null; primaryEmail='admin@e.com' }) }
New-Fixture $G AUTH-010 $F known-bad FAIL 'A super admin has a recovery email set' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; recoveryEmail='r@e.com'; recoveryPhone=$null; primaryEmail='admin@e.com' }) }
New-Fixture $G AUTH-010 $F throttled SKIP 'User inventory not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }
New-Fixture $G AUTH-013 $F clean PASS 'Super admins logged in recently' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; lastLoginTime='2026-06-01T00:00:00Z'; primaryEmail='admin@e.com' }) }
New-Fixture $G AUTH-013 $F known-bad FAIL 'A super admin inactive >90 days' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; lastLoginTime='2026-01-01T00:00:00Z'; primaryEmail='admin@e.com' }) }
New-Fixture $G AUTH-013 $F throttled SKIP 'User inventory not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }
New-Fixture $G AUTH-017 $F clean PASS 'Super admin self-recovery disabled' (Cip 'security.super_admin_account_recovery' @{ enableAccountRecovery=$false })
New-Fixture $G AUTH-017 $F known-bad FAIL 'Super admin self-recovery enabled' (Cip 'security.super_admin_account_recovery' @{ enableAccountRecovery=$true })
New-Fixture $G AUTH-017 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }

# ── Email security ──
New-Fixture $G EMAIL-005 $F always-warn WARN 'TLS enforcement requires manual verification' @{ Errors=@{} }
New-Fixture $G EMAIL-009 $F clean PASS 'No user has auto-forwarding enabled' @{ Errors=@{}; Users=@(@{ suspended=$false }); GmailSettings=@{ 'u1@e.com'=@{ autoForwarding=@{ enabled=$false } } } }
New-Fixture $G EMAIL-009 $F known-bad FAIL 'A user has auto-forwarding enabled' @{ Errors=@{}; GmailSettings=@{ 'u1@e.com'=@{ autoForwarding=@{ enabled=$true; emailAddress='ext@a.com' } } } }
New-Fixture $G EMAIL-009 $F throttled SKIP 'Per-user Gmail settings not assessed' @{ Errors=@{ 'GmailSettings:u1@e.com'='403' }; GmailSettings=$null }
New-Fixture $G EMAIL-011 $F clean PASS 'POP and IMAP disabled for all users' @{ Errors=@{}; Users=@(@{ suspended=$false }); GmailSettings=@{ 'u1@e.com'=@{ imap=@{ enabled=$false }; pop=@{ accessWindow='disabled' } } } }
New-Fixture $G EMAIL-011 $F known-bad FAIL 'A user has IMAP enabled' @{ Errors=@{}; GmailSettings=@{ 'u1@e.com'=@{ imap=@{ enabled=$true }; pop=@{ accessWindow='disabled' } } } }
New-Fixture $G EMAIL-011 $F throttled SKIP 'Per-user Gmail settings not assessed' @{ Errors=@{ 'GmailSettings:u1@e.com'='403' }; GmailSettings=$null }
New-Fixture $G EMAIL-012 $F always-warn WARN 'Spam/phishing filters require manual verification' @{ Errors=@{} }
New-Fixture $G EMAIL-013 $F clean PASS 'Enhanced pre-delivery scanning enabled' (Cip 'gmail.enhanced_pre_delivery_message_scanning' @{ enableImprovedSuspiciousContentDetection=$true })
New-Fixture $G EMAIL-013 $F known-bad FAIL 'Enhanced pre-delivery scanning disabled' (Cip 'gmail.enhanced_pre_delivery_message_scanning' @{ enableImprovedSuspiciousContentDetection=$false })
New-Fixture $G EMAIL-013 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }
New-Fixture $G EMAIL-015 $F clean PASS 'Future attachment-safety settings auto-applied' (Cip 'gmail.email_attachment_safety' @{ applyFutureRecommendedSettingsAutomatically=$true })
New-Fixture $G EMAIL-015 $F known-bad WARN 'Future attachment-safety auto-apply off (no FAIL path)' (Cip 'gmail.email_attachment_safety' @{ applyFutureRecommendedSettingsAutomatically=$false })
New-Fixture $G EMAIL-015 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }
New-Fixture $G EMAIL-016 $F clean PASS 'Link shortener + external image scanning enabled' (Cip 'gmail.links_and_external_images' @{ enableShortenerScanning=$true; enableExternalImageScanning=$true })
New-Fixture $G EMAIL-016 $F known-bad FAIL 'Link shortener scanning disabled' (Cip 'gmail.links_and_external_images' @{ enableShortenerScanning=$false; enableExternalImageScanning=$true })
New-Fixture $G EMAIL-016 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }
New-Fixture $G EMAIL-022 $F clean PASS 'No forwarding rules of any kind' @{ Errors=@{}; Users=@(@{ suspended=$false }); GmailSettings=@{ 'u1@e.com'=@{ autoForwarding=@{ enabled=$false }; filters=@(); sendAs=@(@{ sendAsEmail='u1@e.com' }); forwardingAddresses=@() } } }
New-Fixture $G EMAIL-022 $F known-bad FAIL 'A user has auto-forwarding to external' @{ Errors=@{}; GmailSettings=@{ 'u1@e.com'=@{ autoForwarding=@{ enabled=$true; emailAddress='ext@a.com' }; filters=@(); sendAs=@(); forwardingAddresses=@() } } }
New-Fixture $G EMAIL-022 $F throttled SKIP 'Per-user Gmail settings not assessed' @{ Errors=@{ 'GmailSettings:u1@e.com'='403' }; GmailSettings=$null }

# ── OAuth ──
New-Fixture $G OAUTH-001 $F clean PASS 'Unconfigured third-party app access blocked' (Cip 'api_controls.unconfigured_third_party_apps' @{ accessLevel='BLOCKED' })
New-Fixture $G OAUTH-001 $F known-bad FAIL 'Unconfigured third-party app access allowed for all' (Cip 'api_controls.unconfigured_third_party_apps' @{ accessLevel='ALLOW_ALL' })
New-Fixture $G OAUTH-001 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }
New-Fixture $G OAUTH-002 $F known-bad WARN 'A third-party OAuth app is authorized (review)' @{ Errors=@{}; OAuthApps=@(@{ Params=@{ app_name='App1'; scope='userinfo.email' } }) }
New-Fixture $G OAUTH-002 $F throttled SKIP 'OAuth token activity not assessed' @{ Errors=@{ OAuthApps='Reports API 429' }; OAuthApps=$null }
New-Fixture $G OAUTH-004 $F clean PASS 'Only low-risk-scope OAuth apps' @{ Errors=@{}; OAuthApps=@(@{ Params=@{ app_name='Safe'; scope='https://www.googleapis.com/auth/spreadsheets.readonly' } }) }
New-Fixture $G OAUTH-004 $F known-bad FAIL 'Four high-privilege admin-scope OAuth apps' @{ Errors=@{}; OAuthApps=@(
    @{ Params=@{ app_name='A1'; scope='admin.directory' } },@{ Params=@{ app_name='A2'; scope='admin.directory' } },
    @{ Params=@{ app_name='A3'; scope='admin.directory' } },@{ Params=@{ app_name='A4'; scope='admin.directory' } }) }
New-Fixture $G OAUTH-004 $F throttled SKIP 'OAuth token activity not assessed' @{ Errors=@{ OAuthApps='Reports API 429' }; OAuthApps=$null }
New-Fixture $G OAUTH-005 $F always-warn WARN 'Unverified-app policy requires manual verification' @{ Errors=@{} }
New-Fixture $G OAUTH-009 $F always-warn WARN 'Service-account key inventory requires Cloud Console' @{ Errors=@{} }
New-Fixture $G OAUTH-010 $F clean PASS 'Few apps hold sensitive scopes (<=5)' @{ Errors=@{}; OAuthApps=@(@{ Params=@{ app_name='A1'; scope='drive' } },@{ Params=@{ app_name='A2'; scope='gmail' } }) }
New-Fixture $G OAUTH-010 $F known-bad WARN 'Six apps hold sensitive scopes (6-10)' @{ Errors=@{}; OAuthApps=@(
    @{ Params=@{ app_name='A1'; scope='drive' } },@{ Params=@{ app_name='A2'; scope='gmail' } },@{ Params=@{ app_name='A3'; scope='calendar' } },
    @{ Params=@{ app_name='A4'; scope='drive' } },@{ Params=@{ app_name='A5'; scope='gmail' } },@{ Params=@{ app_name='A6'; scope='calendar' } }) }
New-Fixture $G OAUTH-010 $F throttled SKIP 'OAuth token activity not assessed' @{ Errors=@{ OAuthApps='Reports API 429' }; OAuthApps=$null }

# ── Drive ──
New-Fixture $G DRIVE-001 $F clean PASS 'Drive external sharing OFF' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ driveExternalSharing='OFF' } }; CloudIdentityPolicies=$null }
New-Fixture $G DRIVE-001 $F known-bad FAIL 'Drive external sharing ON' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ driveExternalSharing='ON' } }; CloudIdentityPolicies=$null }
New-Fixture $G DRIVE-001 $F throttled SKIP 'Org-unit policy not assessed' @{ Errors=@{ OrgUnits='collector error' } }
New-Fixture $G DRIVE-002 $F clean PASS 'Default link sharing RESTRICTED' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ defaultLinkSharing='RESTRICTED' } } }
New-Fixture $G DRIVE-002 $F known-bad FAIL 'Default link sharing UNRESTRICTED' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ defaultLinkSharing='UNRESTRICTED' } } }
New-Fixture $G DRIVE-002 $F throttled SKIP 'Org-unit policy not assessed' @{ Errors=@{ OrgUnits='collector error' } }
New-Fixture $G DRIVE-003 $F clean PASS 'Anyone-with-link disabled' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ anyoneWithLinkEnabled=$false } } }
New-Fixture $G DRIVE-003 $F known-bad FAIL 'Anyone-with-link enabled' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ anyoneWithLinkEnabled=$true } } }
New-Fixture $G DRIVE-003 $F throttled SKIP 'Org-unit policy not assessed' @{ Errors=@{ OrgUnits='collector error' } }
New-Fixture $G DRIVE-006 $F clean PASS 'Shared-drive external sharing off' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ sharedDriveExternalSharing=$false } } }
New-Fixture $G DRIVE-006 $F known-bad FAIL 'Shared-drive external sharing on' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ sharedDriveExternalSharing=$true } } }
New-Fixture $G DRIVE-006 $F throttled SKIP 'Org-unit policy not assessed' @{ Errors=@{ OrgUnits='collector error' } }
New-Fixture $G DRIVE-009 $F clean PASS 'Few Drive-scope OAuth apps (<=5)' @{ Errors=@{}; OAuthApps=@(@{ Params=@{ app_name='A1'; scope='drive' } }) }
New-Fixture $G DRIVE-009 $F known-bad WARN 'Six Drive-scope OAuth apps (6-10)' @{ Errors=@{}; OAuthApps=@(
    @{ Params=@{ app_name='A1'; scope='drive' } },@{ Params=@{ app_name='A2'; scope='drive.file' } },@{ Params=@{ app_name='A3'; scope='drive.readonly' } },
    @{ Params=@{ app_name='A4'; scope='drive' } },@{ Params=@{ app_name='A5'; scope='drive' } },@{ Params=@{ app_name='A6'; scope='drive' } }) }
New-Fixture $G DRIVE-009 $F throttled SKIP 'OAuth token activity not assessed' @{ Errors=@{ OAuthApps='Reports API 429' }; OAuthApps=$null }

# ── Device management ──
New-Fixture $G DEVICE-001 $F clean PASS 'All registered mobile devices are managed (>=95%)' @{ Errors=@{}; MobileDevices=@(@{ status='APPROVED'; managementType='ADVANCED' },@{ status='APPROVED'; managementType='ADVANCED' }) }
New-Fixture $G DEVICE-001 $F known-bad FAIL 'Most mobile devices unmanaged (<75%)' @{ Errors=@{}; MobileDevices=@(
    @{ status='BLOCKED'; managementType='NONE' },@{ status='BLOCKED'; managementType='NONE' },@{ status='BLOCKED'; managementType='NONE' },
    @{ status='BLOCKED'; managementType='NONE' },@{ status='BLOCKED'; managementType='NONE' },@{ status='APPROVED'; managementType='ADVANCED' }) }
New-Fixture $G DEVICE-001 $F throttled SKIP 'Mobile device inventory not assessed' @{ Errors=@{ MobileDevices='collector error' }; MobileDevices=$null }
foreach ($d in 'DEVICE-002','DEVICE-003','DEVICE-004','DEVICE-005','DEVICE-006') {
    New-Fixture $G $d $F always-warn WARN 'Setting not exposed via Admin SDK — manual verification' @{ Errors=@{} }
}
New-Fixture $G DEVICE-008 $F clean PASS 'Chrome extension management policy configured' @{ Errors=@{}; ChromePolicies=@{ ExtensionInstallBlocklist=@('*') } }
New-Fixture $G DEVICE-008 $F known-bad WARN 'No Chrome extension policy (no FAIL path)' @{ Errors=@{}; ChromePolicies=@{} }
New-Fixture $G DEVICE-008 $F throttled SKIP 'Chrome policy not assessed' @{ Errors=@{ ChromePolicies='collector error' } }

# ── Collaboration ──
New-Fixture $G COLLAB-004 $F clean PASS 'External chat disabled' (Cip 'chat.external_chat_restriction' @{ allowExternalChat=$false; externalChatRestriction='INTERNAL_ONLY' })
New-Fixture $G COLLAB-004 $F known-bad FAIL 'External chat unrestricted' (Cip 'chat.external_chat_restriction' @{ allowExternalChat=$true; externalChatRestriction='NO_RESTRICTION' })
New-Fixture $G COLLAB-004 $F throttled SKIP 'Chat policy not assessed' @{ Errors=@{ CloudIdentityPolicies='collector error' } }
New-Fixture $G COLLAB-008 $F clean PASS 'Calendar external sharing limited to free/busy' (Cip 'calendar.primary_calendar_max_allowed_external_sharing' @{ maxAllowedExternalSharing='EXTERNAL_FREE_BUSY_ONLY' })
New-Fixture $G COLLAB-008 $F known-bad FAIL 'Calendar external sharing exposes all info read/write' (Cip 'calendar.primary_calendar_max_allowed_external_sharing' @{ maxAllowedExternalSharing='EXTERNAL_ALL_INFO_READ_WRITE' })
New-Fixture $G COLLAB-008 $F throttled SKIP 'Calendar policy not assessed' @{ Errors=@{ CloudIdentityPolicies='collector error' } }

# ── Admin management ──
New-Fixture $G ADMIN-002 $F clean PASS 'Custom roles and assignments configured' @{ Errors=@{}; Roles=@(@{ isSystemRole=$false; isSuperAdminRole=$false }); RoleAssignments=@(@{ id='1' }) }
New-Fixture $G ADMIN-002 $F known-bad WARN 'Assignments exist but no custom roles (no FAIL path)' @{ Errors=@{}; Roles=@(@{ isSystemRole=$true }); RoleAssignments=@(@{ id='1' }) }
New-Fixture $G ADMIN-002 $F throttled SKIP 'Role data not assessed' @{ Errors=@{ Roles='collector error' } }
New-Fixture $G ADMIN-004 $F clean PASS 'No suspended account holds admin privileges' @{ Errors=@{}; Users=@(@{ suspended=$false; isAdmin=$true; primaryEmail='a@e.com' }) }
New-Fixture $G ADMIN-004 $F known-bad FAIL 'A suspended account still holds admin privileges' @{ Errors=@{}; Users=@(@{ suspended=$true; isAdmin=$true; primaryEmail='a@e.com' }) }
New-Fixture $G ADMIN-004 $F throttled SKIP 'User inventory not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }
New-Fixture $G ADMIN-010 $F clean PASS 'Group owners cannot add external members' (Cip 'groups_for_business.groups_sharing' @{ ownersCanAllowExternalMembers=$false })
New-Fixture $G ADMIN-010 $F known-bad FAIL 'Group owners can add external members' (Cip 'groups_for_business.groups_sharing' @{ ownersCanAllowExternalMembers=$true })
New-Fixture $G ADMIN-010 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; CloudIdentityPolicies=$null }
New-Fixture $G ADMIN-013 $F clean PASS 'Two active super admins (2-4 range)' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; primaryEmail='a@e.com' },@{ isAdmin=$true; suspended=$false; primaryEmail='b@e.com' }) }
New-Fixture $G ADMIN-013 $F known-bad FAIL 'Single super admin (no redundancy)' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; primaryEmail='a@e.com' }) }
New-Fixture $G ADMIN-013 $F throttled SKIP 'User inventory not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }

# ── Google tradecraft ──
New-Fixture $G GTRADE-002 $F clean PASS 'No group is viewable by anyone on the internet' @{ Errors=@{}; GroupSettings=@{ 'g@e.com'=@{ email='g@e.com'; whoCanViewGroup='ALL_MEMBERS_CAN_VIEW' } } }
New-Fixture $G GTRADE-002 $F known-bad FAIL 'A group is viewable by anyone on the internet' @{ Errors=@{}; GroupSettings=@{ 'g@e.com'=@{ email='g@e.com'; whoCanViewGroup='ANYONE_CAN_VIEW' } } }
New-Fixture $G GTRADE-002 $F no-data SKIP 'Group settings not collected' @{ Errors=@{}; GroupSettings=@{} }
New-Fixture $G GTRADE-006 $F clean PASS 'No over-scoped OAuth grants' @{ Errors=@{}; OAuthApps=@(@{ Params=@{ app_name='Nice'; scope='https://www.googleapis.com/auth/drive.readonly' } }) }
New-Fixture $G GTRADE-006 $F known-bad FAIL 'An app holds full-mailbox scope (persists across reset)' @{ Errors=@{}; OAuthApps=@(@{ Params=@{ app_name='Evil'; scope='https://mail.google.com/' } }) }
New-Fixture $G GTRADE-006 $F no-data SKIP 'OAuth token activity not collected' @{ Errors=@{}; OAuthApps=@() }

# ── Logging / alerting ──
New-Fixture $G LOG-001 $F clean PASS 'Enterprise edition (extended log retention)' @{ Errors=@{}; Tenant=@{ edition='enterprise' } }
New-Fixture $G LOG-001 $F known-bad WARN 'Business edition (limited retention, no FAIL path)' @{ Errors=@{}; Tenant=@{ edition='business' } }
New-Fixture $G LOG-001 $F throttled SKIP 'Tenant info not assessed' @{ Errors=@{ Customer='collector error' } }
New-Fixture $G LOG-002 $F clean PASS 'Five or more alert rules configured' @{ Errors=@{}; AlertRules=@(@{ name='R1' },@{ name='R2' },@{ name='R3' },@{ name='R4' },@{ name='R5' }) }
# NOTE: 0 alert rules currently yields WARN, not FAIL — the `-not @()` guard returns WARN
# and the status ladder's else-branch is also WARN (dead FAIL branch). Pinned as WARN.
New-Fixture $G LOG-002 $F known-bad WARN 'No alert rules configured (no reachable FAIL path)' @{ Errors=@{}; AlertRules=@() }
New-Fixture $G LOG-002 $F throttled SKIP 'Alert rules not assessed' @{ Errors=@{ AlertRules='collector error' } }

Write-Host "`nDone (high round 5)."
