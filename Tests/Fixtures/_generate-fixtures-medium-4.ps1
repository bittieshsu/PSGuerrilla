#requires -version 7.0
<#
    Medium-tier fixtures, Round 4: Google Workspace (55 checks).
    AUTH/ADMIN/COLLAB/DRIVE/EMAIL/GTRADE/DEVICE/LOG/OAUTH/GWS-CLASS/GWS-GEMINI.
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-medium-4.ps1

    CloudIdentity (Resolve-GooglePolicyValue) checks use the .ByType shape and the
    objectShape flag (auto-detected) so policy value objects load as PSCustomObjects.
    Always-WARN: AUTH-007/009, COLLAB-009, DRIVE-005/007/011, EMAIL-006/007/008/014, DEVICE-010.
    Always-PASS: ADMIN-005, DEVICE-009. Always-SKIP: GWS-GEMINI-005.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Platform,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $objShape = ($AuditData.ContainsKey('CloudIdentityPolicies') -and $AuditData['CloudIdentityPolicies'])
    $obj=[ordered]@{ checkId=$CheckId; platform=$Platform; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; objectShape=[bool]$objShape; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 16 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$F='GWS'; $G='GoogleWorkspace'
function Cip($type,$val){ @{ Errors=@{}; CloudIdentityPolicies=@{ ByType=@{ "$type"=@(@{ setting=@{ value=$val } }) } } } }
$skCip=@{ Errors=@{}; CloudIdentityPolicies=$null }
$recent='2026-06-01T00:00:00Z'

# ── Authentication ──
New-Fixture $G AUTH-003 $F clean PASS '2SV enforcement requires a phishing-resistant security key' (Cip 'security.two_step_verification_enforcement_factor' @{ allowedSignInFactorSet='SECURITY_KEY' })
New-Fixture $G AUTH-003 $F known-bad FAIL '2SV enforcement permits all (weak) factors' (Cip 'security.two_step_verification_enforcement_factor' @{ allowedSignInFactorSet='ALL' })
New-Fixture $G AUTH-003 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G AUTH-005 $F clean PASS 'Password reuse disallowed' (Cip 'security.password' @{ allowReuse=$false })
New-Fixture $G AUTH-005 $F known-bad FAIL 'Password reuse allowed' (Cip 'security.password' @{ allowReuse=$true })
New-Fixture $G AUTH-005 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G AUTH-006 $F clean PASS 'Web session duration <= 12 hours' (Cip 'security.session_controls' @{ webSessionDuration='43200s' })
New-Fixture $G AUTH-006 $F known-bad FAIL 'Web session duration > 24 hours' (Cip 'security.session_controls' @{ webSessionDuration='172800s' })
New-Fixture $G AUTH-006 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G AUTH-007 $F always-warn WARN 'SSO configuration requires manual verification' @{ Errors=@{} }
New-Fixture $G AUTH-009 $F always-warn WARN 'App password policy requires manual verification' @{ Errors=@{} }
New-Fixture $G AUTH-011 $F clean PASS 'Login challenges (employee ID) enabled' (Cip 'security.login_challenges' @{ enableEmployeeIdChallenge=$true })
New-Fixture $G AUTH-011 $F known-bad WARN 'Login challenges not enabled' (Cip 'security.login_challenges' @{ enableEmployeeIdChallenge=$false })
New-Fixture $G AUTH-011 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G AUTH-014 $F clean PASS '2SV enrollment allowed' (Cip 'security.two_step_verification_enrollment' @{ allowEnrollment=$true })
New-Fixture $G AUTH-014 $F known-bad WARN '2SV enrollment disallowed' (Cip 'security.two_step_verification_enrollment' @{ allowEnrollment=$false })
New-Fixture $G AUTH-014 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# ── Admin management ──
New-Fixture $G ADMIN-003 $F clean PASS 'No custom admin roles' @{ Errors=@{}; Roles=@(@{ isSystemRole=$true },@{ isSuperAdminRole=$true }) }
New-Fixture $G ADMIN-003 $F known-bad WARN 'A custom admin role exists (review)' @{ Errors=@{}; Roles=@(@{ isSystemRole=$true },@{ isSystemRole=$false; isSuperAdminRole=$false; roleName='Custom1' }) }
New-Fixture $G ADMIN-003 $F throttled SKIP 'Role data not assessed' @{ Errors=@{ Roles='collector error' } }
New-Fixture $G ADMIN-005 $F clean PASS 'User inventory compiled (informational)' @{ Errors=@{}; Users=@(@{ suspended=$false; archived=$false }) }
New-Fixture $G ADMIN-005 $F throttled SKIP 'User data not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }
New-Fixture $G ADMIN-006 $F clean PASS 'All active users logged in within 90 days' @{ Errors=@{}; Users=@(@{ suspended=$false; lastLoginTime=$recent; primaryEmail='u@e.com' }) }
New-Fixture $G ADMIN-006 $F known-bad FAIL 'High stale-login rate (>20%)' @{ Errors=@{}; Users=@(@{ suspended=$false; lastLoginTime=$null; primaryEmail='stale@e.com' }) }
New-Fixture $G ADMIN-006 $F throttled SKIP 'User data not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }
New-Fixture $G ADMIN-008 $F clean PASS 'Domain shared contacts not exposed in directory' (Cip 'directory.workspace_resource_type_visibility' @{ domainSharedContacts=$false })
New-Fixture $G ADMIN-008 $F known-bad WARN 'Domain shared contacts exposed in directory' (Cip 'directory.workspace_resource_type_visibility' @{ domainSharedContacts=$true })
New-Fixture $G ADMIN-008 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G ADMIN-011 $F clean PASS 'Group creation restricted to admins' (Cip 'groups_for_business.groups_sharing' @{ createGroupsAccessLevel='ADMIN_ONLY' })
New-Fixture $G ADMIN-011 $F known-bad FAIL 'Group creation open to anyone' (Cip 'groups_for_business.groups_sharing' @{ createGroupsAccessLevel='ANYONE_CAN_CREATE' })
New-Fixture $G ADMIN-011 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G ADMIN-012 $F clean PASS 'Groups for Business disabled' (Cip 'groups_for_business.service_status' @{ serviceState='DISABLED' })
New-Fixture $G ADMIN-012 $F known-bad WARN 'Groups for Business enabled' (Cip 'groups_for_business.service_status' @{ serviceState='ENABLED' })
New-Fixture $G ADMIN-012 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G ADMIN-014 $F clean PASS 'Access Approvals required' (Cip 'access_approval.axa_user_scoping' @{ requiresCustomerApproval=$true })
New-Fixture $G ADMIN-014 $F known-bad WARN 'Access Approvals not required' (Cip 'access_approval.axa_user_scoping' @{ requiresCustomerApproval=$false })
New-Fixture $G ADMIN-014 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G ADMIN-015 $F clean PASS 'Support access restricted to U.S. Google staff' (Cip 'access_management.user_scoping' @{ allowedAudience='US_GOOGLE_STAFF' })
New-Fixture $G ADMIN-015 $F known-bad WARN 'Support access allows non-U.S. staff' (Cip 'access_management.user_scoping' @{ allowedAudience='EU_GOOGLE_STAFF' })
New-Fixture $G ADMIN-015 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G ADMIN-016 $F clean PASS 'Data processing limited to storage region' (Cip 'data_regions.data_processing_region' @{ limitToStorageRegion=$true })
New-Fixture $G ADMIN-016 $F known-bad WARN 'Data processing not region-limited' (Cip 'data_regions.data_processing_region' @{ limitToStorageRegion=$false })
New-Fixture $G ADMIN-016 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# ── Collaboration ──
New-Fixture $G COLLAB-001 $F clean PASS 'Automatic Meet recording disabled' (Cip 'meet.automatic_recording' @{ enabled=$false })
New-Fixture $G COLLAB-001 $F known-bad FAIL 'Automatic Meet recording enabled' (Cip 'meet.automatic_recording' @{ enabled=$true })
New-Fixture $G COLLAB-001 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G COLLAB-002 $F clean PASS 'Meet join audience restricted to trusted' (Cip 'meet.meet_joining' @{ allowedAudience='TRUSTED' })
New-Fixture $G COLLAB-002 $F known-bad FAIL 'Meet permits an unrestricted audience' (Cip 'meet.meet_joining' @{ allowedAudience='ALL' })
New-Fixture $G COLLAB-002 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G COLLAB-003 $F clean PASS 'Meet requires signed-in users' (Cip 'meet.safety_domain' @{ usersAllowedToJoin='LOGGED_IN' })
New-Fixture $G COLLAB-003 $F known-bad FAIL 'Meet permits anonymous join' (Cip 'meet.safety_domain' @{ usersAllowedToJoin='ANONYMOUS' })
New-Fixture $G COLLAB-003 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G COLLAB-005 $F clean PASS 'Chat history on by default' (Cip 'chat.chat_history' @{ historyOnByDefault=$true })
New-Fixture $G COLLAB-005 $F known-bad FAIL 'Chat history off by default' (Cip 'chat.chat_history' @{ historyOnByDefault=$false })
New-Fixture $G COLLAB-005 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G COLLAB-006 $F clean PASS 'External Chat spaces disabled' (Cip 'chat.chat_external_spaces' @{ enabled=$false })
New-Fixture $G COLLAB-006 $F known-bad FAIL 'External Chat spaces enabled' (Cip 'chat.chat_external_spaces' @{ enabled=$true })
New-Fixture $G COLLAB-006 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G COLLAB-009 $F always-warn WARN 'Calendar external invitation warning requires manual verification' @{ Errors=@{} }
New-Fixture $G COLLAB-012 $F clean PASS 'Meet host management enabled' (Cip 'meet.safety_host_management' @{ enableHostManagement=$true })
New-Fixture $G COLLAB-012 $F known-bad WARN 'Meet host management disabled' (Cip 'meet.safety_host_management' @{ enableHostManagement=$false })
New-Fixture $G COLLAB-012 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# ── Drive ──
New-Fixture $G DRIVE-004 $F clean PASS 'Shared Drive creation restricted' (Cip 'drive_and_docs.shared_drive_creation' @{ allowSharedDriveCreation=$false })
New-Fixture $G DRIVE-004 $F known-bad WARN 'Shared Drive creation unrestricted' (Cip 'drive_and_docs.shared_drive_creation' @{ allowSharedDriveCreation=$true })
New-Fixture $G DRIVE-004 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G DRIVE-005 $F always-warn WARN 'Shared Drive member management requires manual verification' @{ Errors=@{} }
New-Fixture $G DRIVE-007 $F always-warn WARN 'File ownership transfer requires manual verification' @{ Errors=@{} }
# DRIVE-008 reads OrgUnitPolicies (indexed) AND CloudIdentityPolicies (resolver); provide both.
New-Fixture $G DRIVE-008 $F clean PASS 'Drive for Desktop disabled' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{} }; CloudIdentityPolicies=@{ ByType=@{ 'drive_and_docs.drive_for_desktop'=@(@{ setting=@{ value=@{ allowDriveForDesktop=$false } } }) } } }
New-Fixture $G DRIVE-008 $F known-bad WARN 'Drive for Desktop enabled without device restriction' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{} }; CloudIdentityPolicies=@{ ByType=@{ 'drive_and_docs.drive_for_desktop'=@(@{ setting=@{ value=@{ allowDriveForDesktop=$true; restrictToAuthorizedDevices=$false } } }) } } }
New-Fixture $G DRIVE-008 $F no-data SKIP 'Cloud Identity policy API unavailable' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{} }; CloudIdentityPolicies=$null }
New-Fixture $G DRIVE-010 $F clean PASS 'An active Drive DLP rule is configured' (Cip 'rule.dlp' @{ state='ACTIVE'; action=@{ driveAction=@{} } })
New-Fixture $G DRIVE-010 $F known-bad WARN 'No active Drive-scoped DLP rule' (Cip 'rule.dlp' @{ state='ACTIVE'; action=@{ gmailAction=@{} } })
New-Fixture $G DRIVE-010 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G DRIVE-011 $F always-warn WARN 'Target audience settings require manual verification' @{ Errors=@{} }
New-Fixture $G DRIVE-013 $F clean PASS 'Drive offline access disabled' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ driveOfflineEnabled=$false } } }
New-Fixture $G DRIVE-013 $F known-bad WARN 'Drive offline access enabled' @{ Errors=@{}; OrgUnitPolicies=@{ '/'=@{ driveOfflineEnabled=$true } } }
New-Fixture $G DRIVE-013 $F throttled SKIP 'Org-unit policy not assessed' @{ Errors=@{ OrgUnits='collector error' } }

# ── Email ──
New-Fixture $G EMAIL-004 $F clean PASS 'MTA-STS valid for all domains' @{ Errors=@{}; DnsRecords=@{ 'example.com'=@{ MTASTS=@{ Valid=$true } } } }
New-Fixture $G EMAIL-004 $F known-bad WARN 'A domain lacks valid MTA-STS' @{ Errors=@{}; DnsRecords=@{ 'example.com'=@{ MTASTS=@{ Valid=$false; Details='Not found' } } } }
New-Fixture $G EMAIL-004 $F throttled SKIP 'DNS record collection failed' @{ Errors=@{ 'DnsRecords:example.com'='SERVFAIL' }; DnsRecords=$null }
New-Fixture $G EMAIL-006 $F always-warn WARN 'Allow/block list entries require manual review' @{ Errors=@{} }
New-Fixture $G EMAIL-007 $F always-warn WARN 'Inbound gateway requires manual verification' @{ Errors=@{} }
New-Fixture $G EMAIL-008 $F always-warn WARN 'Email routing rules require manual review' @{ Errors=@{} }
New-Fixture $G EMAIL-010 $F clean PASS 'No send-as aliases configured' @{ Errors=@{}; GmailSettings=@{ 'u@e.com'=@{ sendAs=@() } } }
New-Fixture $G EMAIL-010 $F known-bad WARN 'A user has a send-as alias (review delegate)' @{ Errors=@{}; GmailSettings=@{ 'u@e.com'=@{ sendAs=@(@{ sendAsEmail='delegate@e.com' }) } } }
New-Fixture $G EMAIL-010 $F throttled SKIP 'Per-user Gmail settings not assessed' @{ Errors=@{ 'GmailSettings:u@e.com'='403' }; GmailSettings=$null }
New-Fixture $G EMAIL-014 $F always-warn WARN 'External recipient warning requires manual verification' @{ Errors=@{} }
New-Fixture $G EMAIL-018 $F clean PASS 'Content compliance rules configured' (Cip 'gmail.content_compliance' @{ contentComplianceRules=@(@{ ruleName='r1' }) })
New-Fixture $G EMAIL-018 $F known-bad WARN 'No content compliance rules configured' (Cip 'gmail.content_compliance' @{ contentComplianceRules=@() })
New-Fixture $G EMAIL-018 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G EMAIL-019 $F clean PASS 'An active Gmail DLP rule is configured' (Cip 'rule.dlp' @{ state='ACTIVE'; action=@{ gmailAction=@{ action='REJECT' } } })
New-Fixture $G EMAIL-019 $F known-bad WARN 'No active Gmail DLP rule (rule inactive)' (Cip 'rule.dlp' @{ state='INACTIVE'; action=@{ gmailAction=@{ action='REJECT' } } })
New-Fixture $G EMAIL-019 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# ── Google tradecraft ──
New-Fixture $G GTRADE-003 $F clean PASS 'No groups allow open join / external members' @{ Errors=@{}; GroupSettings=@{ 'g@e.com'=@{ email='g@e.com'; whoCanJoin='CAN_REQUEST_TO_JOIN'; allowExternalMembers='false' } } }
New-Fixture $G GTRADE-003 $F known-bad WARN 'A group allows anyone to join' @{ Errors=@{}; GroupSettings=@{ 'g@e.com'=@{ email='g@e.com'; whoCanJoin='ANYONE_CAN_JOIN'; allowExternalMembers='false' } } }
New-Fixture $G GTRADE-003 $F throttled SKIP 'Group settings not collected' @{ Errors=@{ GroupSettings='collector error' } }
New-Fixture $G GTRADE-004 $F clean PASS 'Four or fewer super admins' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; primaryEmail='a1@e.com' },@{ isAdmin=$false; suspended=$false; primaryEmail='u@e.com' }) }
New-Fixture $G GTRADE-004 $F known-bad FAIL 'Excessive super admins (>10)' @{ Errors=@{}; Users=@(1..12 | ForEach-Object { @{ isAdmin=$true; suspended=$false; primaryEmail="a$_@e.com" } }) }
New-Fixture $G GTRADE-004 $F throttled SKIP 'User data not assessed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }
New-Fixture $G GTRADE-005 $F clean PASS 'No custom role carries super-admin-equivalent privileges' @{ Errors=@{}; Roles=@(@{ isSystemRole=$false; isSuperAdminRole=$false; roleName='Reader'; rolePrivileges=@(@{ privilegeName='USERS_RETRIEVE' }) }) }
New-Fixture $G GTRADE-005 $F known-bad WARN 'A custom role carries write/admin privileges' @{ Errors=@{}; Roles=@(@{ isSystemRole=$false; isSuperAdminRole=$false; roleName='OverReach'; rolePrivileges=@(@{ privilegeName='USERS_CREATE' }) }) }
New-Fixture $G GTRADE-005 $F throttled SKIP 'Role data not assessed' @{ Errors=@{ Roles='collector error' } }

# ── Device / Logging / OAuth ──
New-Fixture $G DEVICE-007 $F clean PASS 'Chrome policies configured' @{ Errors=@{}; ChromePolicies=@(@{ name='BlockedHosts'; value='blocked.com' }) }
New-Fixture $G DEVICE-007 $F known-bad WARN 'No Chrome policies configured' @{ Errors=@{}; ChromePolicies=$null }
New-Fixture $G DEVICE-007 $F throttled SKIP 'Chrome policy not assessed' @{ Errors=@{ ChromePolicies='collector error' } }
New-Fixture $G DEVICE-009 $F clean PASS 'Chrome OS device inventory (informational)' @{ Errors=@{}; ChromeDevices=@(@{ status='ACTIVE'; serialNumber='ABC123' }) }
New-Fixture $G DEVICE-009 $F throttled SKIP 'Chrome device data not assessed' @{ Errors=@{ ChromeDevices='collector error' } }
New-Fixture $G DEVICE-010 $F always-warn WARN 'Device setting not exposed via API (manual)' @{ Errors=@{} }
New-Fixture $G LOG-003 $F clean PASS 'Alert rules cover all audit domains' @{ Errors=@{}; AlertRules=@(@{ name='Login'; source='login_audit' },@{ name='Drive'; source='drive' },@{ name='Admin'; source='admin_audit' },@{ name='Email'; source='email' },@{ name='OAuth'; source='oauth' }) }
New-Fixture $G LOG-003 $F known-bad FAIL 'Alert rules leave most audit domains uncovered (>2)' @{ Errors=@{}; AlertRules=@(@{ name='Login'; source='login_audit' }) }
New-Fixture $G LOG-003 $F throttled SKIP 'Alert rules not assessed' @{ Errors=@{ AlertRules='collector error' } }
New-Fixture $G LOG-004 $F clean PASS 'Cloud data sharing disabled' (Cip 'cloud_sharing_options.cloud_data_sharing' @{ sharingOptions='DISABLED' })
New-Fixture $G LOG-004 $F known-bad FAIL 'Cloud data sharing enabled' (Cip 'cloud_sharing_options.cloud_data_sharing' @{ sharingOptions='ENABLED' })
New-Fixture $G LOG-004 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G LOG-005 $F clean PASS 'A system-defined alert is active' (Cip 'rule.system_defined_alerts' @{ displayName='Suspicious login'; state='ACTIVE' })
New-Fixture $G LOG-005 $F known-bad WARN 'System-defined alert inactive (medium severity => WARN)' (Cip 'rule.system_defined_alerts' @{ displayName='Suspicious login'; state='INACTIVE' })
New-Fixture $G LOG-005 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G OAUTH-006 $F clean PASS 'App approval workflow enabled' (Cip 'api_controls.app_approval_requests' @{ allowedForAll=$true })
New-Fixture $G OAUTH-006 $F known-bad WARN 'App approval workflow not enabled' (Cip 'api_controls.app_approval_requests' @{ allowedForAll=$false })
New-Fixture $G OAUTH-006 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G OAUTH-007 $F clean PASS 'Marketplace apps restricted to an allow-list' (Cip 'workspace_marketplace.apps_access_options' @{ accessLevel='ALLOW_LISTED_APPS' })
New-Fixture $G OAUTH-007 $F known-bad FAIL 'Marketplace allows all apps' (Cip 'workspace_marketplace.apps_access_options' @{ accessLevel='ALLOW_ALL_APPS' })
New-Fixture $G OAUTH-007 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip

# ── GWS service checks (Classroom / Gemini) ──
New-Fixture $G GWS-CLASS-001 $F clean PASS 'Class membership restricted to the domain' (Cip 'classroom.class_membership' @{ whoCanJoinClasses='ANYONE_IN_DOMAIN' })
New-Fixture $G GWS-CLASS-001 $F known-bad FAIL 'Class membership open beyond the domain' (Cip 'classroom.class_membership' @{ whoCanJoinClasses='ANY_GOOGLE_WORKSPACE_USER' })
New-Fixture $G GWS-CLASS-001 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G GWS-CLASS-002 $F clean PASS 'Users may join only in-domain classes' (Cip 'classroom.class_membership' @{ whichClassesCanUsersJoin='CLASSES_IN_DOMAIN' })
New-Fixture $G GWS-CLASS-002 $F known-bad FAIL 'Users may join any Workspace class' (Cip 'classroom.class_membership' @{ whichClassesCanUsersJoin='ANY_GOOGLE_WORKSPACE_CLASS' })
New-Fixture $G GWS-CLASS-002 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G GWS-CLASS-003 $F clean PASS 'Classroom API data access disabled' (Cip 'classroom.api_data_access' @{ enableApiAccess=$false })
New-Fixture $G GWS-CLASS-003 $F known-bad FAIL 'Classroom API data access enabled' (Cip 'classroom.api_data_access' @{ enableApiAccess=$true })
New-Fixture $G GWS-CLASS-003 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G GWS-CLASS-006 $F clean PASS 'Only verified teachers can create classes' (Cip 'classroom.teacher_permissions' @{ whoCanCreateClasses='VERIFIED_TEACHERS_ONLY' })
New-Fixture $G GWS-CLASS-006 $F known-bad FAIL 'Anyone in the domain can create classes' (Cip 'classroom.teacher_permissions' @{ whoCanCreateClasses='ANYONE_IN_DOMAIN' })
New-Fixture $G GWS-CLASS-006 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G GWS-GEMINI-001 $F clean PASS 'Gemini app service disabled' (Cip 'gemini_app.service_status' @{ serviceState='DISABLED' })
New-Fixture $G GWS-GEMINI-001 $F known-bad WARN 'Gemini app enabled (license gating not verifiable)' (Cip 'gemini_app.service_status' @{ serviceState='ENABLED' })
New-Fixture $G GWS-GEMINI-001 $F no-data SKIP 'Cloud Identity policy API unavailable' $skCip
New-Fixture $G GWS-GEMINI-005 $F not-implemented SKIP 'Gemini conversation-sharing not exposed via API' @{ Errors=@{} }

Write-Host "`nDone (medium round 4)."
