#requires -version 7.0
<#
    Medium-tier fixtures, Round 2: Entra ID / Azure (32 checks).
    AZIAM/EIDAPP/EIDAUTH/EIDCA/EIDFED/EIDPIM/EIDTNT. Synthetic data only.
    Re-run: pwsh Tests/Fixtures/_generate-fixtures-medium-2.ps1

    Excluded: EIDPIM-009 (broken — undefined $privilegedUsers; EIDPIM fix task).
    Always-SKIP placeholders: EIDPIM-014, EIDAPP-018, EIDFED-006, EIDAUTH-012, EIDCA-017.
    Always-WARN: EIDAUTH-017. Always-PASS inventory: AZIAM-003.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Theater,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; theater=$Theater; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 16 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$I='Infiltration'
$skCA =@{ Errors=@{ ConditionalAccess='Graph 429' }; ConditionalAccess=@{ Errors=@{}; Policies=$null } }
$skAM =@{ Errors=@{ AuthMethods='Graph 429' }; AuthMethods=@{ Errors=@{} } }
$skTen=@{ Errors=@{ TenantConfig='Graph 429' }; TenantConfig=@{ Errors=@{} } }
$skAz =@{ Errors=@{}; AzureIAM=$null }
$past='2020-01-01T00:00:00Z'; $recent='2026-06-01T00:00:00Z'
$rscope='/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1'

# ── Azure IAM ──
New-Fixture Entra AZIAM-002 $I clean PASS 'No direct resource-level role assignments' @{ Errors=@{}; AzureIAM=@{ RoleAssignments=@(); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-002 $I known-bad WARN 'A few direct resource-level role assignments (1-10)' @{ Errors=@{}; AzureIAM=@{ RoleAssignments=@(@{ properties=@{ scope=$rscope; principalId='p1'; roleDefinitionId='r1' } },@{ properties=@{ scope=$rscope; principalId='p2'; roleDefinitionId='r2' } }); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-002 $I no-data SKIP 'Azure IAM not available' $skAz
New-Fixture Entra AZIAM-003 $I clean PASS 'Resource-group assignment inventory (informational)' @{ Errors=@{}; AzureIAM=@{ RoleAssignments=@(); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-003 $I no-data SKIP 'Azure IAM not available' $skAz
New-Fixture Entra AZIAM-007 $I clean PASS 'No non-compliant Azure Policy resources' @{ Errors=@{}; AzureIAM=@{ PolicyStates=@(@{ Summary=@{ results=@{ nonCompliantResources=0; totalResources=100 } } }); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-007 $I known-bad FAIL 'High Azure Policy non-compliance (>10%)' @{ Errors=@{}; AzureIAM=@{ PolicyStates=@(@{ Summary=@{ results=@{ nonCompliantResources=50; totalResources=100 } } }); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-007 $I no-data SKIP 'Azure IAM not available' $skAz
New-Fixture Entra AZIAM-009 $I clean PASS 'No custom RBAC roles with wildcard actions' @{ Errors=@{}; AzureIAM=@{ RoleDefinitions=@(); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-009 $I known-bad WARN 'A custom RBAC role uses wildcard actions' @{ Errors=@{}; AzureIAM=@{ RoleDefinitions=@(@{ id='r1'; properties=@{ roleName='Custom'; permissions=@(@{ actions=@('*') }) } }); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-009 $I no-data SKIP 'Azure IAM not available' $skAz
New-Fixture Entra AZIAM-010 $I clean PASS 'Resource locks deployed' @{ Errors=@{}; AzureIAM=@{ ResourceLocks=@(@{ id='l1'; properties=@{ level='CanNotDelete' } }); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-010 $I known-bad WARN 'No resource locks deployed' @{ Errors=@{}; AzureIAM=@{ ResourceLocks=@(); Subscriptions=@(@{ id='sub1' }) } }
New-Fixture Entra AZIAM-010 $I no-data SKIP 'Azure IAM not available' $skAz

# ── Entra PIM (009 broken/excluded) ──
New-Fixture Entra EIDPIM-014 $I not-implemented SKIP 'PIM notification settings need beta PIM policy endpoints' @{ Errors=@{}; PIM=@{} }

# ── Entra Tenant ──
New-Fixture Entra EIDTNT-004 $I clean PASS 'Guest invitations restricted (none)' @{ Errors=@{}; TenantConfig=@{ AuthorizationPolicy=@{ allowInvitesFrom='none' } } }
New-Fixture Entra EIDTNT-004 $I known-bad FAIL 'Anyone (incl guests) can invite' @{ Errors=@{}; TenantConfig=@{ AuthorizationPolicy=@{ allowInvitesFrom='everyone' } } }
New-Fixture Entra EIDTNT-004 $I no-data SKIP 'Authorization policy not available' @{ Errors=@{}; TenantConfig=@{ AuthorizationPolicy=$null } }
New-Fixture Entra EIDTNT-013 $I clean PASS 'Notification contacts configured' @{ Errors=@{}; TenantConfig=@{ Organization=@{ technicalNotificationMails=@('tech@c.com'); securityComplianceNotificationMails=@(); privacyProfile=$null } } }
New-Fixture Entra EIDTNT-013 $I known-bad WARN 'No technical/security notification contacts' @{ Errors=@{}; TenantConfig=@{ Organization=@{ technicalNotificationMails=@(); securityComplianceNotificationMails=@(); privacyProfile=$null } } }
New-Fixture Entra EIDTNT-013 $I no-data SKIP 'Organization data not available' @{ Errors=@{}; TenantConfig=@{ Organization=$null } }

# ── Entra Apps ──
New-Fixture Entra EIDAPP-008 $I clean PASS 'No expired/expiring app credentials' @{ Errors=@{}; Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='A1'; passwordCredentials=@(); keyCredentials=@() }) } }
New-Fixture Entra EIDAPP-008 $I known-bad FAIL 'An app credential is already expired' @{ Errors=@{}; Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='A1'; passwordCredentials=@(@{ endDateTime=$past; keyId='k1' }); keyCredentials=@() }) } }
New-Fixture Entra EIDAPP-008 $I no-data SKIP 'App registrations unavailable' @{ Errors=@{}; Applications=@{ AppRegistrations=@() } }
New-Fixture Entra EIDAPP-009 $I clean PASS 'No stale service principals' @{ Errors=@{}; Applications=@{ ServicePrincipals=@(@{ id='sp1'; appId='a1'; displayName='SP1'; signInActivity=@{ lastSignInDateTime=$recent } }) } }
New-Fixture Entra EIDAPP-009 $I known-bad WARN 'A service principal is stale (>90 days)' @{ Errors=@{}; Applications=@{ ServicePrincipals=@(@{ id='sp1'; appId='a1'; displayName='SP1'; signInActivity=@{ lastSignInDateTime=$past } }) } }
New-Fixture Entra EIDAPP-009 $I no-data SKIP 'Service principals unavailable' @{ Errors=@{}; Applications=@{ ServicePrincipals=@() } }
New-Fixture Entra EIDAPP-010 $I clean PASS 'No multi-tenant app registrations' @{ Errors=@{}; Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='A1'; signInAudience='AzureADMyOrg'; createdDateTime='2025-01-01T00:00:00Z' }) } }
New-Fixture Entra EIDAPP-010 $I known-bad WARN 'A multi-tenant app registration exists' @{ Errors=@{}; Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='A1'; signInAudience='AzureADMultipleOrgs'; createdDateTime='2025-01-01T00:00:00Z' }) } }
New-Fixture Entra EIDAPP-010 $I no-data SKIP 'App registrations unavailable' @{ Errors=@{}; Applications=@{ AppRegistrations=@() } }
New-Fixture Entra EIDAPP-013 $I clean PASS 'Admin consent workflow enabled with reviewers' @{ Errors=@{}; TenantConfig=@{ Errors=@{}; AdminConsentRequestPolicy=@{ isEnabled=$true; reviewers=@(@{ query='group:admin'; queryType='directoryObject'; queryRoot='' }); requestExpiresInDays=30; notificationsEnabled=$true; remindersEnabled=$true } } }
New-Fixture Entra EIDAPP-013 $I known-bad FAIL 'Admin consent workflow disabled' @{ Errors=@{}; TenantConfig=@{ Errors=@{}; AdminConsentRequestPolicy=@{ isEnabled=$false } } }
New-Fixture Entra EIDAPP-013 $I throttled SKIP 'Admin consent request policy not assessed' $skTen
New-Fixture Entra EIDAPP-018 $I not-implemented SKIP 'App credential-add audit requires audit log data (not collected)' @{ Errors=@{}; Applications=@{} }
New-Fixture Entra EIDAPP-020 $I clean PASS 'Group-specific consent disabled' @{ Errors=@{}; AuthMethods=@{ DirectorySettings=@(@{ displayName='Group.Unified'; templateId='62375ab9-6b52-47ed-826b-58e47e0e304b'; values=@(@{ name='EnableGroupSpecificConsent'; value='false' }) }) } }
New-Fixture Entra EIDAPP-020 $I known-bad FAIL 'Group-specific consent enabled' @{ Errors=@{}; AuthMethods=@{ DirectorySettings=@(@{ displayName='Group.Unified'; templateId='62375ab9-6b52-47ed-826b-58e47e0e304b'; values=@(@{ name='EnableGroupSpecificConsent'; value='true' }) }) } }
New-Fixture Entra EIDAPP-020 $I no-data SKIP 'Directory settings unavailable' @{ Errors=@{}; AuthMethods=@{ DirectorySettings=@() } }

# ── Entra Federation ──
New-Fixture Entra EIDFED-006 $I not-implemented SKIP 'AAD Connect sync scope needs connector config (not via Graph)' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=$null } }
New-Fixture Entra EIDFED-007 $I clean PASS 'Password hash sync enabled' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=@{ features=@{ passwordHashSyncEnabled=$true } } } }
New-Fixture Entra EIDFED-007 $I known-bad FAIL 'Password hash sync disabled' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=@{ features=@{ passwordHashSyncEnabled=$false } } } }
New-Fixture Entra EIDFED-007 $I no-data SKIP 'Sync settings not available' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=$null } }
New-Fixture Entra EIDFED-008 $I clean PASS 'Pass-through authentication not enabled' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=@{ features=@{ passThroughAuthenticationEnabled=$false } } } }
New-Fixture Entra EIDFED-008 $I known-bad WARN 'Pass-through authentication enabled (review agents)' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=@{ features=@{ passThroughAuthenticationEnabled=$true } } } }
New-Fixture Entra EIDFED-008 $I no-data SKIP 'Sync settings not available' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=$null } }
New-Fixture Entra EIDFED-010 $I clean PASS 'No federated domains (extranet lockout N/A)' @{ Errors=@{}; Federation=@{ FederationConfigs=@() } }
New-Fixture Entra EIDFED-010 $I known-bad WARN 'A federated domain present (verify AD FS extranet lockout)' @{ Errors=@{}; Federation=@{ FederationConfigs=@(@{ DomainName='example.com' }) } }
New-Fixture Entra EIDFED-011 $I clean PASS 'Device writeback enabled' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=@{ features=@{ deviceWritebackEnabled=$true } } } }
New-Fixture Entra EIDFED-011 $I known-bad WARN 'Device writeback not enabled' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=@{ features=@{ deviceWritebackEnabled=$false } } } }
New-Fixture Entra EIDFED-011 $I no-data SKIP 'Sync settings not available' @{ Errors=@{}; Federation=@{ OnPremisesSyncSettings=$null } }

# ── Entra Auth ──
New-Fixture Entra EIDAUTH-008 $I clean PASS 'Most users are passwordless-capable (>=80%)' @{ Errors=@{}; AuthMethods=@{ UserRegistrationDetails=@(@{ isPasswordlessCapable=$true; methodsRegistered=@() },@{ isPasswordlessCapable=$true; methodsRegistered=@() },@{ isPasswordlessCapable=$true; methodsRegistered=@() },@{ isPasswordlessCapable=$true; methodsRegistered=@() }) } }
New-Fixture Entra EIDAUTH-008 $I known-bad FAIL 'Few users passwordless-capable (<30%)' @{ Errors=@{}; AuthMethods=@{ UserRegistrationDetails=@(@{ isPasswordlessCapable=$false; methodsRegistered=@() },@{ isPasswordlessCapable=$false; methodsRegistered=@() },@{ isPasswordlessCapable=$false; methodsRegistered=@() }) } }
New-Fixture Entra EIDAUTH-008 $I no-data SKIP 'User registration details unavailable' @{ Errors=@{}; AuthMethods=@{ UserRegistrationDetails=@() } }
New-Fixture Entra EIDAUTH-009 $I clean PASS 'Windows Hello for Business enabled' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; MethodConfigurations=@(@{ id='windowsHelloForBusiness'; state='enabled'; '@odata.type'='microsoft.graph.windowsHelloForBusinessAuthenticationMethod' }) } }
New-Fixture Entra EIDAUTH-009 $I known-bad WARN 'Windows Hello for Business not enabled' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; MethodConfigurations=@(@{ id='windowsHelloForBusiness'; state='disabled' }) } }
New-Fixture Entra EIDAUTH-009 $I throttled SKIP 'Auth method configs not assessed' $skAM
New-Fixture Entra EIDAUTH-010 $I clean PASS 'Temporary Access Pass not configured' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; MethodConfigurations=@() } }
New-Fixture Entra EIDAUTH-010 $I known-bad FAIL 'TAP enabled but reusable (not one-time)' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; MethodConfigurations=@(@{ id='TemporaryAccessPass'; state='enabled'; isUsableOnce=$false; maximumLifetimeInMinutes=120 }) } }
New-Fixture Entra EIDAUTH-010 $I throttled SKIP 'Auth method configs not assessed' $skAM
New-Fixture Entra EIDAUTH-012 $I not-implemented SKIP 'SSPR method config needs additional data collection' @{ Errors=@{}; AuthMethods=@{} }
New-Fixture Entra EIDAUTH-014 $I clean PASS 'Custom banned password list configured' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; DirectorySettings=@(@{ displayName='Password Rule Settings'; templateId='5cf42378-d67d-4f36-ba46-e8b86229381d'; values=@(@{ name='BannedPasswordList'; value='password1,password2' }) }) } }
New-Fixture Entra EIDAUTH-014 $I known-bad FAIL 'Custom banned password list empty' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; DirectorySettings=@(@{ displayName='Password Rule Settings'; templateId='5cf42378-d67d-4f36-ba46-e8b86229381d'; values=@(@{ name='BannedPasswordList'; value='' }) }) } }
New-Fixture Entra EIDAUTH-014 $I throttled SKIP 'Auth method configs not assessed' $skAM
New-Fixture Entra EIDAUTH-017 $I always-warn WARN 'CA-based vs per-user MFA conflict check (informational)' @{ Errors=@{}; ConditionalAccess=@{ Policies=@(@{ state='enabled'; grantControls=@{ builtInControls=@('mfa') } }) } }
New-Fixture Entra EIDAUTH-018 $I clean PASS 'Authenticator shows app + location in notifications' @{ Errors=@{}; AuthMethods=@{ MethodConfigurations=@(@{ id='MicrosoftAuthenticator'; state='enabled'; featureSettings=@{ displayAppInformationRequiredState=@{ state='enabled' }; displayLocationInformationRequiredState=@{ state='enabled' } }; '@odata.type'='microsoft.graph.microsoftAuthenticatorAuthenticationMethod' }) } }
New-Fixture Entra EIDAUTH-018 $I known-bad FAIL 'Authenticator does not show app name in notifications' @{ Errors=@{}; AuthMethods=@{ MethodConfigurations=@(@{ id='MicrosoftAuthenticator'; state='enabled'; featureSettings=@{ displayAppInformationRequiredState=@{ state='disabled' }; displayLocationInformationRequiredState=@{ state='disabled' } }; '@odata.type'='microsoft.graph.microsoftAuthenticatorAuthenticationMethod' }) } }
New-Fixture Entra EIDAUTH-018 $I no-data SKIP 'Auth method configs not available' @{ Errors=@{}; AuthMethods=@{ MethodConfigurations=@() } }

# ── Entra Conditional Access ──
New-Fixture Entra EIDCA-003 $I clean PASS 'No CA policies stuck in report-only' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='P1'; state='enabled'; createdDateTime='2025-01-01T00:00:00Z' }) } }
New-Fixture Entra EIDCA-003 $I known-bad FAIL 'Three CA policies stuck in report-only' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='R1'; state='enabledForReportingButNotEnforced'; createdDateTime='2025-01-01T00:00:00Z' },@{ id='p2'; displayName='R2'; state='enabledForReportingButNotEnforced'; createdDateTime='2025-01-01T00:00:00Z' },@{ id='p3'; displayName='R3'; state='enabledForReportingButNotEnforced'; createdDateTime='2025-01-01T00:00:00Z' }) } }
New-Fixture Entra EIDCA-003 $I throttled SKIP 'Conditional Access not assessed' $skCA
New-Fixture Entra EIDCA-010 $I clean PASS 'Location-based CA policy present' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='Loc'; state='enabled'; conditions=@{ locations=@{ includeLocations=@('00000000-0000-0000-0000-000000000000'); excludeLocations=@() } } }) } }
New-Fixture Entra EIDCA-010 $I known-bad WARN 'No location-based CA policies' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='NoLoc'; state='enabled'; conditions=@{ locations=$null } }) } }
New-Fixture Entra EIDCA-010 $I throttled SKIP 'Conditional Access not assessed' $skCA
New-Fixture Entra EIDCA-011 $I clean PASS 'Named locations configured' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; NamedLocations=@(@{ id='l1'; displayName='Office IP'; '@odata.type'='#microsoft.graph.ipNamedLocation'; isTrusted=$true }) } }
New-Fixture Entra EIDCA-011 $I known-bad WARN 'No named locations configured' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; NamedLocations=@() } }
New-Fixture Entra EIDCA-011 $I throttled SKIP 'Conditional Access not assessed' @{ Errors=@{ ConditionalAccess='Graph 429' }; ConditionalAccess=@{ Errors=@{}; NamedLocations=$null } }
New-Fixture Entra EIDCA-014 $I clean PASS 'Session-control CA policy present' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='Sess'; state='enabled'; sessionControls=@{ signInFrequency=@{ isEnabled=$true; value=1 }; persistentBrowser=$null; cloudAppSecurity=$null; applicationEnforcedRestrictions=$null } }) } }
New-Fixture Entra EIDCA-014 $I known-bad WARN 'No session-control CA policies' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='NoSess'; state='enabled'; sessionControls=$null }) } }
New-Fixture Entra EIDCA-014 $I throttled SKIP 'Conditional Access not assessed' $skCA
New-Fixture Entra EIDCA-017 $I not-implemented SKIP 'High-risk user notification recipients not readable via Graph' @{ Errors=@{}; RiskDetections=@(); RiskyUsers=@() }
New-Fixture Entra EIDCA-018 $I clean PASS 'Security-info registration requires a managed device' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='Reg'; state='enabled'; conditions=@{ users=@{ includeUsers=@('All') }; applications=@{ includeUserActions=@('registerSecurityInformation') } }; grantControls=@{ builtInControls=@('compliantDevice') } }) } }
New-Fixture Entra EIDCA-018 $I known-bad FAIL 'Security-info registration not device-gated' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ id='p1'; displayName='Reg'; state='enabled'; conditions=@{ users=@{ includeUsers=@('All') }; applications=@{ includeUserActions=@('registerSecurityInformation') } }; grantControls=@{ builtInControls=@('mfa') } }) } }
New-Fixture Entra EIDCA-018 $I no-data SKIP 'No CA policies available' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@() } }

Write-Host "`nDone (medium round 2)."
