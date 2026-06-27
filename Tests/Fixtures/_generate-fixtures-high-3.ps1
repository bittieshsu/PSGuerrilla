#requires -version 7.0
<#
    High-tier fixtures, Round 3: Entra ID / Azure.
    AZIAM / EIDAPP / EIDAUTH / EIDCA / EIDFED / EIDPIM(working) / EIDTNT.
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-high-3.ps1

    Excluded (folded into the EntraPIMChecks fix task — undefined $privilegedUsers):
      EIDPIM-005, EIDPIM-007, EIDPIM-008, EIDPIM-013.
    Degenerate-by-contract, pinned to actual behavior:
      EIDAPP-007 (always SKIP — ARM not collected), EIDFED-004 (always PASS),
      EIDTNT-011/012 (always WARN — manual checks), EIDFED-013 (registry-dependent => SKIP only),
      EIDFED-002 (cert FAIL needs real X.509 => clean PASS via empty configs + SKIP only).
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Theater,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; theater=$Theater; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 14 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$I='Infiltration'
$skCA  =@{ Errors=@{ ConditionalAccess='Graph 429' }; ConditionalAccess=@{ Policies=$null } }
$skFed =@{ Errors=@{ Federation='Graph error' }; Federation=@{ Errors=@{}; FederationConfigs=$null } }
$skPIM =@{ Errors=@{ PIM='Graph error' }; PIM=@{ Errors=@{} } }
$skApp =@{ Errors=@{ Applications='Graph error' }; Applications=@{ Errors=@{} } }
$skAuth=@{ Errors=@{ AuthMethods='Graph error' }; AuthMethods=@{ Errors=@{} } }
$skTnt =@{ Errors=@{ TenantConfig='Graph error' }; TenantConfig=@{ Errors=@{} } }

# ── Azure IAM ──
New-Fixture Entra AZIAM-001 $I clean PASS 'Role-assignment inventory available across subscriptions' @{ AzureIAM=@{ RoleAssignments=@(@{ _subscriptionId='s1'; name='r1' }); Subscriptions=@(@{ id='s1'; name='prod' }); Errors=@{} } }
New-Fixture Entra AZIAM-001 $I no-data SKIP 'Azure IAM data unavailable' @{ AzureIAM=$null }
New-Fixture Entra AZIAM-004 $I clean PASS 'Key Vaults use RBAC + purge protection' @{ AzureIAM=@{ KeyVaults=@(@{ name='v1'; location='eastus'; properties=@{ enableRbacAuthorization=$true; enableSoftDelete=$true; enablePurgeProtection=$true } }); Subscriptions=@(@{ id='s1' }); Errors=@{} } }
New-Fixture Entra AZIAM-004 $I known-bad FAIL 'Key Vault lacks RBAC, soft-delete and purge protection' @{ AzureIAM=@{ KeyVaults=@(@{ name='v1'; location='eastus'; properties=@{ enableRbacAuthorization=$false; enableSoftDelete=$false; enablePurgeProtection=$false } }); Subscriptions=@(@{ id='s1' }); Errors=@{} } }
New-Fixture Entra AZIAM-004 $I no-data SKIP 'Azure IAM data unavailable' @{ AzureIAM=$null }
New-Fixture Entra AZIAM-005 $I clean PASS 'Storage accounts enforce HTTPS, no public blob, TLS1.2' @{ AzureIAM=@{ StorageAccounts=@(@{ name='st1'; properties=@{ supportsHttpsTrafficOnly=$true; allowBlobPublicAccess=$false; minimumTlsVersion='TLS1_2' } }); Subscriptions=@(@{ id='s1' }); Errors=@{} } }
New-Fixture Entra AZIAM-005 $I known-bad FAIL 'Storage account allows HTTP, public blob, TLS1.0 (2+ issues)' @{ AzureIAM=@{ StorageAccounts=@(@{ name='st1'; properties=@{ supportsHttpsTrafficOnly=$false; allowBlobPublicAccess=$true; minimumTlsVersion='TLS1_0' } }); Subscriptions=@(@{ id='s1' }); Errors=@{} } }
New-Fixture Entra AZIAM-005 $I no-data SKIP 'Azure IAM data unavailable' @{ AzureIAM=$null }
New-Fixture Entra AZIAM-006 $I clean PASS 'No permissive inbound NSG rules' @{ AzureIAM=@{ NetworkSecurityGroups=@(@{ name='nsg1'; properties=@{ securityRules=@(@{ name='DenyAll'; properties=@{ access='Deny'; direction='Inbound'; sourceAddressPrefix='*'; destinationPortRange='*'; protocol='*'; priority=65500 } }) } }); Subscriptions=@(@{ id='s1' }); Errors=@{} } }
New-Fixture Entra AZIAM-006 $I known-bad FAIL 'Four any-source any-port inbound Allow rules' @{ AzureIAM=@{ NetworkSecurityGroups=@(@{ name='nsg1'; properties=@{ securityRules=@(
    @{ name='a1'; properties=@{ access='Allow'; direction='Inbound'; sourceAddressPrefix='*'; destinationPortRange='0-65535'; protocol='TCP'; priority=100 } },
    @{ name='a2'; properties=@{ access='Allow'; direction='Inbound'; sourceAddressPrefix='0.0.0.0/0'; destinationPortRange='*'; protocol='*'; priority=101 } },
    @{ name='a3'; properties=@{ access='Allow'; direction='Inbound'; sourceAddressPrefix='Internet'; destinationPortRange='0-65535'; protocol='*'; priority=102 } },
    @{ name='a4'; properties=@{ access='Allow'; direction='Inbound'; sourceAddressPrefix='*'; destinationPortRange='*'; protocol='TCP'; priority=103 } }) } }); Subscriptions=@(@{ id='s1' }); Errors=@{} } }
New-Fixture Entra AZIAM-006 $I no-data SKIP 'Azure IAM data unavailable' @{ AzureIAM=$null }

# ── Entra applications ──
New-Fixture Entra EIDAPP-003 $I clean PASS 'No app registrations hold credentials' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='A1'; passwordCredentials=@(); keyCredentials=@() }) } }
New-Fixture Entra EIDAPP-003 $I known-bad WARN 'An app registration holds a credential (review)' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='A1'; passwordCredentials=@(@{ keyId='c1' }); keyCredentials=@() }) } }
New-Fixture Entra EIDAPP-003 $I no-data SKIP 'App registrations unavailable' @{ Applications=@{ AppRegistrations=@() } }
New-Fixture Entra EIDAPP-006 $I clean PASS 'No excessive consent grants' @{ Applications=@{ ConsentGrants=@(@{ clientId='c1'; scope='User.Read'; consentType='Principal'; resourceId='graph' }) } }
New-Fixture Entra EIDAPP-006 $I known-bad WARN 'A high-privilege consent grant exists' @{ Applications=@{ ConsentGrants=@(@{ clientId='c1'; scope='User.ReadWrite.All'; consentType='AllPrincipals'; resourceId='graph' }) } }
New-Fixture Entra EIDAPP-006 $I no-data SKIP 'Consent grants unavailable' @{ Applications=@{ ConsentGrants=@() } }
New-Fixture Entra EIDAPP-007 $I not-collected SKIP 'ARM role-assignment analysis not available in Entra-only audit' @{ Applications=@{} }
New-Fixture Entra EIDAPP-011 $I clean PASS 'No OAuth2 user-consent grants' @{ Errors=@{}; Applications=@{ Errors=@{}; ConsentGrants=@() } }
New-Fixture Entra EIDAPP-011 $I known-bad WARN 'A user-consented OAuth2 grant exists' @{ Errors=@{}; Applications=@{ Errors=@{}; ConsentGrants=@(@{ clientId='c1'; consentType='Principal'; resourceId='r1'; scope='User.Read' }) } }
New-Fixture Entra EIDAPP-011 $I throttled SKIP 'Applications collection failed' $skApp
New-Fixture Entra EIDAPP-012 $I clean PASS 'User app-consent disabled' @{ TenantConfig=@{ AuthorizationPolicy=@{ permissionGrantPolicyIdsAssignedToDefaultUserRole=@() } } }
New-Fixture Entra EIDAPP-012 $I known-bad FAIL 'Unrestricted legacy user app-consent enabled' @{ TenantConfig=@{ AuthorizationPolicy=@{ permissionGrantPolicyIdsAssignedToDefaultUserRole=@('ManagePermissionGrantsForSelf.microsoft-user-default-legacy') } } }
New-Fixture Entra EIDAPP-012 $I no-data SKIP 'Authorization policy unavailable' @{ TenantConfig=@{ AuthorizationPolicy=$null } }
New-Fixture Entra EIDAPP-015 $I clean PASS 'No read-write OAuth2 permission grants' @{ Errors=@{}; Applications=@{ Errors=@{}; ConsentGrants=@(@{ scope='User.Read Mail.Read' }) } }
New-Fixture Entra EIDAPP-015 $I known-bad WARN 'A read-write OAuth2 grant exists' @{ Errors=@{}; Applications=@{ Errors=@{}; ConsentGrants=@(@{ scope='Mail.ReadWrite' }) } }
New-Fixture Entra EIDAPP-015 $I throttled SKIP 'Applications collection failed' $skApp
New-Fixture Entra EIDAPP-019 $I clean PASS 'No suspicious redirect URIs' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='Safe'; web=@{ redirectUris=@('https://contoso.com/cb') }; spa=@{ redirectUris=@() }; publicClient=@{ redirectUris=@() } }) } }
New-Fixture Entra EIDAPP-019 $I known-bad WARN 'An app has a localhost/http redirect URI' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='Bad'; web=@{ redirectUris=@('http://localhost/auth') }; spa=@{ redirectUris=@() }; publicClient=@{ redirectUris=@() } }) } }
New-Fixture Entra EIDAPP-019 $I no-data SKIP 'App registrations unavailable' @{ Applications=@{ AppRegistrations=@() } }

# ── Entra auth ──
New-Fixture Entra EIDAUTH-004 $I clean PASS 'Users have strong MFA methods' @{ AuthMethods=@{ UserRegistrationDetails=@(@{ isMfaRegistered=$true; methodsRegistered=@('microsoftAuthenticatorPush'); userPrincipalName='u@t'; id='1' }) } }
New-Fixture Entra EIDAUTH-004 $I known-bad WARN 'A user has only weak (SMS/phone) MFA' @{ AuthMethods=@{ UserRegistrationDetails=@(@{ isMfaRegistered=$true; methodsRegistered=@('mobilePhone'); userPrincipalName='u@t'; id='1' }) } }
New-Fixture Entra EIDAUTH-004 $I no-data SKIP 'User registration details unavailable' @{ AuthMethods=@{ UserRegistrationDetails=@() } }
New-Fixture Entra EIDAUTH-011 $I clean PASS 'Self-service password reset enabled' @{ AuthMethods=@{ AuthorizationPolicy=@{ allowedToUseSSPR=$true } } }
New-Fixture Entra EIDAUTH-011 $I known-bad WARN 'Self-service password reset not enabled' @{ AuthMethods=@{ AuthorizationPolicy=@{ allowedToUseSSPR=$false } } }
New-Fixture Entra EIDAUTH-011 $I no-data SKIP 'Authorization policy unavailable' @{ AuthMethods=@{ AuthorizationPolicy=$null } }
New-Fixture Entra EIDAUTH-013 $I clean PASS 'Banned password protection enabled' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; DirectorySettings=@(@{ displayName='Password Rule Settings'; templateId='5cf42378-d67d-4f36-ba46-e8b86229381d'; values=@(@{ name='EnableBannedPasswordCheck'; value='True' }) }) } }
New-Fixture Entra EIDAUTH-013 $I known-bad FAIL 'Banned password protection disabled' @{ Errors=@{}; AuthMethods=@{ Errors=@{}; DirectorySettings=@(@{ displayName='Password Rule Settings'; templateId='5cf42378-d67d-4f36-ba46-e8b86229381d'; values=@(@{ name='EnableBannedPasswordCheck'; value='False' }) }) } }
New-Fixture Entra EIDAUTH-013 $I throttled SKIP 'AuthMethods collection failed' $skAuth
New-Fixture Entra EIDAUTH-015 $I clean PASS 'A CA policy blocks legacy authentication' @{ ConditionalAccess=@{ Policies=@(@{ state='enabled'; conditions=@{ clientAppTypes=@('exchangeActiveSync') }; grantControls=@{ builtInControls=@('block') } }) } }
New-Fixture Entra EIDAUTH-015 $I known-bad FAIL 'No CA policy blocks legacy authentication' @{ ConditionalAccess=@{ Policies=@(@{ state='enabled'; conditions=@{ clientAppTypes=@('browser') }; grantControls=@{ builtInControls=@('mfa') } }) } }
New-Fixture Entra EIDAUTH-015 $I no-data SKIP 'CA policy data unavailable' @{ ConditionalAccess=@{ Policies=@() } }
New-Fixture Entra EIDAUTH-016 $I clean PASS 'No app allows ROPC/public-client flow' @{ Applications=@{ AppRegistrations=@(@{ isFallbackPublicClient=$false; allowPublicClient=$false; appId='a1'; displayName='Safe' }) } }
New-Fixture Entra EIDAUTH-016 $I known-bad WARN 'An app allows public-client (ROPC) flow' @{ Applications=@{ AppRegistrations=@(@{ isFallbackPublicClient=$true; allowPublicClient=$false; appId='a1'; displayName='Ropc' }) } }
New-Fixture Entra EIDAUTH-016 $I no-data SKIP 'App registration data unavailable' @{ Applications=@{ AppRegistrations=$null } }

# ── Entra conditional access ──
New-Fixture Entra EIDCA-002 $I clean PASS 'MFA enforced for all users on all apps' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ users=@{ includeUsers=@('All') }; applications=@{ includeApplications=@('All') } }; grantControls=@{ builtInControls=@('mfa'); authenticationStrength=$null } }) } }
New-Fixture Entra EIDCA-002 $I known-bad FAIL 'No universal MFA coverage (2+ gaps)' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ users=@{ includeUsers=@('SomeGroup') }; applications=@{ includeApplications=@('App1') } }; grantControls=@{ builtInControls=@('block') } }) } }
New-Fixture Entra EIDCA-002 $I throttled SKIP 'ConditionalAccess collection failed' $skCA
New-Fixture Entra EIDCA-004 $I clean PASS 'No group-based CA exclusions' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; displayName='P1'; conditions=@{ users=@{ excludeGroups=@() } } }) } }
New-Fixture Entra EIDCA-004 $I known-bad FAIL 'A group is excluded from 3+ CA policies' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(
    @{ state='enabled'; displayName='P1'; conditions=@{ users=@{ excludeGroups=@('g-123') } } },
    @{ state='enabled'; displayName='P2'; conditions=@{ users=@{ excludeGroups=@('g-123') } } },
    @{ state='enabled'; displayName='P3'; conditions=@{ users=@{ excludeGroups=@('g-123') } } }) } }
New-Fixture Entra EIDCA-004 $I throttled SKIP 'ConditionalAccess collection failed' $skCA
New-Fixture Entra EIDCA-005 $I clean PASS 'No CA exclusion groups to review' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ users=@{ excludeGroups=@() } } }) } }
New-Fixture Entra EIDCA-005 $I known-bad WARN 'CA exclusion group present (review)' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ users=@{ excludeGroups=@('g-456') } } }) } }
New-Fixture Entra EIDCA-005 $I throttled SKIP 'ConditionalAccess collection failed' $skCA
New-Fixture Entra EIDCA-009 $I clean PASS 'A CA policy requires device compliance' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; id='p1'; displayName='Compliant'; grantControls=@{ builtInControls=@('compliantDevice') } }) } }
New-Fixture Entra EIDCA-009 $I known-bad FAIL 'No CA policy requires device compliance' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; grantControls=@{ builtInControls=@('mfa') } }) } }
New-Fixture Entra EIDCA-009 $I throttled SKIP 'ConditionalAccess collection failed' $skCA
New-Fixture Entra EIDCA-012 $I clean PASS 'Sign-in risk policy covers high+medium' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ signInRiskLevels=@('high','medium') } }) } }
New-Fixture Entra EIDCA-012 $I known-bad FAIL 'No sign-in risk policy' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ signInRiskLevels=$null } }) } }
New-Fixture Entra EIDCA-012 $I throttled SKIP 'ConditionalAccess collection failed' $skCA
New-Fixture Entra EIDCA-013 $I clean PASS 'User risk policy covers high' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ userRiskLevels=@('high') } }) } }
New-Fixture Entra EIDCA-013 $I known-bad FAIL 'No user risk policy' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; conditions=@{ userRiskLevels=$null } }) } }
New-Fixture Entra EIDCA-013 $I throttled SKIP 'ConditionalAccess collection failed' $skCA

# ── Entra federation ──
New-Fixture Entra EIDFED-002 $I clean PASS 'No federated domains (no signing certs to validate)' @{ Errors=@{}; Federation=@{ Errors=@{}; FederationConfigs=@() } }
New-Fixture Entra EIDFED-002 $I throttled SKIP 'Federation collection failed (cert-expiry FAIL needs a real X.509)' $skFed
New-Fixture Entra EIDFED-004 $I clean PASS 'Federation metadata extracted (informational, always PASS)' @{ Errors=@{}; Federation=@{ Errors=@{}; FederationConfigs=@(@{ DomainName='c.com'; Config=@{ issuerUri='https://sts/'; preferredAuthenticationProtocol='wsfed' } }) } }
New-Fixture Entra EIDFED-004 $I throttled SKIP 'Federation collection failed' $skFed
New-Fixture Entra EIDFED-005 $I clean PASS 'Password hash sync enabled' @{ Errors=@{}; Federation=@{ Errors=@{}; OnPremisesSyncSettings=@{ value=@(@{ features=@{ passwordHashSyncEnabled=$true; passThroughAuthenticationEnabled=$false } }) }; OnPremisesSyncEnabled=$true; Users=@{ SyncedCount=100 } } }
New-Fixture Entra EIDFED-005 $I known-bad WARN 'Neither PHS nor PTA enabled' @{ Errors=@{}; Federation=@{ Errors=@{}; OnPremisesSyncSettings=@{ value=@(@{ features=@{ passwordHashSyncEnabled=$false; passThroughAuthenticationEnabled=$false } }) }; OnPremisesSyncEnabled=$true; Users=@{ SyncedCount=100 } } }
New-Fixture Entra EIDFED-005 $I no-data SKIP 'Cloud-only tenant (no on-prem sync)' @{ Errors=@{}; Federation=@{ Errors=@{}; OnPremisesSyncSettings=$null; OnPremisesSyncEnabled=$false; Users=@{ SyncedCount=0 } } }
New-Fixture Entra EIDFED-009 $I clean PASS 'Federated IdP MFA behavior configured' @{ Errors=@{}; Federation=@{ Errors=@{}; FederationConfigs=@(@{ DomainName='c.com'; Config=@{ federatedIdpMfaBehavior='acceptIfMfaDoneByFederatedIdp'; preferredAuthenticationProtocol='wsfed'; promptLoginBehavior='NativeClient' } }) } }
New-Fixture Entra EIDFED-009 $I known-bad WARN 'Federated domain missing MFA behavior (1-2 issues)' @{ Errors=@{}; Federation=@{ Errors=@{}; FederationConfigs=@(@{ DomainName='c.com'; Config=@{ federatedIdpMfaBehavior=$null; preferredAuthenticationProtocol='wsfed'; promptLoginBehavior=$null } }) } }
New-Fixture Entra EIDFED-009 $I throttled SKIP 'Federation collection failed' $skFed
New-Fixture Entra EIDFED-013 $I no-data SKIP 'Cloud-only tenant — no Entra Connect to assess (PASS/FAIL need host registry/ADSync)' @{ Errors=@{}; Federation=@{ Errors=@{}; OnPremisesSyncSettings=$null; OnPremisesSyncEnabled=$false; Users=@{ SyncedCount=0 } } }

# ── Entra PIM (working checks only) ──
New-Fixture Entra EIDPIM-003 $I clean PASS 'No permanent privileged role assignments' @{ Errors=@{}; PIM=@{ Errors=@{}; RoleAssignments=@(); RoleEligibilitySchedules=@(); RoleDefinitions=@() } }
New-Fixture Entra EIDPIM-003 $I known-bad WARN 'A permanent Global Admin assignment should be eligible' @{ Errors=@{}; PIM=@{ Errors=@{}; RoleAssignments=@(@{ roleDefinitionId='62e90394-69f5-4237-9190-012177145e10'; principalId='u1' }); RoleEligibilitySchedules=@(); RoleDefinitions=@(@{ id='62e90394-69f5-4237-9190-012177145e10'; displayName='Global Administrator' }) } }
New-Fixture Entra EIDPIM-003 $I throttled SKIP 'PIM collection failed' $skPIM
New-Fixture Entra EIDPIM-010 $I clean PASS 'PIM eligible assignments configured' @{ Errors=@{}; PIM=@{ Errors=@{}; RoleAssignmentSchedules=@(); RoleEligibilitySchedules=@(@{ id='sched1' }) } }
New-Fixture Entra EIDPIM-010 $I known-bad FAIL 'PIM not configured (no eligible assignments)' @{ Errors=@{}; PIM=@{ Errors=@{}; RoleAssignmentSchedules=@(); RoleEligibilitySchedules=@() } }
New-Fixture Entra EIDPIM-010 $I throttled SKIP 'PIM collection failed' $skPIM

# ── Entra tenant ──
New-Fixture Entra EIDTNT-002 $I clean PASS 'Default user role cannot create apps/groups/tenants' @{ TenantConfig=@{ AuthorizationPolicy=@{ defaultUserRolePermissions=@{ allowedToCreateApps=$false; allowedToCreateSecurityGroups=$false; allowedToCreateTenants=$false; allowedToReadOtherUsers=$true } } } }
New-Fixture Entra EIDTNT-002 $I known-bad FAIL 'Default user role can create apps and groups (2+ issues)' @{ TenantConfig=@{ AuthorizationPolicy=@{ defaultUserRolePermissions=@{ allowedToCreateApps=$true; allowedToCreateSecurityGroups=$true; allowedToCreateTenants=$true; allowedToReadOtherUsers=$true } } } }
New-Fixture Entra EIDTNT-002 $I no-data SKIP 'Authorization policy unavailable' @{ TenantConfig=@{ AuthorizationPolicy=$null } }
New-Fixture Entra EIDTNT-003 $I clean PASS 'Guest access restricted (most-limited role)' @{ TenantConfig=@{ AuthorizationPolicy=@{ guestUserRoleId='2af84b1e-32c8-42b7-82bc-daa82404023b' } } }
New-Fixture Entra EIDTNT-003 $I known-bad FAIL 'Guests have member-equivalent access' @{ TenantConfig=@{ AuthorizationPolicy=@{ guestUserRoleId='a0b1b346-4d3e-4e8b-98f8-753987be4970' } } }
New-Fixture Entra EIDTNT-003 $I no-data SKIP 'Authorization policy unavailable' @{ TenantConfig=@{ AuthorizationPolicy=$null } }
New-Fixture Entra EIDTNT-005 $I clean PASS 'B2B collaboration blocked by default' @{ TenantConfig=@{ CrossTenantAccess=@{ b2bCollaborationInbound=@{ usersAndGroups=@{ accessType='blocked'; targets=@() } }; b2bCollaborationOutbound=@{ usersAndGroups=@{ accessType='blocked'; targets=@() } } } } }
New-Fixture Entra EIDTNT-005 $I known-bad FAIL 'B2B collaboration allowed for all users inbound+outbound (2 issues)' @{ TenantConfig=@{ CrossTenantAccess=@{ b2bCollaborationInbound=@{ usersAndGroups=@{ accessType='allowed'; targets=@(@{ target='AllUsers' }) } }; b2bCollaborationOutbound=@{ usersAndGroups=@{ accessType='allowed'; targets=@(@{ target='AllUsers' }) } } } } }
New-Fixture Entra EIDTNT-005 $I no-data SKIP 'Cross-tenant access settings unavailable' @{ TenantConfig=@{ CrossTenantAccess=$null } }
New-Fixture Entra EIDTNT-006 $I clean PASS 'Few cross-tenant partners (<=5)' @{ Errors=@{}; TenantConfig=@{ Errors=@{}; CrossTenantPartners=@(@{ tenantId='11111111-1111-1111-1111-111111111111'; isServiceProvider=$false }) } }
New-Fixture Entra EIDTNT-006 $I known-bad WARN '6 cross-tenant partners (review)' @{ Errors=@{}; TenantConfig=@{ Errors=@{}; CrossTenantPartners=@(
    @{ tenantId='1'; isServiceProvider=$false },@{ tenantId='2'; isServiceProvider=$false },@{ tenantId='3'; isServiceProvider=$false },
    @{ tenantId='4'; isServiceProvider=$false },@{ tenantId='5'; isServiceProvider=$false },@{ tenantId='6'; isServiceProvider=$false }) } }
New-Fixture Entra EIDTNT-006 $I throttled SKIP 'TenantConfig collection failed' $skTnt
New-Fixture Entra EIDTNT-011 $I always-warn WARN 'Diagnostic settings require manual portal verification' @{ }
New-Fixture Entra EIDTNT-012 $I always-warn WARN 'Long-term log retention requires manual verification' @{ TenantConfig=@{ SubscribedSkus=@() } }

Write-Host "`nDone (high round 3)."
