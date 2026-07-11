#requires -version 7.0
<#
    Authoring helper for the golden fixtures consumed by
    Tests/Unit/GoldenFixtureChecks.Tests.ps1.

    The emitted *.json files under AD/ Entra/ GoogleWorkspace/ are the committed
    golden artifacts the tests actually read — this script just regenerates them
    consistently. Every payload is synthetic and hand-crafted; NO real tenant
    data is present. To add coverage for another check, append a New-Fixture
    block below and re-run:  pwsh Tests/Fixtures/_generate-fixtures.ps1

    Each fixture pins one invariant for one check:
        clean      => PASS
        known-bad  => FAIL (or WARN where the check grades a soft control)
        throttled  => SKIP  (collector error map populated)
        no-data    => SKIP  (dependency absent; absence-of-evidence guard)
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function New-Fixture {
    param(
        [Parameter(Mandatory)][string]$Family,      # AD | Entra | GoogleWorkspace
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Platform,
        [Parameter(Mandatory)][string]$Scenario,    # clean | known-bad | throttled | no-data
        [Parameter(Mandatory)][string]$ExpectedStatus,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][hashtable]$AuditData
    )
    $obj = [ordered]@{
        checkId        = $CheckId
        platform        = $Platform
        scenario       = $Scenario
        expectedStatus = $ExpectedStatus
        description    = $Description
        auditData      = $AuditData
    }
    $dir  = Join-Path $root $Family
    $path = Join-Path $dir "$CheckId.$Scenario.json"
    $obj | ConvertTo-Json -Depth 12 | Set-Content -Path $path -Encoding utf8
    Write-Host "  wrote $Family/$CheckId.$Scenario.json -> $ExpectedStatus"
}

# ─────────────────────────────────────────────────────────────────────────────
# ACTIVE DIRECTORY (AD)  Test-Recon*
# ─────────────────────────────────────────────────────────────────────────────

# ADPRIV-001  Domain Admins membership count
New-Fixture AD ADPRIV-001 AD clean PASS '2 effective members in Domain Admins is within the safe threshold (<=3)' @{
    PrivilegedAccounts = @{ PrivilegedGroups = @{ 'Domain Admins' = @(
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin1'; Enabled=$true },
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin2'; Enabled=$true }
    ) } }
    Errors = @{}
}
New-Fixture AD ADPRIV-001 AD known-bad FAIL '6 effective members in Domain Admins exceeds the failing threshold (>5)' @{
    PrivilegedAccounts = @{ PrivilegedGroups = @{ 'Domain Admins' = @(
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin1'; Enabled=$true },
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin2'; Enabled=$true },
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin3'; Enabled=$true },
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin4'; Enabled=$true },
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin5'; Enabled=$true },
        @{ ObjectClass='user'; IsGroup=$false; SamAccountName='admin6'; Enabled=$true }
    ) } }
    Errors = @{}
}
New-Fixture AD ADPRIV-001 AD throttled SKIP 'PrivilegedMembers collection failed; must be Not Assessed, never PASS' @{
    PrivilegedAccounts = $null
    Errors = @{ PrivilegedMembers = 'Get-ADGroupMember failed: a referral was returned from the server.' }
}

# ADPRIV-022  krbtgt password age (substitute for non-existent ADPRIV-028)
New-Fixture AD ADPRIV-022 AD clean PASS 'krbtgt password age 90 days is within the safe threshold (<=180)' @{
    PrivilegedAccounts = @{ KrbtgtAccount = @{ PwdAgeDays = 90; KeyVersionNumber = 3 } }
    Errors = @{}
}
New-Fixture AD ADPRIV-022 AD known-bad FAIL 'krbtgt password age 4000 days exceeds the failing threshold (>365)' @{
    PrivilegedAccounts = @{ KrbtgtAccount = @{ PwdAgeDays = 4000; KeyVersionNumber = 1 } }
    Errors = @{}
}
New-Fixture AD ADPRIV-022 AD throttled SKIP 'PrivilegedMembers collection failed; must be Not Assessed, never PASS' @{
    PrivilegedAccounts = $null
    Errors = @{ PrivilegedMembers = 'krbtgt object query timed out.' }
}

# ADACL-002  GenericAll on critical objects
New-Fixture AD ADACL-002 AD clean PASS 'no dangerous GenericAll ACEs present' @{
    ACLs = @{ DangerousACEs = @() }
    Errors = @{}
}
New-Fixture AD ADACL-002 AD known-bad FAIL 'an unprivileged principal holds GenericAll over the domain root' @{
    ACLs = @{ DangerousACEs = @(
        @{ IdentityReference='CONTOSO\SuspiciousUser'; IdentitySID='S-1-5-21-1111111111-2222222222-3333333333-1601'; ActiveDirectoryRights='GenericAll'; ObjectName='DC=contoso,DC=com' }
    ) }
    Errors = @{}
}
New-Fixture AD ADACL-002 AD throttled SKIP 'ObjectACLs collection failed; must be Not Assessed, never PASS' @{
    ACLs = $null
    Errors = @{ ObjectACLs = 'LDAP ACL read failed: insufficient access rights.' }
}

# ADACL-015  Dangerous delegated rights
New-Fixture AD ADACL-015 AD clean PASS 'no dangerous delegated ACEs after safe-admin filtering' @{
    ACLs = @{ DangerousACEs = @() }
    Errors = @{}
}
New-Fixture AD ADACL-015 AD known-bad FAIL 'an unprivileged principal holds GenericWrite over the domain root' @{
    ACLs = @{ DangerousACEs = @(
        @{ IdentityReference='CONTOSO\RegularUser'; IdentitySID='S-1-5-21-1111111111-2222222222-3333333333-1700'; ActiveDirectoryRights='GenericWrite'; ObjectName='DC=contoso,DC=com' }
    ) }
    Errors = @{}
}
New-Fixture AD ADACL-015 AD throttled SKIP 'ObjectACLs collection failed; must be Not Assessed, never PASS' @{
    ACLs = $null
    Errors = @{ ObjectACLs = 'LDAP ACL read failed: server unavailable.' }
}

# ADCS-002  ESC1 (enrollee-supplies-subject + auth EKU + low-priv enroll)
New-Fixture AD ADCS-002 AD clean PASS 'no ESC1-vulnerable certificate templates' @{
    CertificateServices = @{ CertificateTemplates = @(
        @{ Name='SafeTemplate'; DisplayName='Safe Template'; IsPublished=$false; EnrolleeSuppliesSubject=$false; ExtendedKeyUsageOIDs=@(); RASignaturesRequired=0; EnrollmentPermissions=@() }
    ) }
    Errors = @{}
}
New-Fixture AD ADCS-002 AD known-bad FAIL 'a published template allows enrollee-supplied subject with client-auth EKU and low-priv enroll (ESC1)' @{
    CertificateServices = @{ CertificateTemplates = @(
        @{ Name='ESC1Vulnerable'; DisplayName='ESC1 Vulnerable'; IsPublished=$true; EnrolleeSuppliesSubject=$true; ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.2'); RASignaturesRequired=0; EnrollmentPermissions=@(
            @{ SID='S-1-5-11'; Identity='Authenticated Users'; Right='Enroll' }
        ) }
    ) }
    Errors = @{}
}
New-Fixture AD ADCS-002 AD throttled SKIP 'CertificateServices collection failed; must be Not Assessed, never PASS' @{
    CertificateServices = $null
    Errors = @{ CertificateServices = 'AD CS enumeration failed: no enterprise CA reachable.' }
}

# ADCS-010  Dangerous ACL on CA / enrollment-service PKI objects
New-Fixture AD ADCS-010 AD clean PASS 'no dangerous ACLs on CA enrollment-service objects' @{
    CertificateServices = @{
        CertificateAuthorities = @( @{ Name='CA1'; DNSHostName='ca1.contoso.com' } )
        PKIObjects = @( @{ Name='CA1'; DN='CN=CA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'; Permissions=@() } )
    }
    Errors = @{}
}
New-Fixture AD ADCS-010 AD known-bad FAIL 'a low-priv principal holds WriteDacl over a CA enrollment-service object (ESC4-style)' @{
    CertificateServices = @{
        CertificateAuthorities = @( @{ Name='VulnerableCA'; DNSHostName='vulnerable-ca.contoso.com' } )
        PKIObjects = @( @{ Name='VulnerableCA'; DN='CN=VulnerableCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'; Permissions=@(
            @{ SID='S-1-5-11'; Identity='Authenticated Users'; Right='WriteDacl' }
        ) } )
    }
    Errors = @{}
}
New-Fixture AD ADCS-010 AD throttled SKIP 'CertificateServices collection failed; must be Not Assessed, never PASS' @{
    CertificateServices = $null
    Errors = @{ CertificateServices = 'AD CS enumeration failed: RPC server unavailable.' }
}

# ADKERB-004  Unconstrained delegation on computer accounts
New-Fixture AD ADKERB-004 AD clean PASS 'no computer accounts with unconstrained delegation' @{
    Kerberos = @{ UnconstrainedDelegation = @() }
    Errors = @{}
}
New-Fixture AD ADKERB-004 AD known-bad FAIL 'a workstation is trusted for unconstrained delegation' @{
    Kerberos = @{ UnconstrainedDelegation = @(
        @{ ObjectClass=@('computer'); SamAccountName='WORKSTATION01$'; DnsHostName='workstation01.contoso.com'; DN='CN=WORKSTATION01,CN=Computers,DC=contoso,DC=com' }
    ) }
    Errors = @{}
}
New-Fixture AD ADKERB-004 AD throttled SKIP 'KerberosConfig collection failed; must be Not Assessed, never PASS' @{
    Kerberos = $null
    Errors = @{ KerberosConfig = 'Kerberos delegation query failed: domain controller unreachable.' }
}

# ─────────────────────────────────────────────────────────────────────────────
# ENTRA ID / M365 (Entra)  Test-Entra*
# ─────────────────────────────────────────────────────────────────────────────

# EIDPIM-001  Global Administrator count (substitute for broken EIDPIM-006)
New-Fixture Entra EIDPIM-001 Entra clean PASS '3 Global Administrators is within the recommended range (2-4)' @{
    PIM = @{ GlobalAdmins = @(
        @{ id='1'; displayName='Admin 1'; userPrincipalName='admin1@contoso.com'; userType='Member'; accountEnabled=$true },
        @{ id='2'; displayName='Admin 2'; userPrincipalName='admin2@contoso.com'; userType='Member'; accountEnabled=$true },
        @{ id='3'; displayName='Admin 3'; userPrincipalName='admin3@contoso.com'; userType='Member'; accountEnabled=$true }
    ) }
    Errors = @{}
}
New-Fixture Entra EIDPIM-001 Entra known-bad FAIL '6 Global Administrators exceeds the failing threshold (>5)' @{
    PIM = @{ GlobalAdmins = @(
        @{ id='1'; displayName='Admin 1'; userPrincipalName='admin1@contoso.com'; userType='Member'; accountEnabled=$true },
        @{ id='2'; displayName='Admin 2'; userPrincipalName='admin2@contoso.com'; userType='Member'; accountEnabled=$true },
        @{ id='3'; displayName='Admin 3'; userPrincipalName='admin3@contoso.com'; userType='Member'; accountEnabled=$true },
        @{ id='4'; displayName='Admin 4'; userPrincipalName='admin4@contoso.com'; userType='Member'; accountEnabled=$true },
        @{ id='5'; displayName='Admin 5'; userPrincipalName='admin5@contoso.com'; userType='Member'; accountEnabled=$true },
        @{ id='6'; displayName='Admin 6'; userPrincipalName='admin6@contoso.com'; userType='Member'; accountEnabled=$true }
    ) }
    Errors = @{}
}
New-Fixture Entra EIDPIM-001 Entra no-data SKIP 'Global Administrator list unavailable; must be Not Assessed, never PASS' @{
    PIM = @{ GlobalAdmins = $null }
    Errors = @{}
}

# EIDAUTH-002  MFA registration coverage
New-Fixture Entra EIDAUTH-002 Entra clean PASS '10 of 10 users MFA-registered (100%) meets the >=99% threshold' @{
    AuthMethods = @{ UserRegistrationDetails = @(
        1..10 | ForEach-Object { @{ id="$_"; isMfaRegistered=$true; isMfaCapable=$true } }
    ) }
    Errors = @{}
}
New-Fixture Entra EIDAUTH-002 Entra known-bad FAIL '0 of 10 users MFA-registered (0%) is below the 90% failing threshold' @{
    AuthMethods = @{ UserRegistrationDetails = @(
        1..10 | ForEach-Object { @{ id="$_"; isMfaRegistered=$false; isMfaCapable=$false } }
    ) }
    Errors = @{}
}
New-Fixture Entra EIDAUTH-002 Entra no-data SKIP 'User registration details unavailable; must be Not Assessed, never PASS' @{
    AuthMethods = @{ UserRegistrationDetails = @() }
    Errors = @{}
}

# EIDCA-007  Conditional Access universal MFA
New-Fixture Entra EIDCA-007 Entra clean PASS 'an enabled CA policy requires MFA for all users on all cloud apps' @{
    ConditionalAccess = @{ Policies = @(
        @{ id='p1'; displayName='MFA for All'; state='enabled'; grantControls=@{ builtInControls=@('mfa'); authenticationStrength=$null }; conditions=@{ users=@{ includeUsers=@('All') }; applications=@{ includeApplications=@('All') } } }
    ) }
    Errors = @{}
}
New-Fixture Entra EIDCA-007 Entra known-bad FAIL 'no Conditional Access policy enforces MFA' @{
    ConditionalAccess = @{ Policies = @(
        @{ id='p1'; displayName='Block Legacy Auth'; state='enabled'; grantControls=@{ builtInControls=@('block') }; conditions=@{ users=@{ includeUsers=@('All') }; applications=@{ includeApplications=@('All') } } }
    ) }
    Errors = @{}
}
New-Fixture Entra EIDCA-007 Entra throttled SKIP 'ConditionalAccess collection failed; must be Not Assessed, never PASS' @{
    ConditionalAccess = @{ Policies = $null }
    Errors = @{ ConditionalAccess = 'Graph 429: conditionalAccess/policies throttled.' }
}

# EIDAPP-005  High-privilege service principals holding credentials
New-Fixture Entra EIDAPP-005 Entra clean PASS 'a benign app (User.Read delegated only) with a credential-free service principal' @{
    Applications = @{
        AppRegistrations = @(
            @{ appId='app-benign'; requiredResourceAccess=@( @{ resourceAppId='00000003-0000-0000-c000-000000000000'; resourceAccess=@( @{ id='e1fe6dd8-ba31-4d61-89e7-88639da4683d'; type='Scope' } ) } ) }
        )
        ServicePrincipals = @(
            @{ appId='app-benign'; displayName='Benign App'; passwordCredentials=@(); keyCredentials=@() }
        )
    }
    Errors = @{}
}
New-Fixture Entra EIDAPP-005 Entra known-bad FAIL 'an app with RoleManagement.ReadWrite.Directory holds a password credential' @{
    Applications = @{
        AppRegistrations = @(
            @{ appId='app-1'; requiredResourceAccess=@( @{ resourceAppId='00000003-0000-0000-c000-000000000000'; resourceAccess=@( @{ id='9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'; type='Role' } ) } ) }
        )
        ServicePrincipals = @(
            @{ appId='app-1'; passwordCredentials=@( @{ keyId='cred-1'; endDateTime='2099-12-31T00:00:00Z' } ); keyCredentials=@() }
        )
    }
    Errors = @{}
}
New-Fixture Entra EIDAPP-005 Entra no-data SKIP 'Application/service-principal inventory unavailable; must be Not Assessed, never PASS' @{
    Applications = @{ AppRegistrations = $null; ServicePrincipals = $null }
    Errors = @{}
}

# EIDTNT-007  Security defaults / baseline protection
New-Fixture Entra EIDTNT-007 Entra clean PASS 'security defaults are enabled' @{
    TenantConfig = @{ SecurityDefaults = @{ isEnabled=$true } }
    ConditionalAccess = @{ Policies = @() }
    Errors = @{}
}
New-Fixture Entra EIDTNT-007 Entra known-bad FAIL 'security defaults disabled and no enabled CA policy replaces them' @{
    TenantConfig = @{ SecurityDefaults = @{ isEnabled=$false } }
    ConditionalAccess = @{ Policies = @( @{ state='disabled' } ) }
    Errors = @{}
}
New-Fixture Entra EIDTNT-007 Entra throttled SKIP 'TenantConfig collection failed; must be Not Assessed, never PASS' @{
    TenantConfig = @{ SecurityDefaults = $null }
    ConditionalAccess = @{ Policies = @() }
    Errors = @{ TenantConfig = 'Graph 429: policies/identitySecurityDefaultsEnforcementPolicy throttled.' }
}

# M365EXO-007  Exchange transport forwarding rules
# NOTE: a healthy tenant typically has at least one benign (non-forwarding) rule.
# An *empty* TransportRules array currently returns SKIP, not PASS, because the
# guard `-not $exo.TransportRules` swallows the empty array before the intended
# `RuleCount -eq 0 => PASS` branch in Test-M365EXO007 (latent bug).
New-Fixture Entra M365EXO-007 Entra clean PASS 'one benign disclaimer rule, no redirect/forward actions' @{
    M365Services = @{ Exchange = @{ TransportRules = @(
        @{ Name='Append disclaimer'; State='Enabled'; Priority=0; Mode='Enforce'; RedirectMessageTo=$null; BlindCopyTo=$null; CopyTo=$null; AddToRecipients=$null }
    ) } }
    Errors = @{}
}
New-Fixture Entra M365EXO-007 Entra known-bad WARN 'an enabled transport rule redirects mail to an external address' @{
    M365Services = @{ Exchange = @{ TransportRules = @(
        @{ Name='Forward to external'; State='Enabled'; Priority=1; Mode='Enforce'; RedirectMessageTo=@('attacker@external.com'); BlindCopyTo=$null; CopyTo=$null; AddToRecipients=$null }
    ) } }
    Errors = @{}
}
New-Fixture Entra M365EXO-007 Entra throttled SKIP 'Exchange transport-rule collection failed; must be Not Assessed, never PASS' @{
    M365Services = @{ Exchange = $null }
    Errors = @{ M365Services = 'Exchange Online PowerShell connection failed.' }
}

# M365AUDIT-001  Unified audit log ingestion
New-Fixture Entra M365AUDIT-001 Entra clean PASS 'unified audit log ingestion is enabled' @{
    M365Services = @{ AuditConfig = @{ UnifiedAuditLogIngestionEnabled=$true } }
    Errors = @{}
}
New-Fixture Entra M365AUDIT-001 Entra known-bad FAIL 'unified audit log ingestion is disabled' @{
    M365Services = @{ AuditConfig = @{ UnifiedAuditLogIngestionEnabled=$false } }
    Errors = @{}
}
New-Fixture Entra M365AUDIT-001 Entra throttled SKIP 'Audit configuration collection failed; must be Not Assessed, never PASS' @{
    M365Services = @{ AuditConfig = $null }
    Errors = @{ M365Services = 'Get-AdminAuditLogConfig failed: connection timed out.' }
}

# INTUNE-010  Endpoint detection & response configuration
New-Fixture Entra INTUNE-010 Entra clean PASS 'an EDR configuration profile is deployed' @{
    Intune = @{ DeviceConfigurations = @(
        @{ id='c1'; displayName='MDE Onboarding'; '@odata.type'='#microsoft.graph.endpointDetectionAndResponsePolicy' }
    ) }
    Errors = @{}
}
New-Fixture Entra INTUNE-010 Entra known-bad WARN 'no EDR configuration profile is deployed' @{
    Intune = @{ DeviceConfigurations = @(
        @{ id='c1'; displayName='Firewall Policy'; '@odata.type'='#microsoft.graph.windowsFirewallConfiguration' }
    ) }
    Errors = @{}
}
New-Fixture Entra INTUNE-010 Entra throttled SKIP 'Intune device-configuration collection failed; must be Not Assessed, never PASS' @{
    Intune = @{ DeviceConfigurations = $null }
    Errors = @{ Intune = 'Graph 429: deviceManagement/deviceConfigurations throttled.' }
}

# ─────────────────────────────────────────────────────────────────────────────
# GOOGLE WORKSPACE (GWS)  Test-GWS*
# ─────────────────────────────────────────────────────────────────────────────

# AUTH-001  2SV enforcement
New-Fixture GoogleWorkspace AUTH-001 GWS clean PASS 'all active users have 2SV enforced (100% >= 95%)' @{
    Users = @(
        @{ suspended=$false; primaryEmail='user1@example.com'; isEnforcedIn2Sv=$true },
        @{ suspended=$false; primaryEmail='user2@example.com'; isEnforcedIn2Sv=$true }
    )
    Errors = @{}
}
New-Fixture GoogleWorkspace AUTH-001 GWS known-bad FAIL '0% of active users have 2SV enforced (below 50%)' @{
    Users = @(
        @{ suspended=$false; primaryEmail='user1@example.com'; isEnforcedIn2Sv=$false },
        @{ suspended=$false; primaryEmail='user2@example.com'; isEnforcedIn2Sv=$false }
    )
    Errors = @{}
}
New-Fixture GoogleWorkspace AUTH-001 GWS throttled SKIP 'User inventory collection failed; must be Not Assessed, never PASS' @{
    Users = $null
    Errors = @{ Users = 'Admin SDK 429: rate limit exceeded for users.list' }
}

# EMAIL-001  SPF hardening
New-Fixture GoogleWorkspace EMAIL-001 GWS clean PASS 'SPF valid with a hard/soft-fail qualifier on every domain' @{
    DnsRecords = @{ 'example.com' = @{ SPF = @{ Valid=$true; Record='v=spf1 include:_spf.google.com ~all'; Details='' } } }
    Errors = @{}
}
New-Fixture GoogleWorkspace EMAIL-001 GWS known-bad FAIL 'SPF ends in +all, allowing any host to send' @{
    DnsRecords = @{ 'example.com' = @{ SPF = @{ Valid=$true; Record='v=spf1 include:_spf.google.com +all'; Details='' } } }
    Errors = @{}
}
New-Fixture GoogleWorkspace EMAIL-001 GWS throttled SKIP 'DNS record collection failed; must be Not Assessed, never PASS' @{
    DnsRecords = $null
    Errors = @{ 'DnsRecords:example.com' = 'DNS resolution failed: SERVFAIL' }
}

# EMAIL-003  DMARC enforcement
New-Fixture GoogleWorkspace EMAIL-003 GWS clean PASS 'DMARC valid with an enforcing policy (reject)' @{
    DnsRecords = @{ 'example.com' = @{ DMARC = @{ Valid=$true; Policy='reject'; Details='' } } }
    Errors = @{}
}
New-Fixture GoogleWorkspace EMAIL-003 GWS known-bad FAIL 'no valid DMARC record present' @{
    DnsRecords = @{ 'example.com' = @{ DMARC = @{ Valid=$false; Policy=$null; Details='DMARC record not found' } } }
    Errors = @{}
}
New-Fixture GoogleWorkspace EMAIL-003 GWS throttled SKIP 'DNS record collection failed; must be Not Assessed, never PASS' @{
    DnsRecords = $null
    Errors = @{ 'DnsRecords:example.com' = 'DNS resolution failed: timeout' }
}

# OAUTH-008  Domain-wide delegation sensitive scopes
New-Fixture GoogleWorkspace OAUTH-008 GWS clean PASS 'domain-wide delegation grants hold no Gmail/Drive/Admin/Calendar scopes' @{
    DomainWideDelegation = @(
        @{ clientId='100000000000000000001'; scopes=@('https://www.googleapis.com/auth/spreadsheets.readonly') }
    )
    Errors = @{}
}
New-Fixture GoogleWorkspace OAUTH-008 GWS known-bad FAIL 'a delegation grant holds Gmail and Drive scopes' @{
    DomainWideDelegation = @(
        @{ clientId='100000000000000000002'; scopes=@('https://www.googleapis.com/auth/gmail.modify','https://www.googleapis.com/auth/drive') }
    )
    Errors = @{}
}
New-Fixture GoogleWorkspace OAUTH-008 GWS throttled SKIP 'Domain-wide delegation collection failed; must be Not Assessed, never PASS' @{
    DomainWideDelegation = $null
    Errors = @{ DomainWideDelegation = 'Admin SDK: domain-wide delegation list returned 403' }
}

# GTRADE-001  Domain-wide delegation high-risk scopes (tradecraft)
New-Fixture GoogleWorkspace GTRADE-001 GWS clean PASS 'delegation grants exist and hold only read-only scopes' @{
    DomainWideDelegation = @(
        @{ clientId='100000000000000000003'; scopes=@('https://www.googleapis.com/auth/spreadsheets.readonly','https://www.googleapis.com/auth/drive.readonly') }
    )
    Errors = @{}
}
New-Fixture GoogleWorkspace GTRADE-001 GWS known-bad FAIL 'a delegation grant holds full mailbox and directory write scopes' @{
    DomainWideDelegation = @(
        @{ clientId='100000000000000000004'; scopes=@('https://mail.google.com/','https://www.googleapis.com/auth/admin.directory.user') }
    )
    Errors = @{}
}
New-Fixture GoogleWorkspace GTRADE-001 GWS throttled SKIP 'Domain-wide delegation collection failed; must be Not Assessed, never PASS' @{
    DomainWideDelegation = $null
    Errors = @{ DomainWideDelegation = 'Admin SDK: domain-wide delegation list returned 403' }
}

Write-Host "`nDone."
