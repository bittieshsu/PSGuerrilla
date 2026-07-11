#requires -version 7.0
<#
    Critical-tier expansion of the golden fixtures (batch 2).

    Companion to _generate-fixtures.ps1 (the original 20). Emits clean / known-bad
    / skip fixtures for the remaining Critical-severity checks. All payloads are
    synthetic; NO real tenant data. Re-run:  pwsh Tests/Fixtures/_generate-fixtures-critical.ps1

    Conventions:
      - "known-bad" asserts FAIL where the check has a FAIL path, else WARN.
      - SKIP fixtures populate the collector error map (throttle) OR omit the
        dependency (no-data), whichever the check actually treats as Not Assessed.
    Excluded (tracked separately): EIDPIM-004 & EIDPIM-006 (broken: undefined
    $privilegedUsers), ADMIN-001 (no implementing function). Object-only PASS/FAIL
    paths (ADPRIV-020, EIDFED-003 FAIL, EMAIL-017 PASS/FAIL) are partially covered.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function New-Fixture {
    param(
        [Parameter(Mandatory)][string]$Family,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Platform,
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$ExpectedStatus,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][hashtable]$AuditData
    )
    $obj = [ordered]@{
        checkId = $CheckId; platform = $Platform; scenario = $Scenario
        expectedStatus = $ExpectedStatus; description = $Description; auditData = $AuditData
    }
    $path = Join-Path $root $Family "$CheckId.$Scenario.json"
    $obj | ConvertTo-Json -Depth 12 | Set-Content -Path $path -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}

$RECON = 'AD'; $INFIL = 'Entra'; $FORT = 'GWS'

# ── AD privileged accounts ───────────────────────────────────────────────────
New-Fixture AD ADPRIV-002 $RECON clean PASS 'No direct user members in Enterprise Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Enterprise Admins'=@() } } }
New-Fixture AD ADPRIV-002 $RECON known-bad FAIL '3 user members in Enterprise Admins exceeds threshold (>2)' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Enterprise Admins'=@(
    @{ SamAccountName='ea1'; ObjectClass='user'; IsGroup=$false; Enabled=$true },
    @{ SamAccountName='ea2'; ObjectClass='user'; IsGroup=$false; Enabled=$true },
    @{ SamAccountName='ea3'; ObjectClass='user'; IsGroup=$false; Enabled=$true }) } } }
New-Fixture AD ADPRIV-002 $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='referral returned from server' }; PrivilegedAccounts=$null }

foreach ($u in @(
    @{ Id='ADPRIV-010'; Flag='DONT_EXPIRE_PASSWORD'; Subj='non-expiring password' },
    @{ Id='ADPRIV-011'; Flag='PASSWD_NOTREQD';       Subj='password-not-required' },
    @{ Id='ADPRIV-012'; Flag='DONT_REQ_PREAUTH';     Subj='AS-REP roastable' },
    @{ Id='ADPRIV-013'; Flag='ENCRYPTED_TEXT_PWD_ALLOWED'; Subj='reversible encryption' }
)) {
    New-Fixture AD $u.Id $RECON clean PASS "No privileged account flagged $($u.Subj)" @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(
        @{ SamAccountName='admin1'; DistinguishedName='CN=admin1,CN=Users,DC=test,DC=local'; UACFlags=@{ "$($u.Flag)"=$false } }) } }
    New-Fixture AD $u.Id $RECON known-bad FAIL "A privileged account is $($u.Subj)" @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(
        @{ SamAccountName='admin1'; DistinguishedName='CN=admin1,CN=Users,DC=test,DC=local'; UACFlags=@{ "$($u.Flag)"=$true } }) } }
    New-Fixture AD $u.Id $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='referral returned from server' }; PrivilegedAccounts=$null }
}

New-Fixture AD ADPRIV-016 $RECON clean PASS 'No privileged accounts with weak/known passwords' @{ Errors=@{}; PrivilegedAccounts=@{ PasswordAnalysis=@{ WeakPasswords=@() } } }
New-Fixture AD ADPRIV-016 $RECON known-bad FAIL 'A privileged account uses a weak/known password' @{ Errors=@{}; PrivilegedAccounts=@{ PasswordAnalysis=@{ WeakPasswords=@(@{ SamAccountName='admin1' }) } } }
New-Fixture AD ADPRIV-016 $RECON throttled SKIP 'PasswordHashQuality collection failed' @{ Errors=@{ PasswordHashQuality='DSInternals replication denied' }; PrivilegedAccounts=$null }

New-Fixture AD ADPRIV-020 $RECON no-data SKIP 'AdminSDHolder ACL data not available (object-only PASS/FAIL not JSON-representable)' @{ Errors=@{}; PrivilegedAccounts=@{ AdminSDHolderACL=$null } }
New-Fixture AD ADPRIV-020 $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='referral returned from server' }; PrivilegedAccounts=$null }

New-Fixture AD ADPRIV-023 $RECON clean PASS 'krbtgt is disabled and not DES-only' @{ Errors=@{}; PrivilegedAccounts=@{ KrbtgtAccount=@{ PwdAgeDays=90; UACFlags=@{ ACCOUNTDISABLE=$true; USE_DES_KEY_ONLY=$false }; WhenCreated='2024-01-01T00:00:00Z' } } }
New-Fixture AD ADPRIV-023 $RECON known-bad WARN 'krbtgt account is enabled' @{ Errors=@{}; PrivilegedAccounts=@{ KrbtgtAccount=@{ PwdAgeDays=90; UACFlags=@{ ACCOUNTDISABLE=$false; USE_DES_KEY_ONLY=$false }; WhenCreated='2024-01-01T00:00:00Z' } } }
New-Fixture AD ADPRIV-023 $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='referral returned from server' }; PrivilegedAccounts=$null }

New-Fixture AD ADPRIV-028 $RECON clean PASS 'No non-default principals hold DCSync rights' @{ Errors=@{}; DCSyncAccounts=@() }
New-Fixture AD ADPRIV-028 $RECON known-bad FAIL 'A non-default principal holds DCSync replication rights' @{ Errors=@{}; DCSyncAccounts=@(@{ SamAccountName='attacker'; DistinguishedName='CN=attacker,CN=Users,DC=test,DC=local' }) }
New-Fixture AD ADPRIV-028 $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='referral returned from server' }; DCSyncAccounts=$null }

# ── AD password policy ───────────────────────────────────────────────────────
New-Fixture AD ADPWD-010 $RECON clean PASS 'No accounts with blank passwords' @{ ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ BlankPasswordUsers=@() } }
New-Fixture AD ADPWD-010 $RECON known-bad FAIL 'An account has a blank password' @{ ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ BlankPasswordUsers=@(@{ SamAccountName='weakuser' }) } }
New-Fixture AD ADPWD-010 $RECON no-data SKIP 'DSInternals not available; NT-hash analysis not performed' @{ ModuleAvailability=@{ DSInternals=$false }; PasswordPolicies=@{ BlankPasswordUsers=$null } }

# ── AD tier-zero ─────────────────────────────────────────────────────────────
New-Fixture AD ADTIER-001 $RECON clean PASS 'No MSOL_ accounts present' @{ Errors=@{}; TierZero=@{ MsolAccounts=@() } }
New-Fixture AD ADTIER-001 $RECON known-bad WARN 'MSOL_ account sits in CN=Users with an old password' @{ Errors=@{}; TierZero=@{ MsolAccounts=@(@{ SamAccountName='MSOL_abc'; DistinguishedName='CN=MSOL_abc,CN=Users,DC=test,DC=local'; PasswordAgeDays=400 }) } }
New-Fixture AD ADTIER-001 $RECON throttled SKIP 'TierZeroSignals collection failed' @{ Errors=@{ TierZeroSignals='collector error' }; TierZero=$null }

New-Fixture AD ADTIER-002 $RECON clean PASS 'No backup-software service accounts in Tier-0 groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='admin1'; DisplayName='Admin'; Description='standard admin' }) } } }
New-Fixture AD ADTIER-002 $RECON known-bad FAIL 'A Veeam backup account is in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='veeam_svc'; DisplayName='Veeam Backup'; Description='backup service' }) } } }
New-Fixture AD ADTIER-002 $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='referral returned from server' }; PrivilegedAccounts=$null }

New-Fixture AD ADTIER-004 $RECON clean PASS 'No config-management service accounts in Tier-0 groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='admin1'; DisplayName='Admin'; Description='standard admin' }) } } }
New-Fixture AD ADTIER-004 $RECON known-bad FAIL 'An SCCM account is in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='sccm_svc'; DisplayName='SCCM Service'; Description='config management' }) } } }
New-Fixture AD ADTIER-004 $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='referral returned from server' }; PrivilegedAccounts=$null }

# ── AD Kerberos ──────────────────────────────────────────────────────────────
New-Fixture AD ADKERB-002 $RECON clean PASS 'Kerberoastable account supports AES' @{ Errors=@{}; Kerberos=@{ KerberoastableAccounts=@(@{ SamAccountName='svc1'; EncryptionTypes=24; AdminCount=0 }) } }
New-Fixture AD ADKERB-002 $RECON known-bad FAIL 'Kerberoastable account is RC4-only' @{ Errors=@{}; Kerberos=@{ KerberoastableAccounts=@(@{ SamAccountName='svc1'; EncryptionTypes=4; AdminCount=0 }) } }
New-Fixture AD ADKERB-002 $RECON throttled SKIP 'KerberosConfig collection failed' @{ Errors=@{ KerberosConfig='collector error' }; Kerberos=$null }

New-Fixture AD ADKERB-005 $RECON clean PASS 'No user accounts trusted for unconstrained delegation' @{ Errors=@{}; Kerberos=@{ UnconstrainedDelegation=@() } }
New-Fixture AD ADKERB-005 $RECON known-bad FAIL 'A user account is trusted for unconstrained delegation' @{ Errors=@{}; Kerberos=@{ UnconstrainedDelegation=@(@{ ObjectClass=@('user'); SamAccountName='svc_uncon' }) } }
New-Fixture AD ADKERB-005 $RECON throttled SKIP 'KerberosConfig collection failed' @{ Errors=@{ KerberosConfig='collector error' }; Kerberos=$null }

# ── AD trusts ────────────────────────────────────────────────────────────────
foreach ($t in 'ADTRUST-004','ADTRUST-005') {
    New-Fixture AD $t $RECON clean PASS 'External trust has SID filtering enabled' @{ Errors=@{}; Trusts=@(@{ WithinForest=$false; SIDFilteringEnabled=$true; TrustPartner='partner.com' }) }
    New-Fixture AD $t $RECON known-bad FAIL 'External trust has SID filtering disabled' @{ Errors=@{}; Trusts=@(@{ WithinForest=$false; SIDFilteringEnabled=$false; TrustPartner='partner.com' }) }
    New-Fixture AD $t $RECON throttled SKIP 'TrustRelationships collection failed' @{ Errors=@{ TrustRelationships='collector error' }; Trusts=$null }
}

# ── AD group policy ──────────────────────────────────────────────────────────
New-Fixture AD ADGPO-012 $RECON clean PASS 'No cpassword values in SYSVOL GPOs' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ GPO1=@{ CPasswordFound=$false } } } }
New-Fixture AD ADGPO-012 $RECON known-bad FAIL 'A GPP cpassword value is present in SYSVOL' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ GPO1=@{ CPasswordFound=$true; CPasswordLocations=@('Groups.xml') } } } }
New-Fixture AD ADGPO-012 $RECON throttled SKIP 'GroupPolicyObjects collection failed' @{ Errors=@{ GroupPolicyObjects='collector error' }; GroupPolicies=$null }

# ── AD network policy (registry) ─────────────────────────────────────────────
New-Fixture AD ADNET-001 $RECON clean PASS 'DC requires LDAP signing (LDAPServerIntegrity=2)' @{ Errors=@{}; Network=@{ DefaultDCPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'=@{ Value='2' } } } } }
New-Fixture AD ADNET-001 $RECON known-bad FAIL 'DC does not require LDAP signing (LDAPServerIntegrity=0)' @{ Errors=@{}; Network=@{ DefaultDCPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'=@{ Value='0' } } } } }
New-Fixture AD ADNET-001 $RECON throttled SKIP 'NetworkConfig collection failed' @{ Errors=@{ NetworkConfig='collector error' }; Network=$null }

New-Fixture AD ADNET-003 $RECON clean PASS 'SMB server signing required (RequireSecuritySignature=1)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'=@{ Value='1' } } } } }
New-Fixture AD ADNET-003 $RECON known-bad FAIL 'SMB server signing not required (RequireSecuritySignature=0)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'=@{ Value='0' } } } } }
New-Fixture AD ADNET-003 $RECON throttled SKIP 'NetworkConfig collection failed' @{ Errors=@{ NetworkConfig='collector error' }; Network=$null }

New-Fixture AD ADNET-009 $RECON clean PASS 'Print Spooler disabled on DCs (StartType=4)' @{ Errors=@{}; Network=@{ DefaultDCPolicy=@{ Services=@{ Spooler=@{ StartType=4 } } } } }
New-Fixture AD ADNET-009 $RECON known-bad FAIL 'Print Spooler running on DCs (StartType=2)' @{ Errors=@{}; Network=@{ DefaultDCPolicy=@{ Services=@{ Spooler=@{ StartType=2 } } } } }
New-Fixture AD ADNET-009 $RECON throttled SKIP 'NetworkConfig collection failed' @{ Errors=@{ NetworkConfig='collector error' }; Network=$null }

# ── AD ACL delegation ────────────────────────────────────────────────────────
$safeSid = 'S-1-5-18'; $badSid = 'S-1-5-21-1111111111-2222222222-3333333333-1601'
New-Fixture AD ADACL-001 $RECON clean PASS 'No dangerous ACEs on critical objects' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(); CriticalObjectACLs=@{ 'Domain Root'=$null } } }
New-Fixture AD ADACL-001 $RECON known-bad FAIL 'A dangerous ACE exists on the domain root' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ObjectName='Domain Root'; IdentityReference='CORP\BadUser'; IdentitySID=$badSid }); CriticalObjectACLs=@{ 'Domain Root'=$null } } }
New-Fixture AD ADACL-001 $RECON throttled SKIP 'ObjectACLs collection failed' @{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null }

New-Fixture AD ADACL-004 $RECON clean PASS 'WriteDacl held only by a default admin (SYSTEM)' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ActiveDirectoryRights='WriteDacl'; IdentitySID=$safeSid; IdentityReference='NT AUTHORITY\SYSTEM' }) } }
New-Fixture AD ADACL-004 $RECON known-bad FAIL 'WriteDacl held by a non-default principal' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ActiveDirectoryRights='WriteDacl'; IdentitySID=$badSid; IdentityReference='CORP\BadUser' }) } }
New-Fixture AD ADACL-004 $RECON throttled SKIP 'ObjectACLs collection failed' @{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null }

New-Fixture AD ADACL-005 $RECON clean PASS 'WriteOwner held only by a default admin' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ActiveDirectoryRights='WriteOwner'; IdentitySID='S-1-5-32-544'; IdentityReference='BUILTIN\Administrators' }) } }
New-Fixture AD ADACL-005 $RECON known-bad FAIL 'WriteOwner held by a non-default principal' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ActiveDirectoryRights='WriteOwner'; IdentitySID=$badSid; IdentityReference='CORP\BadUser' }) } }
New-Fixture AD ADACL-005 $RECON throttled SKIP 'ObjectACLs collection failed' @{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null }

New-Fixture AD ADACL-007 $RECON clean PASS 'No broad-group ACEs on critical objects' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ IdentitySID=$badSid; IdentityReference='CORP\SpecificUser'; ActiveDirectoryRights='GenericAll'; ObjectName='Domain Root' }) } }
New-Fixture AD ADACL-007 $RECON known-bad FAIL 'Everyone holds GenericAll on the domain root' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ IdentitySID='S-1-1-0'; IdentityReference='Everyone'; ActiveDirectoryRights='GenericAll'; ObjectName='Domain Root'; ObjectDN='DC=corp,DC=local' }) } }
New-Fixture AD ADACL-007 $RECON throttled SKIP 'ObjectACLs collection failed' @{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null }

New-Fixture AD ADACL-010 $RECON clean PASS 'DCSync rights held only by default admins' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ObjectTypeGUID='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; IdentitySID='S-1-5-32-544'; IdentityReference='BUILTIN\Administrators' }) } }
New-Fixture AD ADACL-010 $RECON known-bad FAIL 'A non-default principal holds DS-Replication-Get-Changes-All' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ObjectTypeGUID='1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; ObjectType='DS-Replication-Get-Changes-All'; IdentitySID=$badSid; IdentityReference='CORP\AttackSvc' }) } }
New-Fixture AD ADACL-010 $RECON throttled SKIP 'ObjectACLs collection failed' @{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null }

New-Fixture AD ADACL-016 $RECON clean PASS 'No ACL-based attack paths' @{ Errors=@{}; ACLs=@{ DangerousACEs=@() } }
New-Fixture AD ADACL-016 $RECON known-bad FAIL 'Everyone holds GenericAll on the domain root (high-risk path)' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ IdentitySID='S-1-1-0'; IdentityReference='Everyone'; ActiveDirectoryRights='GenericAll'; ObjectName='Domain Root'; ObjectDN='DC=corp,DC=local' }) } }
New-Fixture AD ADACL-016 $RECON throttled SKIP 'ObjectACLs collection failed' @{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null }

# ── AD attack paths ──────────────────────────────────────────────────────────
$daSid = 'S-1-5-21-1111111111-2222222222-3333333333-512'
$atkSid = 'S-1-5-21-1111111111-2222222222-3333333333-2001'
New-Fixture AD ADPATH-001 $RECON clean PASS 'No non-default principals control Tier-0 objects' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ObjectName='Domain Root'; IdentitySID='S-1-5-32-544'; IdentityReference='BUILTIN\Administrators'; ObjectTypeGUID=$null; IsInherited=$false }) }; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SID=$daSid; SamAccountName='da1'; IsGroup=$false }) } } }
New-Fixture AD ADPATH-001 $RECON known-bad FAIL 'A non-privileged principal has GenericAll over the domain root' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ObjectName='Domain Root'; IdentitySID=$atkSid; IdentityReference='CORP\Attacker'; ActiveDirectoryRights='GenericAll'; ObjectType=$null; ObjectTypeGUID=$null; IsInherited=$false }) }; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@() } } }
New-Fixture AD ADPATH-001 $RECON throttled SKIP 'PrivilegedMembers collection failed' @{ Errors=@{ PrivilegedMembers='collector error' }; ACLs=$null; PrivilegedAccounts=$null }

# NOTE: ADPATH-002 reports MULTI-HOP chains (path length > 1). A deterministic
# FAIL fixture needs a graph-aware construction (source -> intermediate -> Tier-0)
# matched by the BFS node-naming in Get-ADTransitiveAttackPath — deferred as a
# follow-up. ADPATH-001 already covers the single-hop attack-path FAIL verdict.
New-Fixture AD ADPATH-002 $RECON clean PASS 'No multi-hop privilege chains to Tier-0' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ObjectName='Domain Root'; IdentitySID='S-1-5-32-544'; IdentityReference='BUILTIN\Administrators'; ActiveDirectoryRights='GenericAll'; ObjectClass='container' }) }; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='da1'; SID=$daSid; IsGroup=$false }) } } }
New-Fixture AD ADPATH-002 $RECON throttled SKIP 'ObjectACLs collection failed' @{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null; PrivilegedAccounts=$null }

# ── AD certificate services ──────────────────────────────────────────────────
New-Fixture AD ADCS-003 $RECON clean PASS 'No template grants Any-Purpose/no-EKU to low-priv enrollees' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ Name='Secure'; DisplayName='Secure'; IsPublished=$true; ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.2'); EnrollmentPermissions=@(); RASignaturesRequired=0; SchemaVersion=3 }) } }
New-Fixture AD ADCS-003 $RECON known-bad FAIL 'Published template has Any-Purpose EKU with low-priv enroll and no RA signature (ESC2)' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ Name='Vuln'; DisplayName='Vuln'; IsPublished=$true; ExtendedKeyUsageOIDs=@('2.5.29.37.0'); EnrollmentPermissions=@(@{ Right='Enroll'; SID='S-1-5-11'; Identity='Authenticated Users' }); RASignaturesRequired=0; SchemaVersion=3 }) } }
New-Fixture AD ADCS-003 $RECON throttled SKIP 'CertificateServices collection failed' @{ Errors=@{ CertificateServices='collector error' }; CertificateServices=$null }

New-Fixture AD ADCS-006 $RECON clean PASS 'No low-priv write ACEs on templates' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ Name='Secure'; DisplayName='Secure'; IsPublished=$true; EnrollmentPermissions=@(@{ Right='Enroll'; SID='S-1-5-21-1-512'; Identity='Domain Admins' }) }) } }
New-Fixture AD ADCS-006 $RECON known-bad FAIL 'Authenticated Users hold WriteDacl on a template (ESC4)' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ Name='Vuln'; DisplayName='Vuln'; IsPublished=$true; EnrollmentPermissions=@(@{ Right='WriteDacl'; SID='S-1-5-11'; Identity='Authenticated Users' }) }) } }
New-Fixture AD ADCS-006 $RECON throttled SKIP 'CertificateServices collection failed' @{ Errors=@{ CertificateServices='collector error' }; CertificateServices=$null }

New-Fixture AD ADCS-007 $RECON clean PASS 'No low-priv ownership ACEs on templates' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ Name='Secure'; DisplayName='Secure'; IsPublished=$true; EnrollmentPermissions=@(@{ Right='Enroll'; SID='S-1-5-21-1-512'; Identity='Domain Admins' }) }) } }
New-Fixture AD ADCS-007 $RECON known-bad FAIL 'Authenticated Users hold WriteOwner on a template' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ Name='Vuln'; DisplayName='Vuln'; IsPublished=$true; EnrollmentPermissions=@(@{ Right='WriteOwner'; SID='S-1-5-11'; Identity='Authenticated Users' }) }) } }
New-Fixture AD ADCS-007 $RECON throttled SKIP 'CertificateServices collection failed' @{ Errors=@{ CertificateServices='collector error' }; CertificateServices=$null }

# ADCS-009 / ADCS-011 cannot be assessed via LDAP -> always WARN (limitation), SKIP without CA data.
New-Fixture AD ADCS-009 $RECON limitation WARN 'EDITF_ATTRIBUTESUBJECTALTNAME2 lives in CA registry, not LDAP (cannot assess)' @{ Errors=@{}; CertificateServices=@{ CertificateAuthorities=@(@{ Name='CA1'; DNSHostName='ca1.test.local'; Flags=0 }) } }
New-Fixture AD ADCS-009 $RECON throttled SKIP 'CertificateServices collection failed' @{ Errors=@{ CertificateServices='collector error' }; CertificateServices=$null }
New-Fixture AD ADCS-011 $RECON limitation WARN 'HTTP enrollment endpoints require IIS inspection, not LDAP (cannot assess)' @{ Errors=@{}; CertificateServices=@{ CertificateAuthorities=@(@{ DNSHostName='ca1.test.local' }) } }
New-Fixture AD ADCS-011 $RECON throttled SKIP 'CertificateServices collection failed' @{ Errors=@{ CertificateServices='collector error' }; CertificateServices=$null }

# ── AD domain/forest ─────────────────────────────────────────────────────────
New-Fixture AD ADDOM-005 $RECON clean PASS 'All DCs run supported OS' @{ Errors=@{}; DomainControllers=@(@{ ObsoleteOS=$false; Name='DC1'; FQDN='dc1.test.local'; OperatingSystem='Windows Server 2022' }) }
New-Fixture AD ADDOM-005 $RECON known-bad FAIL 'A DC runs an obsolete OS' @{ Errors=@{}; DomainControllers=@(@{ ObsoleteOS=$true; Name='DC1'; FQDN='dc1.test.local'; OperatingSystem='Windows Server 2008' }) }
New-Fixture AD ADDOM-005 $RECON throttled SKIP 'DomainControllers collection failed' @{ Errors=@{ DomainControllers='collector error' }; DomainControllers=$null }

New-Fixture AD ADDOM-013 $RECON clean PASS 'LDAP signing required via GPO (>=2)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ guid1=@{ RegistryPolicies=@(@{ ValueName='LDAPServerIntegrity'; Value=2 }) } } } }
New-Fixture AD ADDOM-013 $RECON known-bad FAIL 'LDAP signing disabled via GPO (0)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ guid1=@{ RegistryPolicies=@(@{ ValueName='LDAPServerIntegrity'; Value=0 }) } } } }
New-Fixture AD ADDOM-013 $RECON throttled SKIP 'GroupPolicyObjects collection failed' @{ Errors=@{ GroupPolicyObjects='collector error' }; GroupPolicies=$null }

New-Fixture AD ADDOM-015 $RECON clean PASS 'SMB signing required via GPO (1)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ guid1=@{ RegistryPolicies=@(@{ ValueName='RequireSecuritySignature'; Key='HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'; Value=1 }) } } } }
New-Fixture AD ADDOM-015 $RECON known-bad FAIL 'SMB signing not required via GPO (0)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ guid1=@{ RegistryPolicies=@(@{ ValueName='RequireSecuritySignature'; Key='HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'; Value=0 }) } } } }
New-Fixture AD ADDOM-015 $RECON throttled SKIP 'GroupPolicyObjects collection failed' @{ Errors=@{ GroupPolicyObjects='collector error' }; GroupPolicies=$null }

New-Fixture AD ADDOM-016 $RECON clean PASS 'NTLMv2-only enforced via GPO (>=3)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ guid1=@{ RegistryPolicies=@(@{ ValueName='LmCompatibilityLevel'; Value=5 }) } } } }
New-Fixture AD ADDOM-016 $RECON known-bad FAIL 'Weak LM compatibility allows NTLMv1 (2)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ guid1=@{ RegistryPolicies=@(@{ ValueName='LmCompatibilityLevel'; Value=2 }) } } } }
New-Fixture AD ADDOM-016 $RECON throttled SKIP 'GroupPolicyObjects collection failed' @{ Errors=@{ GroupPolicyObjects='collector error' }; GroupPolicies=$null }

# ── AD logon scripts ─────────────────────────────────────────────────────────
foreach ($s in @(
    @{ Id='ADSCRIPT-004'; Flag='HardcodedCredentials'; Match='CredentialMatches'; Subj='hardcoded credentials' },
    @{ Id='ADSCRIPT-006'; Flag='PlaintextPasswords';   Match='PasswordMatches';   Subj='plaintext passwords' }
)) {
    New-Fixture AD $s.Id $RECON clean PASS "No logon scripts with $($s.Subj)" @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ "$($s.Flag)"=$false; RelativePath='logon.ps1'; "$($s.Match)"=@() }) } }
    New-Fixture AD $s.Id $RECON known-bad FAIL "A logon script contains $($s.Subj)" @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ "$($s.Flag)"=$true; RelativePath='logon.ps1'; "$($s.Match)"=@(@{ Pattern='secret' }) }) } }
    New-Fixture AD $s.Id $RECON throttled SKIP 'LogonScripts collection failed' @{ Errors=@{ LogonScripts='collector error' }; LogonScripts=$null }
}
New-Fixture AD ADSCRIPT-007 $RECON clean PASS 'No world-writable logon scripts' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ WorldWritable=$false; RelativePath='logon.ps1' }) } }
New-Fixture AD ADSCRIPT-007 $RECON known-bad FAIL 'A logon script is world-writable' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ WorldWritable=$true; RelativePath='logon.ps1' }) } }
New-Fixture AD ADSCRIPT-007 $RECON throttled SKIP 'LogonScripts collection failed' @{ Errors=@{ LogonScripts='collector error' }; LogonScripts=$null }

# ── AD tradecraft ────────────────────────────────────────────────────────────
New-Fixture AD ADTRADE-001 $RECON clean PASS 'SYSVOL readable, no cpassword hits' @{ Errors=@{}; Tradecraft=@{ SysvolReadable=$true; CpasswordHits=@() } }
New-Fixture AD ADTRADE-001 $RECON known-bad FAIL 'cpassword exposure found in SYSVOL' @{ Errors=@{}; Tradecraft=@{ SysvolReadable=$true; CpasswordHits=@(@{ ExposedUser='svc'; FilePath='Groups.xml' }) } }
New-Fixture AD ADTRADE-001 $RECON throttled SKIP 'TradecraftSignals collection failed' @{ Errors=@{ TradecraftSignals='collector error' }; Tradecraft=$null }

New-Fixture AD ADTRADE-006 $RECON clean PASS 'No shadow credentials on collected accounts' @{ Errors=@{}; Tradecraft=@{ ShadowCredCollected=$true; ShadowCredentials=@() } }
New-Fixture AD ADTRADE-006 $RECON known-bad FAIL 'A user account has shadow credentials (msDS-KeyCredentialLink)' @{ Errors=@{}; Tradecraft=@{ ShadowCredCollected=$true; ShadowCredentials=@(@{ IsComputer=$false; IsDomainController=$false; SamAccountName='admin'; ObjectClass='user'; KeyCredentialCount=1 }) } }
New-Fixture AD ADTRADE-006 $RECON throttled SKIP 'TradecraftSignals collection failed' @{ Errors=@{ TradecraftSignals='collector error' }; Tradecraft=$null }

New-Fixture AD ADTRADE-007 $RECON clean PASS 'No risky BadSuccessor dMSA delegation' @{ Errors=@{}; Tradecraft=@{ DmsaClassPresent=$true; DmsaAclCollected=$true; BadSuccessorOus=@() } }
New-Fixture AD ADTRADE-007 $RECON known-bad FAIL 'An OU allows low-priv dMSA creation (BadSuccessor)' @{ Errors=@{}; Tradecraft=@{ DmsaClassPresent=$true; DmsaAclCollected=$true; BadSuccessorOus=@(@{ Name='OU=Workstations'; RiskyAces=@(@{ Principal='Domain Users'; Scope='Subtree' }) }) } }
New-Fixture AD ADTRADE-007 $RECON throttled SKIP 'TradecraftSignals collection failed' @{ Errors=@{ TradecraftSignals='collector error' }; Tradecraft=$null }

# ── Entra applications ───────────────────────────────────────────────────────
New-Fixture Entra EIDAPP-002 $INFIL clean PASS 'No app requests high-risk Graph application permissions' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='Benign'; requiredResourceAccess=@() }) } }
New-Fixture Entra EIDAPP-002 $INFIL known-bad FAIL 'An app requests Application.ReadWrite.All (Role)' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='Risky'; requiredResourceAccess=@(@{ resourceAppId='00000003-0000-0000-c000-000000000000'; resourceAccess=@(@{ type='Role'; id='1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' }) }) }) } }
New-Fixture Entra EIDAPP-002 $INFIL no-data SKIP 'App registrations unavailable' @{ Applications=@{ AppRegistrations=@() } }

New-Fixture Entra EIDAPP-004 $INFIL clean PASS 'No first-party Microsoft SP carries custom credentials' @{ Applications=@{ ServicePrincipals=@(@{ appOwnerOrganizationId='other-tenant'; id='1'; appId='sp1'; displayName='SP1' }) } }
New-Fixture Entra EIDAPP-004 $INFIL known-bad FAIL 'A first-party Microsoft SP has a password credential' @{ Applications=@{ ServicePrincipals=@(@{ appOwnerOrganizationId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'; id='1'; appId='sp1'; displayName='SP1'; passwordCredentials=@(@{ keyId='c1' }) }) } }
New-Fixture Entra EIDAPP-004 $INFIL no-data SKIP 'Service principals unavailable' @{ Applications=@{ ServicePrincipals=@() } }

New-Fixture Entra EIDAPP-014 $INFIL clean PASS 'No app holds Exchange full_access_as_app' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='Benign'; requiredResourceAccess=@() }) } }
New-Fixture Entra EIDAPP-014 $INFIL known-bad FAIL 'An app holds Exchange full_access_as_app (impersonation)' @{ Applications=@{ AppRegistrations=@(@{ appId='a1'; displayName='Impersonator'; requiredResourceAccess=@(@{ resourceAppId='00000002-0000-0ff1-ce00-000000000000'; resourceAccess=@(@{ type='Role'; id='dc890d15-9560-4a4c-9b7f-a736ec74ec40' }) }) }) } }
New-Fixture Entra EIDAPP-014 $INFIL no-data SKIP 'App registrations unavailable' @{ Applications=@{ AppRegistrations=@() } }

# ── Entra auth ───────────────────────────────────────────────────────────────
New-Fixture Entra EIDAUTH-005 $INFIL clean PASS 'All users MFA-registered (0% gap)' @{ AuthMethods=@{ UserRegistrationDetails=@(@{ isMfaRegistered=$true; userPrincipalName='u1@contoso.com'; id='1' }) } }
New-Fixture Entra EIDAUTH-005 $INFIL known-bad FAIL '50% of users lack MFA (>5% gap)' @{ AuthMethods=@{ UserRegistrationDetails=@(@{ isMfaRegistered=$false; userPrincipalName='u1@contoso.com'; id='1' }, @{ isMfaRegistered=$true; userPrincipalName='u2@contoso.com'; id='2' }) } }
New-Fixture Entra EIDAUTH-005 $INFIL no-data SKIP 'User registration details unavailable' @{ AuthMethods=@{ UserRegistrationDetails=@() } }

# EIDAUTH-007 always SKIP (ROCA needs FIDO2 AAGUID metadata not collected)
New-Fixture Entra EIDAUTH-007 $INFIL not-implemented SKIP 'ROCA check intentionally unimplemented (requires FIDO2 metadata)' @{ AuthMethods=@{ UserRegistrationDetails=@(@{ isMfaRegistered=$true; id='1' }) } }

# ── Entra conditional access ─────────────────────────────────────────────────
New-Fixture Entra EIDCA-006 $INFIL clean PASS 'Two+ break-glass accounts excluded from most CA policies' @{ ConditionalAccess=@{ Policies=@(
    @{ state='enabled'; displayName='P1'; id='p1'; conditions=@{ users=@{ excludeUsers=@('bg1','bg2') } } },
    @{ state='enabled'; displayName='P2'; id='p2'; conditions=@{ users=@{ excludeUsers=@('bg1','bg2') } } },
    @{ state='enabled'; displayName='P3'; id='p3'; conditions=@{ users=@{ excludeUsers=@('bg1','bg2') } } }) } }
New-Fixture Entra EIDCA-006 $INFIL known-bad WARN 'Fewer than two break-glass accounts identified' @{ ConditionalAccess=@{ Policies=@(@{ state='enabled'; displayName='P1'; id='p1'; conditions=@{ users=@{ excludeUsers=@() } } }) } }
New-Fixture Entra EIDCA-006 $INFIL no-data SKIP 'No CA policies available' @{ ConditionalAccess=@{ Policies=@() } }

New-Fixture Entra EIDCA-008 $INFIL clean PASS 'Legacy auth blocked for all users' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; displayName='BlockLegacy'; id='p1'; conditions=@{ clientAppTypes=@('exchangeActiveSync','other'); users=@{ includeUsers=@('All') } }; grantControls=@{ builtInControls=@('block') } }) } }
New-Fixture Entra EIDCA-008 $INFIL known-bad FAIL 'No CA policy blocks legacy authentication' @{ Errors=@{}; ConditionalAccess=@{ Errors=@{}; Policies=@(@{ state='enabled'; displayName='MFA'; id='p1'; conditions=@{ clientAppTypes=@(); users=@{ includeUsers=@('All') } }; grantControls=@{ builtInControls=@('mfa') } }) } }
New-Fixture Entra EIDCA-008 $INFIL throttled SKIP 'ConditionalAccess collection failed' @{ Errors=@{ ConditionalAccess='Graph 429' }; ConditionalAccess=@{ Policies=$null } }

# ── Entra federation ─────────────────────────────────────────────────────────
New-Fixture Entra EIDFED-003 $INFIL clean PASS 'No federated domains configured' @{ Errors=@{}; Federation=@{ Errors=@{}; FederationConfigs=@() } }
New-Fixture Entra EIDFED-003 $INFIL throttled SKIP 'Federation collection failed (FAIL path needs a crafted X.509 cert)' @{ Errors=@{ Federation='Graph error' }; Federation=@{ Errors=@{}; FederationConfigs=$null } }

# ── Entra PIM ────────────────────────────────────────────────────────────────
New-Fixture Entra EIDPIM-012 $INFIL clean PASS 'Two+ break-glass Global Admins by naming pattern' @{ Errors=@{}; PIM=@{ Errors=@{}; GlobalAdmins=@(
    @{ displayName='Break-Glass 1'; userPrincipalName='breakglass1@contoso.com'; onPremisesSyncEnabled=$false },
    @{ displayName='Break-Glass 2'; userPrincipalName='bg-admin2@contoso.com'; onPremisesSyncEnabled=$false }) } }
New-Fixture Entra EIDPIM-012 $INFIL known-bad WARN 'Fewer than two break-glass Global Admins' @{ Errors=@{}; PIM=@{ Errors=@{}; GlobalAdmins=@(@{ displayName='Regular Admin'; userPrincipalName='admin1@contoso.com'; onPremisesSyncEnabled=$false }) } }
New-Fixture Entra EIDPIM-012 $INFIL throttled SKIP 'PIM collection failed' @{ Errors=@{ PIM='Graph error' }; PIM=@{ GlobalAdmins=$null } }

# ── Intune ───────────────────────────────────────────────────────────────────
New-Fixture Entra INTUNE-008 $INFIL clean PASS 'A Defender/antivirus profile is deployed' @{ Intune=@{ DeviceConfigurations=@(@{ '@odata.type'='microsoft.graph.windows10EndpointProtectionConfiguration'; displayName='Defender Policy'; id='1' }) } }
New-Fixture Entra INTUNE-008 $INFIL known-bad FAIL 'No Defender/antivirus profile deployed' @{ Intune=@{ DeviceConfigurations=@(@{ '@odata.type'='microsoft.graph.someOtherConfiguration'; displayName='Other'; id='1' }) } }
New-Fixture Entra INTUNE-008 $INFIL throttled SKIP 'Intune collection failed' @{ Errors=@{ Intune='Graph 429' }; Intune=$null }

New-Fixture Entra INTUNE-018 $INFIL clean PASS 'No device management scripts deployed' @{ Intune=@{ DeviceManagementScripts=@() } }
New-Fixture Entra INTUNE-018 $INFIL known-bad WARN 'A SYSTEM-context unsigned script is deployed' @{ Intune=@{ DeviceManagementScripts=@(@{ id='1'; displayName='S1'; fileName='s.ps1'; runAsAccount='system'; enforceSignatureCheck=$false }) } }
New-Fixture Entra INTUNE-018 $INFIL throttled SKIP 'Intune collection failed' @{ Errors=@{ Intune='Graph 429' }; Intune=$null }

New-Fixture Entra INTUNE-023 $INFIL clean PASS 'Approval policies cover all destructive operations (wipe/retire/delete)' @{ Intune=@{ OperationApprovalPolicies=@(
    @{ id='1'; displayName='Wipe Approval';   operationApprovalPolicyType='deviceWipe';   approverGroupIds=@('g1') },
    @{ id='2'; displayName='Retire Approval'; operationApprovalPolicyType='deviceRetire'; approverGroupIds=@('g1') },
    @{ id='3'; displayName='Delete Approval'; operationApprovalPolicyType='deviceDelete'; approverGroupIds=@('g1') }) } }
New-Fixture Entra INTUNE-023 $INFIL known-bad FAIL 'No operation approval policies configured' @{ Intune=@{ OperationApprovalPolicies=@() } }
New-Fixture Entra INTUNE-023 $INFIL throttled SKIP 'Intune collection failed' @{ Errors=@{ Intune='Graph 429' }; Intune=$null }

# ── M365 Exchange ────────────────────────────────────────────────────────────
# NOTE: the 'No policy configured => WARN' branch is unreachable for an EMPTY
# SafeLinksPolicies array — the `-not $exo.SafeLinksPolicies` guard swallows it
# into SKIP first (same empty-array bug as M365EXO-007). So no WARN fixture here.
New-Fixture Entra M365EXO-006 $INFIL clean PASS 'A Safe Links policy is configured' @{ M365Services=@{ Exchange=@{ SafeLinksPolicies=@(@{ Name='SL1'; EnableSafeLinksForEmail=$true; ScanUrls=$true }) } } }
New-Fixture Entra M365EXO-006 $INFIL throttled SKIP 'Exchange collection failed' @{ Errors=@{ M365Services='EXO connect failed' }; M365Services=@{ Exchange=$null } }

New-Fixture Entra M365EXO-015 $INFIL clean PASS 'All domains have valid SPF' @{ M365Services=@{ Exchange=@{ DomainMailSecurity=@(@{ Domain='contoso.com'; SPF=@{ Valid=$true; Record='v=spf1 -all' } }) } } }
New-Fixture Entra M365EXO-015 $INFIL known-bad FAIL 'No domain has valid SPF' @{ M365Services=@{ Exchange=@{ DomainMailSecurity=@(@{ Domain='contoso.com'; SPF=@{ Valid=$false } }) } } }
New-Fixture Entra M365EXO-015 $INFIL throttled SKIP 'Exchange collection failed' @{ Errors=@{ M365Services='EXO connect failed' }; M365Services=@{ Exchange=$null } }

New-Fixture Entra M365EXO-017 $INFIL clean PASS 'All domains have valid DMARC' @{ M365Services=@{ Exchange=@{ DomainMailSecurity=@(@{ Domain='contoso.com'; DMARC=@{ Valid=$true; Record='v=DMARC1; p=reject'; Policy='reject' } }) } } }
New-Fixture Entra M365EXO-017 $INFIL known-bad FAIL 'No domain has valid DMARC' @{ M365Services=@{ Exchange=@{ DomainMailSecurity=@(@{ Domain='contoso.com'; DMARC=@{ Valid=$false } }) } } }
New-Fixture Entra M365EXO-017 $INFIL throttled SKIP 'Exchange collection failed' @{ Errors=@{ M365Services='EXO connect failed' }; M365Services=@{ Exchange=$null } }

# ── Google Workspace ─────────────────────────────────────────────────────────
New-Fixture GoogleWorkspace AUTH-012 $FORT clean PASS 'All super admins enrolled in 2SV' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; isEnrolledIn2Sv=$true; primaryEmail='admin@example.com' }) }
New-Fixture GoogleWorkspace AUTH-012 $FORT known-bad FAIL 'A super admin is not enrolled in 2SV' @{ Errors=@{}; Users=@(@{ isAdmin=$true; suspended=$false; isEnrolledIn2Sv=$false; primaryEmail='admin@example.com' }) }
New-Fixture GoogleWorkspace AUTH-012 $FORT throttled SKIP 'User inventory collection failed' @{ Errors=@{ Users='Admin SDK 429' }; Users=$null }

New-Fixture GoogleWorkspace EMAIL-002 $FORT clean PASS 'All domains have valid DKIM' @{ Errors=@{}; DnsRecords=@{ 'example.com'=@{ DKIM=@{ Valid=$true; Details='' } } } }
New-Fixture GoogleWorkspace EMAIL-002 $FORT known-bad FAIL 'A domain has no valid DKIM' @{ Errors=@{}; DnsRecords=@{ 'example.com'=@{ DKIM=@{ Valid=$false; Details='no key' } } } }
New-Fixture GoogleWorkspace EMAIL-002 $FORT throttled SKIP 'DNS record collection failed' @{ Errors=@{ 'DnsRecords:example.com'='SERVFAIL' }; DnsRecords=$null }

# EMAIL-017 PASS/FAIL need the CloudIdentityPolicies resolver shape; cover SKIP path.
New-Fixture GoogleWorkspace EMAIL-017 $FORT no-data SKIP 'Cloud Identity policy data unavailable (PASS/FAIL need policy-resolver shape)' @{ Errors=@{}; CloudIdentityPolicies=$null }

New-Fixture GoogleWorkspace OAUTH-003 $FORT clean PASS 'No third-party apps hold high-risk scopes' @{ Errors=@{}; OAuthApps=@(@{ Params=@{ app_name='Safe'; scope='https://www.googleapis.com/auth/userinfo.email' } }) }
New-Fixture GoogleWorkspace OAUTH-003 $FORT known-bad FAIL 'Six third-party apps hold high-risk scopes' @{ Errors=@{}; OAuthApps=@(
    @{ Params=@{ app_name='A1'; scope='gmail.readonly' } }, @{ Params=@{ app_name='A2'; scope='admin.directory.user' } },
    @{ Params=@{ app_name='A3'; scope='drive' } }, @{ Params=@{ app_name='A4'; scope='calendar' } },
    @{ Params=@{ app_name='A5'; scope='contacts' } }, @{ Params=@{ app_name='A6'; scope='directory' } }) }
New-Fixture GoogleWorkspace OAUTH-003 $FORT throttled SKIP 'OAuthApps collection failed' @{ Errors=@{ OAuthApps='Reports API 429' }; OAuthApps=$null }

Write-Host "`nDone (critical expansion)."
