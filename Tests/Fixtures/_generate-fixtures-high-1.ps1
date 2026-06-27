#requires -version 7.0
<#
    High-tier fixtures, Round 1: AD identity & privilege.
    ADPRIV / ADACL / ADKERB / ADTIER / ADTRUST / ADSTALE (37 checks).
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-high-1.ps1
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Theater,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; theater=$Theater; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$R='Reconnaissance'
$badSid='S-1-5-21-1111111111-2222222222-3333333333-1601'
$skipPriv=@{ Errors=@{ PrivilegedMembers='referral returned from server' }; PrivilegedAccounts=$null }
$skipAcl =@{ Errors=@{ ObjectACLs='LDAP ACL read failed' }; ACLs=$null }
$skipKerb=@{ Errors=@{ KerberosConfig='collector error' }; Kerberos=$null }

# ── Privileged group emptiness (PASS empty / FAIL members) ──
$grpFail = @(@{ ObjectClass='user'; IsGroup=$false; SamAccountName='m1'; Enabled=$true })
New-Fixture AD ADPRIV-003 $R clean PASS 'Schema Admins empty' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Schema Admins'=@() } } }
New-Fixture AD ADPRIV-003 $R known-bad FAIL 'Schema Admins has 2 members' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Schema Admins'=@(@{ ObjectClass='user'; IsGroup=$false; SamAccountName='m1'; Enabled=$true },@{ ObjectClass='user'; IsGroup=$false; SamAccountName='m2'; Enabled=$true }) } } }
New-Fixture AD ADPRIV-003 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
foreach ($g in @(
    @{ Id='ADPRIV-004'; Grp='Account Operators' }, @{ Id='ADPRIV-005'; Grp='Server Operators' },
    @{ Id='ADPRIV-006'; Grp='Backup Operators' }, @{ Id='ADPRIV-008'; Grp='DnsAdmins' })) {
    New-Fixture AD $g.Id $R clean PASS "$($g.Grp) empty" @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ "$($g.Grp)"=@() } } }
    New-Fixture AD $g.Id $R known-bad FAIL "$($g.Grp) has a member" @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ "$($g.Grp)"=$grpFail } } }
    New-Fixture AD $g.Id $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
}
New-Fixture AD ADPRIV-009 $R clean PASS 'No nested groups in privileged groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; IsGroup=$false; SamAccountName='a'; Enabled=$true }) } } }
New-Fixture AD ADPRIV-009 $R known-bad FAIL 'Nested group inside Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='group'; IsGroup=$true; SamAccountName='nested'; DistinguishedName='CN=nested,DC=t,DC=l' }) } } }
New-Fixture AD ADPRIV-009 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv

# ── UAC-flag / attribute checks on AllPrivilegedUsers ──
foreach ($u in @(@{ Id='ADPRIV-014'; Flag='USE_DES_KEY_ONLY' })) {
    New-Fixture AD $u.Id $R clean PASS "No privileged account with $($u.Flag)" @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ SamAccountName='a'; Enabled=$true; UACFlags=@{ "$($u.Flag)"=$false } }) } }
    New-Fixture AD $u.Id $R known-bad FAIL "A privileged account has $($u.Flag)" @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ SamAccountName='a'; Enabled=$true; UACFlags=@{ "$($u.Flag)"=$true } }) } }
    New-Fixture AD $u.Id $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
}
New-Fixture AD ADPRIV-015 $R clean PASS 'Privileged user requires smartcard' @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ ObjectClass='user'; SamAccountName='a'; Enabled=$true; UACFlags=@{ SMARTCARD_REQUIRED=$true } }) } }
New-Fixture AD ADPRIV-015 $R known-bad FAIL 'No privileged user requires smartcard' @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ ObjectClass='user'; SamAccountName='a'; Enabled=$true; UACFlags=@{ SMARTCARD_REQUIRED=$false } }) } }
New-Fixture AD ADPRIV-015 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
New-Fixture AD ADPRIV-017 $R clean PASS 'Privileged password changed recently' @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ SamAccountName='a'; Enabled=$true; PwdLastSet='2026-05-01T00:00:00Z' }) } }
New-Fixture AD ADPRIV-017 $R known-bad FAIL 'Privileged password older than 365 days' @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ SamAccountName='a'; Enabled=$true; PwdLastSet='2020-01-01T00:00:00Z' }) } }
New-Fixture AD ADPRIV-017 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
New-Fixture AD ADPRIV-019 $R clean PASS 'No disabled accounts in privileged groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; Enabled=$true; SamAccountName='a' }) } } }
New-Fixture AD ADPRIV-019 $R known-bad FAIL 'Disabled account in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; Enabled=$false; SamAccountName='old' }) } } }
New-Fixture AD ADPRIV-019 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
New-Fixture AD ADPRIV-024 $R clean PASS 'No service accounts in privileged groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; IsServiceAccount=$false; SamAccountName='a'; ServicePrincipalName=@(); Enabled=$true }) } } }
New-Fixture AD ADPRIV-024 $R known-bad FAIL 'Service account in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; IsServiceAccount=$true; SamAccountName='svc_app'; ServicePrincipalName=@('app/h'); Enabled=$true }) } } }
New-Fixture AD ADPRIV-024 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
New-Fixture AD ADPRIV-025 $R clean PASS 'No computer accounts in privileged groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; IsComputer=$false; SamAccountName='a'; DistinguishedName='CN=a,DC=t,DC=l' }) } } }
New-Fixture AD ADPRIV-025 $R known-bad FAIL 'Computer account in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='computer'; IsComputer=$true; SamAccountName='PC1$'; DistinguishedName='CN=PC1,DC=t,DC=l' }) } } }
New-Fixture AD ADPRIV-025 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv

# ── DC logon rights (UserRightsAssignment) ──
foreach ($l in @(@{ Id='ADPRIV-026'; Key='InteractiveLogon' },@{ Id='ADPRIV-027'; Key='RemoteInteractiveLogon' })) {
    New-Fixture AD $l.Id $R clean PASS "Only Tier-0 principals hold the DC logon right" @{ PrivilegedAccounts=@{ UserRightsAssignment=@{ "$($l.Key)"=@(@{ Name='Domain Admins'; Sid='S-1-5-21-1-512'; IsExpected=$true }) } } }
    New-Fixture AD $l.Id $R known-bad FAIL "A non-Tier-0 principal holds the DC logon right" @{ PrivilegedAccounts=@{ UserRightsAssignment=@{ "$($l.Key)"=@(@{ Name='CORP\User'; Sid=$badSid; IsExpected=$false }) } } }
    New-Fixture AD $l.Id $R no-data SKIP 'DC security template not readable' @{ PrivilegedAccounts=@{ UserRightsAssignment=@{ "$($l.Key)"=$null } } }
}
New-Fixture AD ADPRIV-029 $R clean PASS 'Protected Users group is populated' @{ Errors=@{}; PrivilegedAccounts=@{ ProtectedUsersMembers=@(@{ SamAccountName='a'; Enabled=$true }) } }
New-Fixture AD ADPRIV-029 $R known-bad WARN 'Protected Users group is empty' @{ Errors=@{}; PrivilegedAccounts=@{ ProtectedUsersMembers=@() } }
New-Fixture AD ADPRIV-029 $R no-data SKIP 'Protected Users data unavailable (key absent)' @{ Errors=@{}; PrivilegedAccounts=@{} }
New-Fixture AD ADPRIV-030 $R clean PASS 'Privileged account is in Protected Users' @{ Errors=@{}; PrivilegedAccounts=@{ ProtectedUsersMembers=@(@{ DistinguishedName='CN=a,DC=t,DC=l' }); PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; Enabled=$true; IsComputer=$false; IsServiceAccount=$false; DistinguishedName='CN=a,DC=t,DC=l'; SamAccountName='a' }) } } }
New-Fixture AD ADPRIV-030 $R known-bad FAIL 'Privileged account missing from Protected Users' @{ Errors=@{}; PrivilegedAccounts=@{ ProtectedUsersMembers=@(); PrivilegedGroups=@{ 'Domain Admins'=@(@{ ObjectClass='user'; Enabled=$true; IsComputer=$false; IsServiceAccount=$false; DistinguishedName='CN=a,DC=t,DC=l'; SamAccountName='a' }) } } }
New-Fixture AD ADPRIV-030 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv

# ── ACL delegation ──
New-Fixture AD ADACL-003 $R clean PASS 'No non-default GenericWrite on critical objects' @{ Errors=@{}; ACLs=@{ DangerousACEs=@() } }
New-Fixture AD ADACL-003 $R known-bad FAIL 'Non-default principal has GenericWrite on domain root' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ActiveDirectoryRights='GenericWrite'; IdentitySID=$badSid; IdentityReference='CORP\U'; ObjectName='DC=t,DC=l' }) } }
New-Fixture AD ADACL-003 $R throttled SKIP 'ObjectACLs failed' $skipAcl
New-Fixture AD ADACL-006 $R clean PASS 'No non-default User-Force-Change-Password rights' @{ Errors=@{}; ACLs=@{ DangerousACEs=@() } }
New-Fixture AD ADACL-006 $R known-bad FAIL 'Non-default principal can force-change passwords' @{ Errors=@{}; ACLs=@{ DangerousACEs=@(@{ ObjectTypeGUID='00299570-246d-11d0-a768-00aa006e0529'; IdentitySID=$badSid; IdentityReference='CORP\Helpdesk'; ObjectName='CN=Users,DC=t,DC=l' }) } }
New-Fixture AD ADACL-006 $R throttled SKIP 'ObjectACLs failed' $skipAcl
New-Fixture AD ADACL-009 $R clean PASS 'MachineAccountQuota is 0' @{ Errors=@{}; ACLs=@{ MachineAccountQuota=0 } }
New-Fixture AD ADACL-009 $R known-bad FAIL 'MachineAccountQuota is 10' @{ Errors=@{}; ACLs=@{ MachineAccountQuota=10 } }
New-Fixture AD ADACL-009 $R throttled SKIP 'ObjectACLs failed' $skipAcl
New-Fixture AD ADACL-011 $R clean PASS 'Domain root owned by Domain Admins' @{ Errors=@{}; ACLs=@{ CriticalObjectACLs=@{ 'Domain Root'=@{} }; DomainRootOwner='Domain Admins' } }
New-Fixture AD ADACL-011 $R known-bad FAIL 'Domain root owned by a non-default principal' @{ Errors=@{}; ACLs=@{ CriticalObjectACLs=@{ 'Domain Root'=@{} }; DomainRootOwner='CORP\BadUser' } }
New-Fixture AD ADACL-011 $R throttled SKIP 'ObjectACLs failed' $skipAcl
New-Fixture AD ADACL-012 $R clean PASS 'Domain root ACEs are all held by default admins' @{ Errors=@{}; ACLs=@{ CriticalObjectACLs=@{ 'Domain Root'=@{ ACEs=@(@{ AccessControlType='Allow'; ActiveDirectoryRights='GenericAll'; IdentitySID='S-1-5-18'; IdentityReference='NT AUTHORITY\SYSTEM' }) } } } }
New-Fixture AD ADACL-012 $R known-bad FAIL 'Dangerous allow ACE on domain root' @{ Errors=@{}; ACLs=@{ CriticalObjectACLs=@{ 'Domain Root'=@{ ACEs=@(@{ AccessControlType='Allow'; ActiveDirectoryRights='GenericWrite'; IdentitySID=$badSid; IdentityReference='CORP\U' }) } } } }
New-Fixture AD ADACL-012 $R throttled SKIP 'ObjectACLs failed' $skipAcl
New-Fixture AD ADACL-013 $R clean PASS 'No gPLink-modify rights on critical OUs' @{ Errors=@{}; ACLs=@{ CriticalObjectACLs=@{ 'Domain Root'=@{ ACEs=@() }; 'Domain Controllers OU'=@{ ACEs=@() } } } }
New-Fixture AD ADACL-013 $R known-bad FAIL 'Non-default principal can modify gPLink on domain root' @{ Errors=@{}; ACLs=@{ CriticalObjectACLs=@{ 'Domain Root'=@{ ACEs=@(@{ AccessControlType='Allow'; ActiveDirectoryRights='GenericWrite'; IdentitySID=$badSid; IdentityReference='CORP\U'; ObjectTypeGUID=$null }) } } } }
New-Fixture AD ADACL-013 $R throttled SKIP 'ObjectACLs failed' $skipAcl
New-Fixture AD ADACL-014 $R clean PASS 'GPOs editable only by default admins' @{ Errors=@{}; ACLs=@{ GPOPermissions=@{ 'Default Domain Policy'=@{ CanEdit=@('Domain Admins'); DN='cn=p,DC=t,DC=l' } } } }
New-Fixture AD ADACL-014 $R known-bad FAIL 'A GPO is editable by a non-default principal' @{ Errors=@{}; ACLs=@{ GPOPermissions=@{ 'Default Domain Policy'=@{ CanEdit=@('CORP\UnprivUser'); DN='cn=p,DC=t,DC=l' } } } }
New-Fixture AD ADACL-014 $R throttled SKIP 'ObjectACLs failed' $skipAcl

# ── Kerberos ──
New-Fixture AD ADKERB-001 $R clean PASS 'No Kerberoastable accounts' @{ Errors=@{}; Kerberos=@{ KerberoastableAccounts=@() } }
New-Fixture AD ADKERB-001 $R known-bad FAIL 'A user account has an SPN (Kerberoastable)' @{ Errors=@{}; Kerberos=@{ KerberoastableAccounts=@(@{ SamAccountName='svc'; AdminCount=0; SPNs=@('mssql/db') }) } }
New-Fixture AD ADKERB-001 $R throttled SKIP 'KerberosConfig failed' $skipKerb
New-Fixture AD ADKERB-003 $R clean PASS 'No AS-REP roastable accounts' @{ Errors=@{}; Kerberos=@{ ASREPRoastableAccounts=@() } }
New-Fixture AD ADKERB-003 $R known-bad FAIL 'An account is AS-REP roastable' @{ Errors=@{}; Kerberos=@{ ASREPRoastableAccounts=@(@{ SamAccountName='u'; AdminCount=0 }) } }
New-Fixture AD ADKERB-003 $R throttled SKIP 'KerberosConfig failed' $skipKerb
New-Fixture AD ADKERB-006 $R clean PASS 'No constrained delegation configured' @{ Errors=@{}; Kerberos=@{ ConstrainedDelegation=@() } }
New-Fixture AD ADKERB-006 $R known-bad WARN 'Constrained delegation present (review)' @{ Errors=@{}; Kerberos=@{ ConstrainedDelegation=@(@{ SamAccountName='svc'; ObjectClass=@('user'); AllowedToDelegateTo=@('http/s1') }) } }
New-Fixture AD ADKERB-006 $R throttled SKIP 'KerberosConfig failed' $skipKerb
New-Fixture AD ADKERB-007 $R clean PASS 'No resource-based constrained delegation' @{ Errors=@{}; Kerberos=@{ RBCD=@() } }
New-Fixture AD ADKERB-007 $R known-bad WARN 'RBCD present (review)' @{ Errors=@{}; Kerberos=@{ RBCD=@(@{ SamAccountName='c1'; AllowedPrincipals=@('DOMAIN\u1') }) } }
New-Fixture AD ADKERB-007 $R throttled SKIP 'KerberosConfig failed' $skipKerb
New-Fixture AD ADKERB-008 $R clean PASS 'No protocol-transition delegation' @{ Errors=@{}; Kerberos=@{ ProtocolTransition=@(); ConstrainedDelegation=@() } }
New-Fixture AD ADKERB-008 $R known-bad FAIL 'Protocol-transition with delegation target (abuse path)' @{ Errors=@{}; Kerberos=@{ ProtocolTransition=@(@{ SamAccountName='svc'; ObjectClass=@('user'); AllowedToDelegateTo=@('host/dc1') }); ConstrainedDelegation=@() } }
New-Fixture AD ADKERB-008 $R throttled SKIP 'KerberosConfig failed' $skipKerb
New-Fixture AD ADKERB-009 $R clean PASS 'DCs and accounts use AES' @{ Errors=@{}; Kerberos=@{ EncryptionTypes=@{ Summary=@{ TotalDCs=1; DESEnabled=0; RC4Enabled=0; AESEnabled=1 }; DomainControllers=@(@{ HasAES=$true; HasRC4=$false }) }; KerberoastableAccounts=@() } }
New-Fixture AD ADKERB-009 $R known-bad FAIL 'DES encryption enabled on a DC' @{ Errors=@{}; Kerberos=@{ EncryptionTypes=@{ Summary=@{ TotalDCs=1; DESEnabled=1; RC4Enabled=0; AESEnabled=0 }; DomainControllers=@(@{ HasAES=$false; HasRC4=$false }) }; KerberoastableAccounts=@() } }
New-Fixture AD ADKERB-009 $R no-data SKIP 'Encryption type data unavailable' @{ Errors=@{}; Kerberos=@{ EncryptionTypes=$null } }

# ── Tier-zero pattern matches ──
New-Fixture AD ADTIER-003 $R clean PASS 'No hypervisor service accounts in Tier-0 groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='a'; DisplayName='Admin'; Description='admin'; ObjectClass='user' }) } } }
New-Fixture AD ADTIER-003 $R known-bad FAIL 'A vCenter account is in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='svc_vcenter'; DisplayName='vCenter'; Description='VMware vCenter'; ObjectClass='user' }) } } }
New-Fixture AD ADTIER-003 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
New-Fixture AD ADTIER-005 $R clean PASS 'No database service accounts in Tier-0 groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='a'; DisplayName='Admin'; Description='admin'; ObjectClass='user' }) } } }
New-Fixture AD ADTIER-005 $R known-bad FAIL 'A SQL service account is in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='sqlsvc_prod'; DisplayName='SQL'; Description='SQL Server service'; ObjectClass='user' }) } } }
New-Fixture AD ADTIER-005 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
New-Fixture AD ADTIER-006 $R clean PASS 'Tier-0 admins live under a dedicated admin OU' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ Group='Domain Admins'; SamAccountName='t0'; DistinguishedName='CN=t0,OU=Tier-0,OU=Admin,DC=t,DC=l'; ObjectClass='user' }); 'Enterprise Admins'=@(); 'Schema Admins'=@(); 'Backup Operators'=@() } } }
New-Fixture AD ADTIER-006 $R known-bad WARN 'A Tier-0 admin is not in a dedicated admin OU' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ Group='Domain Admins'; SamAccountName='bad'; DistinguishedName='CN=bad,OU=Users,DC=t,DC=l'; ObjectClass='user' }); 'Enterprise Admins'=@(); 'Schema Admins'=@(); 'Backup Operators'=@() } } }
New-Fixture AD ADTIER-006 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv
New-Fixture AD ADTIER-007 $R clean PASS 'No service-named accounts in Tier-0 groups' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='jsmith'; ObjectClass='user' }) } } }
New-Fixture AD ADTIER-007 $R known-bad FAIL 'A service-named account is in Domain Admins' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Domain Admins'=@(@{ SamAccountName='svc_backup'; ObjectClass='user' }) } } }
New-Fixture AD ADTIER-007 $R throttled SKIP 'PrivilegedMembers failed' $skipPriv

# ── Trusts (empty Trusts => PASS; SKIP only via Errors) ──
New-Fixture AD ADTRUST-006 $R clean PASS 'External trust uses selective authentication' @{ Errors=@{}; Trusts=@(@{ TrustPartner='p.com'; WithinForest=$false; SelectiveAuthentication=$true }) }
New-Fixture AD ADTRUST-006 $R known-bad FAIL 'External trust lacks selective authentication' @{ Errors=@{}; Trusts=@(@{ TrustPartner='p.com'; WithinForest=$false; SelectiveAuthentication=$false }) }
New-Fixture AD ADTRUST-006 $R throttled SKIP 'TrustRelationships failed' @{ Errors=@{ TrustRelationships='collector error' }; Trusts=$null }
New-Fixture AD ADTRUST-010 $R clean PASS 'Trust password rotated within 180 days' @{ Errors=@{}; Trusts=@(@{ TrustPartner='p.com'; TrustDirection='Bidirectional'; WhenChanged='2026-05-01T00:00:00Z' }) }
New-Fixture AD ADTRUST-010 $R known-bad WARN 'Trust password older than 180 days' @{ Errors=@{}; Trusts=@(@{ TrustPartner='p.com'; TrustDirection='Bidirectional'; WhenChanged='2020-01-01T00:00:00Z' }) }
New-Fixture AD ADTRUST-010 $R throttled SKIP 'TrustRelationships failed' @{ Errors=@{ TrustRelationships='collector error' }; Trusts=$null }

# ── Stale objects (missing StaleObjects => SKIP; empty arrays => PASS) ──
New-Fixture AD ADSTALE-005 $R clean PASS 'No obsolete-OS computers' @{ Errors=@{}; StaleObjects=@{ ObsoleteOSComputers=@(); TotalComputers=100 } }
New-Fixture AD ADSTALE-005 $R known-bad FAIL 'An obsolete-OS computer exists' @{ Errors=@{}; StaleObjects=@{ ObsoleteOSComputers=@(@{ SamAccountName='OLD$'; DN='CN=OLD,DC=t,DC=l'; OperatingSystem='Windows Server 2003'; Enabled=$true }); TotalComputers=100 } }
New-Fixture AD ADSTALE-005 $R no-data SKIP 'Stale object data unavailable' @{ Errors=@{}; StaleObjects=$null }
New-Fixture AD ADSTALE-006 $R clean PASS 'No unsupported-OS computers' @{ Errors=@{}; StaleObjects=@{ UnsupportedOSComputers=@(); TotalComputers=100 } }
New-Fixture AD ADSTALE-006 $R known-bad FAIL 'An unsupported-OS computer exists' @{ Errors=@{}; StaleObjects=@{ UnsupportedOSComputers=@(@{ SamAccountName='OLD$'; DN='CN=OLD,DC=t,DC=l'; OperatingSystem='Windows 7'; Enabled=$true }); TotalComputers=100 } }
New-Fixture AD ADSTALE-006 $R no-data SKIP 'Stale object data unavailable' @{ Errors=@{}; StaleObjects=$null }

Write-Host "`nDone (high round 1)."
