#requires -version 7.0
<#
    Medium-tier fixtures, Round 1: AD (48 checks).
    ADPWD/ADGPO/ADDOM/ADPRIV/ADKERB/ADCS/ADACL/ADNET/ADLOG/ADSCRIPT/ADTRADE/ADSTALE/ADTRUST.
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-medium-1.ps1

    Notes: ADSTALE-003/004/007/008/011 + most ADTRUST/ADGPO return WARN (not FAIL).
    Always-WARN: ADGPO-019/020/022, ADNET-006, ADLOG-007. No-PASS: ADDOM-020.
    Always-PASS-on-data: ADGPO-016, ADSCRIPT-011. Always-SKIP: ADPWD-019.
    TimeSpan-typed clean PASS deferred: ADPWD-003 covered via empty-FGPP PASS;
    ADPWD-008/022 clean PASS need [TimeSpan] (FAIL+SKIP only). datetime => ISO-8601 strings.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Theater,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; theater=$Theater; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 14 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$R='Reconnaissance'
$skPwd  =@{ Errors=@{ PasswordPolicies='collector error' }; PasswordPolicies=$null }
$skGPO  =@{ Errors=@{ GroupPolicyObjects='collector error' }; GroupPolicies=$null }
$skDI   =@{ Errors=@{ DomainInfo='collector error' }; Domain=$null }
$skPriv =@{ Errors=@{ PrivilegedMembers='collector error' }; PrivilegedAccounts=$null }
$skKerb =@{ Errors=@{ KerberosConfig='collector error' }; Kerberos=$null }
$skCS   =@{ Errors=@{ CertificateServices='collector error' }; CertificateServices=$null }
$skAcl  =@{ Errors=@{ ObjectACLs='collector error' }; ACLs=$null }
$skNet  =@{ Errors=@{ NetworkConfig='collector error' }; Network=$null }
$skLS   =@{ Errors=@{ LogonScripts='collector error' }; LogonScripts=$null }
$skTC   =@{ Errors=@{ TradecraftSignals='collector error' }; Tradecraft=$null }
$skStale=@{ Errors=@{ StaleObjects='collector error' }; StaleObjects=$null }
$skTrust=@{ Errors=@{ TrustRelationships='collector error' }; Trusts=$null }
$recent='2026-05-01T00:00:00Z'; $old='2023-01-01T00:00:00Z'

# ── ADPWD ──
New-Fixture AD ADPWD-002 $R clean PASS 'No fine-grained password policies defined' @{ Errors=@{}; PasswordPolicies=@{ FineGrainedPolicies=@() } }
New-Fixture AD ADPWD-002 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-003 $R clean PASS 'No FGPP weaker than the default policy' @{ Errors=@{}; PasswordPolicies=@{ FineGrainedPolicies=@(); DefaultPolicy=@{ MinPasswordLength=14; PasswordComplexity=$true; PasswordHistoryCount=24 } } }
New-Fixture AD ADPWD-003 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-007 $R clean PASS 'Password history >= 24' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ PasswordHistoryCount=24 } } }
New-Fixture AD ADPWD-007 $R known-bad FAIL 'Password history 8 (<12)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ PasswordHistoryCount=8 } } }
New-Fixture AD ADPWD-007 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-008 $R known-bad FAIL 'Max password age unset/0 (never expires)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ MinPasswordLength=14 } } }
New-Fixture AD ADPWD-008 $R throttled SKIP 'Password policy not assessed (clean PASS needs TimeSpan MaxPasswordAge)' $skPwd
New-Fixture AD ADPWD-013 $R clean PASS 'No dictionary-based passwords' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ DictionaryMatchUsers=@() } }
New-Fixture AD ADPWD-013 $R known-bad FAIL 'An account uses a dictionary password' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ DictionaryMatchUsers=@(@{ SamAccountName='u1' }) } }
New-Fixture AD ADPWD-013 $R no-data SKIP 'DSInternals unavailable' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$false }; PasswordPolicies=@{} }
New-Fixture AD ADPWD-015 $R clean PASS 'Few passwords older than 365 days (<=20%)' @{ Errors=@{}; PasswordPolicies=@{ UsersPasswordNeverExpires=@() }; AllUsers=@(@{ PwdLastSet=$recent },@{ PwdLastSet=$recent }) }
New-Fixture AD ADPWD-015 $R known-bad WARN 'Most passwords older than 365 days (>20%)' @{ Errors=@{}; PasswordPolicies=@{ UsersPasswordNeverExpires=@() }; AllUsers=@(@{ PwdLastSet=$old },@{ PwdLastSet=$old },@{ PwdLastSet=$old },@{ PwdLastSet=$recent }) }
New-Fixture AD ADPWD-015 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-017 $R clean PASS 'LAPS deployed with managed expiration' @{ Errors=@{}; PasswordPolicies=@{ LAPSDeployed=$true; LAPSExpirationDays=$null; LAPSType='Windows' } }
New-Fixture AD ADPWD-017 $R known-bad WARN 'LAPS expiration too long (90 days)' @{ Errors=@{}; PasswordPolicies=@{ LAPSDeployed=$true; LAPSExpirationDays=90; LAPSType='Windows' } }
New-Fixture AD ADPWD-017 $R no-data SKIP 'LAPS not deployed' @{ Errors=@{}; PasswordPolicies=@{ LAPSDeployed=$false } }
New-Fixture AD ADPWD-019 $R not-implemented SKIP 'Entra password protection requires Azure portal (not collected)' @{ Errors=@{}; PasswordPolicies=@{} }
New-Fixture AD ADPWD-022 $R known-bad FAIL 'Lockout disabled (threshold 0)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ LockoutThreshold=0 } } }
New-Fixture AD ADPWD-022 $R throttled SKIP 'Password policy not assessed (clean PASS needs TimeSpan observation window)' $skPwd

# ── ADGPO ──
$gpoDN='CN={12345678-1234-1234-1234-123456789012},CN=Policies,CN=System,DC=t,DC=l'
New-Fixture AD ADGPO-006 $R clean PASS 'All GPO links reference valid GPOs' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DN=$gpoDN; DisplayName='P1'; GUID='{1}' }); GPOLinks=@{ 'OU=T,DC=t,DC=l'=@(@{ GPODN=$gpoDN; IsEnabled=$true }) } } }
New-Fixture AD ADGPO-006 $R known-bad WARN 'A GPO link references a missing GPO' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DN=$gpoDN; DisplayName='P1'; GUID='{1}' }); GPOLinks=@{ 'OU=T,DC=t,DC=l'=@(@{ GPODN='CN={9999},CN=Policies,CN=System,DC=t,DC=l'; IsEnabled=$true }) } } }
New-Fixture AD ADGPO-006 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-008 $R clean PASS 'No WMI filters configured' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='P1' }); WMIFilters=@() } }
New-Fixture AD ADGPO-008 $R known-bad WARN 'A WMI filter is configured (review)' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='P1' }); WMIFilters=@(@{ Name='F1'; Description='d'; Query='select * from x' }) } }
New-Fixture AD ADGPO-008 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-009 $R clean PASS 'Linked GPO has Apply permission' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='P1'; GUID='{1}'; IsLinked=$true }); GPOPermissions=@{ P1=@{ CanApply=@('Domain Admins') } } } }
New-Fixture AD ADGPO-009 $R known-bad WARN 'Linked GPO has no Apply permission' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='P1'; GUID='{1}'; IsLinked=$true }); GPOPermissions=@{ P1=@{ CanApply=@() } } } }
New-Fixture AD ADGPO-009 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-010 $R clean PASS 'GPO versions match AD and SYSVOL' @{ Errors=@{}; GroupPolicies=@{ GPOVersionMismatch=@(); SYSVOLContent=@{} } }
New-Fixture AD ADGPO-010 $R known-bad FAIL 'A GPO version mismatch between AD and SYSVOL' @{ Errors=@{}; GroupPolicies=@{ GPOVersionMismatch=@(@{ DisplayName='P1'; GUID='{1}'; ADVersionUser=1; ADVersionComputer=0; SYSVOLVersionUser=2; SYSVOLVersionComputer=0 }); SYSVOLContent=@{} } }
New-Fixture AD ADGPO-010 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-014 $R clean PASS 'No MSI packages in GPO SYSVOL folders' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ PreferenceFiles=@('a.xml'); ScriptFiles=@('b.bat') } } } }
New-Fixture AD ADGPO-014 $R known-bad WARN 'An MSI package is staged in a GPO SYSVOL folder' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ PreferenceFiles=@('app.msi'); ScriptFiles=@() } } } }
New-Fixture AD ADGPO-014 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-016 $R clean PASS 'Registry.pol inventory (informational)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ HasRegistryPol=$true } } } }
New-Fixture AD ADGPO-016 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-019 $R informational WARN 'Windows Firewall GPO presence (informational)' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='Default Domain Policy' }); SYSVOLContent=@{ G1=@{ HasRegistryPol=$false } } } }
New-Fixture AD ADGPO-019 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-020 $R informational WARN 'PowerShell-policy GPO presence (informational)' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='Default Domain Policy' }); SYSVOLContent=@{ G1=@{ HasRegistryPol=$false } } } }
New-Fixture AD ADGPO-020 $R throttled SKIP 'Group Policy not assessed' $skGPO
New-Fixture AD ADGPO-022 $R informational WARN 'AppLocker/WDAC GPO presence (informational)' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='Default Domain Policy' }); SYSVOLContent=@{ G1=@{ HasRegistryPol=$false; PreferenceFiles=@() } } } }
New-Fixture AD ADGPO-022 $R throttled SKIP 'Group Policy not assessed' $skGPO

# ── ADDOM ──
New-Fixture AD ADDOM-003 $R clean PASS 'Schema version current (>=88)' @{ Errors=@{}; Domain=@{ SchemaVersion=88; SchemaVersionName='2016' } }
New-Fixture AD ADDOM-003 $R known-bad FAIL 'Schema version legacy (<87)' @{ Errors=@{}; Domain=@{ SchemaVersion=85; SchemaVersionName='2003' } }
New-Fixture AD ADDOM-003 $R throttled SKIP 'Domain info not assessed' $skDI
New-Fixture AD ADDOM-008 $R clean PASS 'Tombstone lifetime >= 180 days' @{ Errors=@{}; Domain=@{ TombstoneLifetime=180 } }
New-Fixture AD ADDOM-008 $R known-bad FAIL 'Tombstone lifetime 30 days (<60)' @{ Errors=@{}; Domain=@{ TombstoneLifetime=30 } }
New-Fixture AD ADDOM-008 $R throttled SKIP 'Domain info not assessed' $skDI
New-Fixture AD ADDOM-009 $R clean PASS 'AD Recycle Bin enabled' @{ Errors=@{}; Domain=@{ RecycleBinEnabled=$true } }
New-Fixture AD ADDOM-009 $R known-bad FAIL 'AD Recycle Bin disabled' @{ Errors=@{}; Domain=@{ RecycleBinEnabled=$false } }
New-Fixture AD ADDOM-009 $R throttled SKIP 'Domain info not assessed' $skDI
New-Fixture AD ADDOM-010 $R clean PASS 'All sites have subnets assigned' @{ Errors=@{}; Domain=@{ Sites=@(@{ Name='Site1'; Subnets=@('10.0.0.0/8') }) } }
New-Fixture AD ADDOM-010 $R known-bad WARN 'A site has no subnets assigned' @{ Errors=@{}; Domain=@{ Sites=@(@{ Name='Site1'; Subnets=@() }) } }
New-Fixture AD ADDOM-010 $R throttled SKIP 'Domain info not assessed' $skDI
New-Fixture AD ADDOM-020 $R known-bad FAIL 'DSRM admin allowed to log on over network' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ RegistryPolicies=@(@{ ValueName='DsrmAdminLogonBehavior'; Value=1 }) } } }; DomainControllers=@(@{ Name='DC1' }) }
New-Fixture AD ADDOM-020 $R degraded WARN 'DSRM logon behavior 0 (cannot fully verify, no PASS path)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ RegistryPolicies=@(@{ ValueName='DsrmAdminLogonBehavior'; Value=0 }) } } }; DomainControllers=@(@{ Name='DC1' }) }
New-Fixture AD ADDOM-020 $R throttled SKIP 'Group Policy not assessed' $skGPO

# ── ADPRIV ──
New-Fixture AD ADPRIV-007 $R clean PASS 'Print Operators group empty' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Print Operators'=@() } } }
New-Fixture AD ADPRIV-007 $R known-bad WARN 'Print Operators group has a member' @{ Errors=@{}; PrivilegedAccounts=@{ PrivilegedGroups=@{ 'Print Operators'=@(@{ SamAccountName='u1'; Enabled=$true; ObjectClass='user' }) } } }
New-Fixture AD ADPRIV-007 $R throttled SKIP 'Privileged members not assessed' $skPriv
New-Fixture AD ADPRIV-018 $R clean PASS 'All privileged accounts have logged in' @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ SamAccountName='admin1'; LastLogonTimestamp=$recent }) } }
New-Fixture AD ADPRIV-018 $R known-bad WARN 'A privileged account has never logged in' @{ Errors=@{}; PrivilegedAccounts=@{ AllPrivilegedUsers=@(@{ SamAccountName='admin1'; LastLogonTimestamp=0 }) } }
New-Fixture AD ADPRIV-018 $R throttled SKIP 'Privileged members not assessed' $skPriv
New-Fixture AD ADPRIV-021 $R clean PASS 'No adminCount orphans' @{ Errors=@{}; PrivilegedAccounts=@{ AdminCountOrphans=@() } }
New-Fixture AD ADPRIV-021 $R known-bad FAIL 'An adminCount orphan exists' @{ Errors=@{}; PrivilegedAccounts=@{ AdminCountOrphans=@(@{ SamAccountName='orphan1'; DistinguishedName='CN=orphan1,DC=t,DC=l'; Enabled=$false }) } }
New-Fixture AD ADPRIV-021 $R throttled SKIP 'Privileged members not assessed' $skPriv

# ── ADKERB / ADCS / ADACL ──
New-Fixture AD ADKERB-010 $R clean PASS 'Kerberos ticket lifetimes within recommended limits' @{ Errors=@{}; Kerberos=@{ KerberosPolicy=@{ MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=$null; MaxClockSkew=$null } } }
New-Fixture AD ADKERB-010 $R known-bad FAIL 'Kerberos ticket lifetimes exceed limits' @{ Errors=@{}; Kerberos=@{ KerberosPolicy=@{ MaxTicketAge=24; MaxRenewAge=14; MaxServiceAge=$null; MaxClockSkew=$null } } }
New-Fixture AD ADKERB-010 $R throttled SKIP 'Kerberos config not assessed' $skKerb
New-Fixture AD ADCS-015 $R clean PASS 'No published v1 templates with low-priv enrollment' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$false; SchemaVersion=1; ExtendedKeyUsageOIDs=@(); EnrollmentPermissions=@() }) } }
New-Fixture AD ADCS-015 $R known-bad FAIL 'A published v1 template is enrollable by Authenticated Users' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; SchemaVersion=1; ExtendedKeyUsageOIDs=@(); EnrollmentPermissions=@(@{ Right='Enroll'; SID='S-1-5-11'; Identity='Authenticated Users' }) }) } }
New-Fixture AD ADCS-015 $R throttled SKIP 'Certificate services not assessed' $skCS
New-Fixture AD ADACL-008 $R clean PASS 'No non-default OU delegations' @{ Errors=@{}; ACLs=@{ OUDelegation=@() } }
New-Fixture AD ADACL-008 $R known-bad WARN 'A broad principal holds GenericAll on an OU' @{ Errors=@{}; ACLs=@{ OUDelegation=@(@{ OUDN='OU=T,DC=t,DC=l'; ActiveDirectoryRights='GenericAll'; IdentityReference='Domain Users'; IdentitySID='S-1-5-21-1-2-3-513' }) } }
New-Fixture AD ADACL-008 $R throttled SKIP 'Object ACLs not assessed' $skAcl

# ── ADNET / ADLOG / ADSCRIPT / ADTRADE ──
# ADNET-006 is purely always-WARN and ignores the error map (no SKIP path).
New-Fixture AD ADNET-006 $R always-warn WARN 'NetBIOS over TCP/IP not verifiable via GPO (manual)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{} } }
New-Fixture AD ADNET-008 $R clean PASS 'WPAD (WinHttpAutoProxySvc) disabled (StartType 4)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Services=@{ WinHttpAutoProxySvc=@{ StartType=4 } } } } }
New-Fixture AD ADNET-008 $R known-bad WARN 'WPAD service not disabled via policy' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Services=@{ WinHttpAutoProxySvc=@{ StartType=3 } } } } }
New-Fixture AD ADNET-008 $R throttled SKIP 'Network config not assessed' $skNet
New-Fixture AD ADLOG-003 $R clean PASS 'PowerShell Module Logging enabled (1)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging'=@{ Value=1 } } } } }
New-Fixture AD ADLOG-003 $R known-bad WARN 'PowerShell Module Logging not enabled' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging'=@{ Value=0 } } } } }
New-Fixture AD ADLOG-003 $R throttled SKIP 'Network config not assessed' $skNet
New-Fixture AD ADLOG-007 $R always-warn WARN 'Sysmon presence not detectable from AD (manual)' @{ Errors=@{} }
New-Fixture AD ADSCRIPT-009 $R clean PASS 'NETLOGON files have expected extensions/structure' @{ Errors=@{}; LogonScripts=@{ NetlogonFiles=@(@{ Extension='.bat'; RelativePath='logon.bat'; Size=100 }); ScriptAnalysis=@() } }
New-Fixture AD ADSCRIPT-009 $R known-bad WARN 'A NETLOGON file has an unusual extension' @{ Errors=@{}; LogonScripts=@{ NetlogonFiles=@(@{ Extension='.unknown'; RelativePath='x.unknown'; Size=100 }); ScriptAnalysis=@() } }
New-Fixture AD ADSCRIPT-009 $R throttled SKIP 'Logon scripts not assessed' $skLS
New-Fixture AD ADSCRIPT-011 $R clean PASS 'Logon-script inventory compiled (informational)' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(); NetlogonFiles=@(@{ Extension='.bat'; RelativePath='logon.bat' }); UserScripts=@() } }
New-Fixture AD ADSCRIPT-011 $R throttled SKIP 'Logon scripts not assessed' $skLS
New-Fixture AD ADTRADE-003 $R clean PASS 'No stale BitLocker recovery keys' @{ Errors=@{}; Tradecraft=@{ BitLockerKeys=@() } }
New-Fixture AD ADTRADE-003 $R known-bad WARN 'A BitLocker recovery key is older than 365 days' @{ Errors=@{}; Tradecraft=@{ BitLockerKeys=@(@{ WhenCreated=$old; DistinguishedName='CN=Key'; ParentComputer='COMP1' }) } }
New-Fixture AD ADTRADE-003 $R throttled SKIP 'Tradecraft signals not assessed' $skTC

# ── ADSTALE (present arrays => WARN for 003/004/007/008/011; FAIL for 001/002) ──
New-Fixture AD ADSTALE-001 $R clean PASS 'No inactive user accounts' @{ Errors=@{}; StaleObjects=@{ InactiveUsers=@(); TotalUsers=100 } }
New-Fixture AD ADSTALE-001 $R known-bad FAIL 'An inactive user account exists' @{ Errors=@{}; StaleObjects=@{ InactiveUsers=@(@{ SamAccountName='u1'; DN='CN=u1,DC=t,DC=l'; LastLogon=$old; Enabled=$true; MemberOf=@() }); TotalUsers=100 } }
New-Fixture AD ADSTALE-001 $R throttled SKIP 'Stale object data not assessed' $skStale
New-Fixture AD ADSTALE-002 $R clean PASS 'No inactive computer accounts' @{ Errors=@{}; StaleObjects=@{ InactiveComputers=@(); TotalComputers=50 } }
New-Fixture AD ADSTALE-002 $R known-bad FAIL 'An inactive computer account exists' @{ Errors=@{}; StaleObjects=@{ InactiveComputers=@(@{ SamAccountName='c1'; Name='C1'; DN='CN=c1,DC=t,DC=l'; LastLogon=$old; OperatingSystem='Windows Server 2008'; Enabled=$true }); TotalComputers=50 } }
New-Fixture AD ADSTALE-002 $R throttled SKIP 'Stale object data not assessed' $skStale
New-Fixture AD ADSTALE-003 $R clean PASS 'No disabled accounts retain group memberships' @{ Errors=@{}; StaleObjects=@{ DisabledWithGroups=@(); TotalDisabled=10 } }
New-Fixture AD ADSTALE-003 $R known-bad WARN 'A disabled account retains group memberships' @{ Errors=@{}; StaleObjects=@{ DisabledWithGroups=@(@{ SamAccountName='d1'; DN='CN=d1,DC=t,DC=l'; GroupCount=2; Groups=@('CN=G1,DC=t,DC=l') }); TotalDisabled=10 } }
New-Fixture AD ADSTALE-003 $R throttled SKIP 'Stale object data not assessed' $skStale
New-Fixture AD ADSTALE-004 $R clean PASS 'No enabled accounts with expired passwords' @{ Errors=@{}; StaleObjects=@{ ExpiredNotDisabled=@(); TotalUsers=100 } }
New-Fixture AD ADSTALE-004 $R known-bad WARN 'An enabled account has an expired password' @{ Errors=@{}; StaleObjects=@{ ExpiredNotDisabled=@(@{ SamAccountName='e1'; DN='CN=e1,DC=t,DC=l'; PwdLastSet=$old; Enabled=$true }); TotalUsers=100 } }
New-Fixture AD ADSTALE-004 $R throttled SKIP 'Stale object data not assessed' $skStale
New-Fixture AD ADSTALE-007 $R clean PASS 'No orphaned Foreign Security Principals' @{ Errors=@{}; StaleObjects=@{ OrphanedFSPs=@() } }
New-Fixture AD ADSTALE-007 $R known-bad WARN 'An orphaned FSP with an unresolvable SID exists' @{ Errors=@{}; StaleObjects=@{ OrphanedFSPs=@(@{ SID='S-1-5-21-1-2-3-9999'; DN='CN=S-1-5-21-1-2-3-9999,CN=ForeignSecurityPrincipals,DC=t,DC=l' }) } }
New-Fixture AD ADSTALE-007 $R throttled SKIP 'Stale object data not assessed' $skStale
New-Fixture AD ADSTALE-008 $R clean PASS 'No orphaned SID History entries' @{ Errors=@{}; StaleObjects=@{ OrphanedSIDHistory=@() } }
New-Fixture AD ADSTALE-008 $R known-bad WARN 'An object has orphaned SID History entries' @{ Errors=@{}; StaleObjects=@{ OrphanedSIDHistory=@(@{ SamAccountName='u1'; DN='CN=u1,DC=t,DC=l'; OrphanedSIDs=@('S-1-5-21-1-1-1-500'); TotalSIDHistory=1 }) } }
New-Fixture AD ADSTALE-008 $R throttled SKIP 'Stale object data not assessed' $skStale
New-Fixture AD ADSTALE-011 $R clean PASS 'No stale DNS records' @{ Errors=@{}; StaleObjects=@{ StaleDNSRecords=@() } }
New-Fixture AD ADSTALE-011 $R known-bad WARN 'A stale DNS record exists' @{ Errors=@{}; StaleObjects=@{ StaleDNSRecords=@(@{ Name='stale.t.l'; DN='CN=stale,...'; WhenChanged=$old; Tombstoned=$false }) } }
New-Fixture AD ADSTALE-011 $R throttled SKIP 'Stale object data not assessed' $skStale

# ── ADTRUST (empty Trusts => PASS; 002/003 => FAIL, 007/008/009 => WARN) ──
New-Fixture AD ADTRUST-002 $R clean PASS 'No inbound/bidirectional trusts' @{ Errors=@{}; Trusts=@() }
New-Fixture AD ADTRUST-002 $R known-bad FAIL 'An inbound trust allows external authentication' @{ Errors=@{}; Trusts=@(@{ TrustPartner='trusted.com'; TrustDirection='Inbound'; TrustType='External'; WithinForest=$false; IsTransitive=$false }) }
New-Fixture AD ADTRUST-002 $R throttled SKIP 'Trust relationships not assessed' $skTrust
New-Fixture AD ADTRUST-003 $R clean PASS 'No transitive trusts' @{ Errors=@{}; Trusts=@() }
New-Fixture AD ADTRUST-003 $R known-bad FAIL 'A transitive trust extends authentication paths' @{ Errors=@{}; Trusts=@(@{ TrustPartner='trusted.com'; TrustDirection='Outbound'; TrustType='External'; ForestTransitive=$false; WithinForest=$false; IsTransitive=$true }) }
New-Fixture AD ADTRUST-003 $R throttled SKIP 'Trust relationships not assessed' $skTrust
New-Fixture AD ADTRUST-007 $R clean PASS 'No Azure AD trust relationships' @{ Errors=@{}; Trusts=@() }
New-Fixture AD ADTRUST-007 $R known-bad WARN 'An Azure AD trust is present (review)' @{ Errors=@{}; Trusts=@(@{ TrustPartner='contoso.onmicrosoft.com'; IsAzureAD=$true; FlatName='CONTOSO'; TrustDirection='Bidirectional'; TrustType='External'; SelectiveAuthentication=$false; SIDFilteringEnabled=$false; WhenCreated=$old; WhenChanged=$old }) }
New-Fixture AD ADTRUST-007 $R throttled SKIP 'Trust relationships not assessed' $skTrust
New-Fixture AD ADTRUST-008 $R clean PASS 'No foreign/external domain trusts' @{ Errors=@{}; Trusts=@() }
New-Fixture AD ADTRUST-008 $R known-bad WARN 'A foreign/external domain trust is present (review)' @{ Errors=@{}; Trusts=@(@{ TrustPartner='external-org.com'; TrustDirection='Bidirectional'; TrustType='External'; WithinForest=$false; ForestTransitive=$false; IsTransitive=$true; SIDFilteringEnabled=$false; SelectiveAuthentication=$false; TreatAsExternal=$false; WhenCreated=$old }) }
New-Fixture AD ADTRUST-008 $R throttled SKIP 'Trust relationships not assessed' $skTrust
New-Fixture AD ADTRUST-009 $R clean PASS 'No orphaned trusts' @{ Errors=@{}; Trusts=@() }
New-Fixture AD ADTRUST-009 $R known-bad WARN 'An orphaned/stale trust (>365 days) is present' @{ Errors=@{}; Trusts=@(@{ TrustPartner='old-domain.com'; TrustDirection='Outbound'; TrustType='External'; TrustSID='S-1-5-21-1-2-3'; WhenChanged=$old }) }
New-Fixture AD ADTRUST-009 $R throttled SKIP 'Trust relationships not assessed' $skTrust

Write-Host "`nDone (medium round 1)."
