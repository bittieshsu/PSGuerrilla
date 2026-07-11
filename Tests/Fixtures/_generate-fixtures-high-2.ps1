#requires -version 7.0
<#
    High-tier fixtures, Round 2: AD infrastructure.
    ADCS / ADDOM / ADGPO / ADNET / ADLOG / ADSCRIPT / ADTRADE (47 checks).
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-high-2.ps1

    Special cases pinned here:
      - ADCS-012 (ESC9) & ADGPO-017: no reachable PASS path (probable bugs) -> WARN/SKIP only.
      - ADCS-013/018, ADGPO-011, ADLOG-005/006: by-design always-WARN (out-of-band/LDAP-blind).
      - ADGPO-018/021: no PASS path by design (present=>WARN, absent=>FAIL).
      - ADLOG-001: filesystem-dependent PASS/FAIL -> SKIP-only fixture.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Platform,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; platform=$Platform; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$R='AD'
$badSid='S-1-5-21-1111111111-2222222222-3333333333-1601'
$skCS  =@{ Errors=@{ CertificateServices='collector error' }; CertificateServices=$null }
$skGPO =@{ Errors=@{ GroupPolicyObjects='collector error' }; GroupPolicies=$null }
$skNet =@{ Errors=@{ NetworkConfig='collector error' }; Network=$null }
$skDI  =@{ Errors=@{ DomainInfo='collector error' }; Domain=$null }
$skDC  =@{ Errors=@{ DomainControllers='collector error' }; DomainControllers=$null }
$skLS  =@{ Errors=@{ LogonScripts='collector error' }; LogonScripts=$null }
$skTC  =@{ Errors=@{ TradecraftSignals='collector error' }; Tradecraft=$null }

# ── ADCS ──
New-Fixture AD ADCS-004 $R clean PASS 'No template grants Cert Request Agent EKU to low-priv' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.2'); EnrollmentPermissions=@(); Name='Safe'; DisplayName='Safe'; SchemaVersion=3 }) } }
New-Fixture AD ADCS-004 $R known-bad FAIL 'Enrollment-agent template enrollable by Everyone (ESC3)' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; ExtendedKeyUsageOIDs=@('1.3.6.1.4.1.311.20.2.1'); EnrollmentPermissions=@(@{ Right='Enroll'; SID='S-1-1-0'; Identity='Everyone' }); Name='Agent'; DisplayName='Agent'; SchemaVersion=3 }) } }
New-Fixture AD ADCS-004 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-005 $R clean PASS 'No RA-signed enrollment-agent template' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; RASignaturesRequired=0; ApplicationPolicies=@(); ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.2'); Name='Safe'; DisplayName='Safe'; SchemaVersion=3; ExtendedKeyUsage=@() }) } }
New-Fixture AD ADCS-005 $R known-bad FAIL 'RA-signed template with enrollment-agent policy (ESC3#2)' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; RASignaturesRequired=1; ApplicationPolicies=@('1.3.6.1.4.1.311.20.2.1'); ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.2'); Name='RA'; DisplayName='RA'; SchemaVersion=3; ExtendedKeyUsage=@(@{ Name='Client Authentication' }) }) } }
New-Fixture AD ADCS-005 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-008 $R clean PASS 'No low-priv write ACEs on PKI container objects' @{ Errors=@{}; CertificateServices=@{ PKIObjects=@(@{ Permissions=@(); Name='CN=PKS'; DN='CN=Public Key Services,...'; ObjectClass='container' }) } }
New-Fixture AD ADCS-008 $R known-bad FAIL 'Authenticated Users hold WriteDacl on a PKI object' @{ Errors=@{}; CertificateServices=@{ PKIObjects=@(@{ Permissions=@(@{ Right='WriteDacl'; SID='S-1-5-11'; Identity='Authenticated Users' }); Name='CN=PKS'; DN='CN=Public Key Services,...'; ObjectClass='container' }) } }
New-Fixture AD ADCS-008 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-012 $R compat-mode WARN 'StrongCertificateBindingEnforcement in compatibility mode (no reachable PASS path)' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@() }; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ RegistryPolicies=@(@{ ValueName='StrongCertificateBindingEnforcement'; Value=1 }) } } } }
New-Fixture AD ADCS-012 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-013 $R limitation WARN 'IF_ENFORCEENCRYPTICERTREQUEST not assessable via LDAP' @{ Errors=@{}; CertificateServices=@{ CertificateAuthorities=@(@{ Name='CA1'; DNSHostName='ca1.t.l' }) } }
New-Fixture AD ADCS-013 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-014 $R clean PASS 'No OID linked to a security group' @{ Errors=@{}; CertificateServices=@{ OIDObjects=@(@{ HasGroupLink=$false; Name='OID1'; OID='1.2.3'; DN='CN=OID1' }); CertificateTemplates=@() } }
New-Fixture AD ADCS-014 $R known-bad FAIL 'An OID is linked to a security group (ESC13)' @{ Errors=@{}; CertificateServices=@{ OIDObjects=@(@{ HasGroupLink=$true; Name='OID1'; OID='1.2.3'; GroupLink='DOMAIN\Grp'; DN='CN=OID1' }); CertificateTemplates=@() } }
New-Fixture AD ADCS-014 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-016 $R clean PASS 'No UPN-SAN auth template enrollable by low-priv' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; CertificateNameFlag=0; EnrolleeSuppliesSubject=$false; ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.1'); EnrollmentPermissions=@(); Name='Safe'; DisplayName='Safe'; SchemaVersion=3 }) } }
New-Fixture AD ADCS-016 $R known-bad FAIL 'UPN-SAN auth template enrollable by Authenticated Users (ESC1-like)' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; CertificateNameFlag=33554432; EnrolleeSuppliesSubject=$false; ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.2'); EnrollmentPermissions=@(@{ Right='Enroll'; SID='S-1-5-11'; Identity='Authenticated Users' }); Name='UPN'; DisplayName='UPN'; SchemaVersion=3; ExtendedKeyUsage=@(@{ Name='Client Authentication' }) }) } }
New-Fixture AD ADCS-016 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-017 $R clean PASS 'No V1/any-purpose template enrollable by low-priv' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; SchemaVersion=3; ExtendedKeyUsageOIDs=@('1.3.6.1.5.5.7.3.1'); RASignaturesRequired=0; EnrollmentPermissions=@(); Name='Safe'; DisplayName='Safe'; ExtendedKeyUsage=@() }) } }
New-Fixture AD ADCS-017 $R known-bad FAIL 'V1 no-EKU template enrollable by Everyone' @{ Errors=@{}; CertificateServices=@{ CertificateTemplates=@(@{ IsPublished=$true; SchemaVersion=1; ExtendedKeyUsageOIDs=@(); RASignaturesRequired=0; EnrollmentPermissions=@(@{ Right='Enroll'; SID='S-1-1-0'; Identity='Everyone' }); Name='V1'; DisplayName='V1'; ExtendedKeyUsage=@() }) } }
New-Fixture AD ADCS-017 $R throttled SKIP 'CertificateServices failed' $skCS
New-Fixture AD ADCS-018 $R limitation WARN 'CA AuditFilter not assessable via LDAP' @{ Errors=@{}; CertificateServices=@{ CertificateAuthorities=@(@{ Name='CA1'; DNSHostName='ca1.t.l' }) } }
New-Fixture AD ADCS-018 $R throttled SKIP 'CertificateServices failed' $skCS

# ── ADDOM ──
New-Fixture AD ADDOM-001 $R clean PASS 'Forest functional level current (>=7)' @{ Errors=@{}; Domain=@{ ForestFunctionalLevel=7; ForestFunctionalLevelName='2016' } }
New-Fixture AD ADDOM-001 $R known-bad FAIL 'Forest functional level legacy (<6)' @{ Errors=@{}; Domain=@{ ForestFunctionalLevel=4; ForestFunctionalLevelName='2003' } }
New-Fixture AD ADDOM-001 $R throttled SKIP 'DomainInfo failed' $skDI
New-Fixture AD ADDOM-002 $R clean PASS 'Domain functional level current (>=7)' @{ Errors=@{}; Domain=@{ DomainFunctionalLevel=7; DomainFunctionalLevelName='2016' } }
New-Fixture AD ADDOM-002 $R known-bad FAIL 'Domain functional level legacy (<6)' @{ Errors=@{}; Domain=@{ DomainFunctionalLevel=3; DomainFunctionalLevelName='2000' } }
New-Fixture AD ADDOM-002 $R throttled SKIP 'DomainInfo failed' $skDI
New-Fixture AD ADDOM-004 $R clean PASS 'Multiple domain controllers (redundancy)' @{ Errors=@{}; DomainControllers=@(@{ Name='DC1'; FQDN='dc1.t.l'; OperatingSystem='Windows Server 2019'; IsGlobalCatalog=$true; IsRODC=$false; ObsoleteOS=$false },@{ Name='DC2'; FQDN='dc2.t.l'; OperatingSystem='Windows Server 2019'; IsGlobalCatalog=$true; IsRODC=$false; ObsoleteOS=$false }) }
New-Fixture AD ADDOM-004 $R known-bad WARN 'Single domain controller (no redundancy)' @{ Errors=@{}; DomainControllers=@(@{ Name='DC1'; FQDN='dc1.t.l'; OperatingSystem='Windows Server 2019'; IsGlobalCatalog=$true; IsRODC=$false; ObsoleteOS=$false }) }
New-Fixture AD ADDOM-004 $R throttled SKIP 'DomainControllers failed' $skDC
New-Fixture AD ADDOM-007 $R clean PASS 'Replication healthy (single DC)' @{ Errors=@{}; Domain=@{ ReplicationHealth=@{ SingleDC=$true } } }
New-Fixture AD ADDOM-007 $R known-bad FAIL 'Replication failures detected' @{ Errors=@{}; Domain=@{ ReplicationHealth=@(@{ Status='Failure'; ErrorCode=1 }) } }
New-Fixture AD ADDOM-007 $R throttled SKIP 'DomainInfo failed' $skDI
New-Fixture AD ADDOM-012 $R clean PASS 'AD-integrated zones require secure dynamic updates' @{ Errors=@{}; Domain=@{ DnsZones=@(@{ Name='c.com'; ZoneType='AD-Forward'; DynamicUpdate=2 }) } }
New-Fixture AD ADDOM-012 $R known-bad FAIL 'A zone allows nonsecure dynamic updates' @{ Errors=@{}; Domain=@{ DnsZones=@(@{ Name='c.com'; ZoneType='AD-Forward'; DynamicUpdate=1 }) } }
New-Fixture AD ADDOM-012 $R throttled SKIP 'DomainInfo failed' $skDI
New-Fixture AD ADDOM-014 $R clean PASS 'LDAP channel binding always enforced (2)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ RegistryPolicies=@(@{ ValueName='LdapEnforceChannelBinding'; Value=2 }) } } } }
New-Fixture AD ADDOM-014 $R known-bad FAIL 'LDAP channel binding disabled (0)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ RegistryPolicies=@(@{ ValueName='LdapEnforceChannelBinding'; Value=0 }) } } } }
New-Fixture AD ADDOM-014 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADDOM-017 $R clean PASS 'NTLMv2-only fully enforced (5)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ SecuritySettings=@{ LmCompatibilityLevel=5 } } } } }
New-Fixture AD ADDOM-017 $R known-bad FAIL 'LM/NTLMv1 allowed (<3)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ SecuritySettings=@{ LmCompatibilityLevel=0 } } } } }
New-Fixture AD ADDOM-017 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADDOM-018 $R clean PASS 'Anonymous access restricted' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ SecuritySettings=@{ RestrictAnonymous=1; RestrictAnonymousSAM=1 } } } } }
New-Fixture AD ADDOM-018 $R known-bad FAIL 'Anonymous access not restricted' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ SecuritySettings=@{ RestrictAnonymous=0; RestrictAnonymousSAM=0 } } } } }
New-Fixture AD ADDOM-018 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADDOM-019 $R clean PASS 'Print Spooler disabled on DCs via GPO' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ SystemServices=@{ Spooler=@{ StartupMode=4 } } } } } }
New-Fixture AD ADDOM-019 $R known-bad FAIL 'Print Spooler enabled on DCs via GPO' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ g1=@{ SystemServices=@{ Spooler=@{ StartupMode=2 } } } } } }
New-Fixture AD ADDOM-019 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO

# ── ADGPO ──
New-Fixture AD ADGPO-007 $R clean PASS 'GPOs editable only by admins' @{ Errors=@{}; GroupPolicies=@{ GPOPermissions=@{ G1=@{ CanEdit=@('Domain Admins','SYSTEM') } } } }
New-Fixture AD ADGPO-007 $R known-bad FAIL 'A non-admin can edit a GPO' @{ Errors=@{}; GroupPolicies=@{ GPOPermissions=@{ G1=@{ CanEdit=@('Domain Admins','CORP\UntrustedUser') } } } }
New-Fixture AD ADGPO-007 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADGPO-011 $R informational WARN 'GPO registry/preference inventory (informational, always WARN)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ HasRegistryPol=$true; HasPreferences=$false } } } }
New-Fixture AD ADGPO-011 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADGPO-013 $R clean PASS 'No script files in GPO SYSVOL folders' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ HasScripts=$false; ScriptFiles=@() } } } }
New-Fixture AD ADGPO-013 $R known-bad WARN 'GPO contains script files (review)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ HasScripts=$true; ScriptFiles=@('logon.ps1') } } } }
New-Fixture AD ADGPO-013 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADGPO-015 $R clean PASS 'No scheduled-task GPP files' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ PreferenceFiles=@() } } } }
New-Fixture AD ADGPO-015 $R known-bad WARN 'GPO deploys scheduled tasks (review)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ PreferenceFiles=@('ScheduledTasks.xml') } } } }
New-Fixture AD ADGPO-015 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADGPO-017 $R informational WARN 'Restricted Groups review (no reachable PASS path)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ PreferenceFiles=@() } } } }
New-Fixture AD ADGPO-017 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADGPO-018 $R audit-present WARN 'Audit-policy GPO present (verify coverage)' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ HasRegistryPol=$true; PreferenceFiles=@() } } } }
New-Fixture AD ADGPO-018 $R known-bad FAIL 'No audit-policy GPO detected' @{ Errors=@{}; GroupPolicies=@{ SYSVOLContent=@{ G1=@{ HasRegistryPol=$false; PreferenceFiles=@() } } } }
New-Fixture AD ADGPO-018 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADGPO-021 $R logging-present WARN 'PowerShell-logging GPO present (verify)' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='PowerShell Logging Policy' }); SYSVOLContent=@{ G1=@{ HasRegistryPol=$true } } } }
New-Fixture AD ADGPO-021 $R known-bad FAIL 'No PowerShell-logging GPO detected' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(); SYSVOLContent=@{ G1=@{ HasRegistryPol=$false } } } }
New-Fixture AD ADGPO-021 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO
New-Fixture AD ADGPO-023 $R clean PASS 'LAPS GPO present and linked' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='LAPS Policy'; GUID='{1}'; IsLinked=$true }); SYSVOLContent=@{ G1=@{ HasRegistryPol=$false } } } }
New-Fixture AD ADGPO-023 $R known-bad WARN 'LAPS GPO present but not linked' @{ Errors=@{}; GroupPolicies=@{ GPOs=@(@{ DisplayName='LAPS Policy'; GUID='{1}'; IsLinked=$false }); SYSVOLContent=@{ G1=@{ HasRegistryPol=$false } } } }
New-Fixture AD ADGPO-023 $R throttled SKIP 'GroupPolicyObjects failed' $skGPO

# ── ADNET ──
New-Fixture AD ADNET-002 $R clean PASS 'LDAP channel binding required (2)' @{ Errors=@{}; Network=@{ DefaultDCPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'=@{ Value='2' } } } } }
New-Fixture AD ADNET-002 $R known-bad FAIL 'LDAP channel binding disabled (0)' @{ Errors=@{}; Network=@{ DefaultDCPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'=@{ Value='0' } } } } }
New-Fixture AD ADNET-002 $R throttled SKIP 'NetworkConfig failed' $skNet
New-Fixture AD ADNET-004 $R clean PASS 'SMB client signing required (1)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'=@{ Value='1' } } } } }
New-Fixture AD ADNET-004 $R known-bad FAIL 'SMB client signing not required (0)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'=@{ Value='0' } } } } }
New-Fixture AD ADNET-004 $R throttled SKIP 'NetworkConfig failed' $skNet
New-Fixture AD ADNET-005 $R clean PASS 'LLMNR disabled (0)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'=@{ Value='0' } } } } }
New-Fixture AD ADNET-005 $R known-bad FAIL 'LLMNR enabled (1)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'=@{ Value='1' } } } } }
New-Fixture AD ADNET-005 $R throttled SKIP 'NetworkConfig failed' $skNet
New-Fixture AD ADNET-007 $R clean PASS 'IPv6 fully disabled (0xFF)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents'=@{ Value='255' } } } } }
New-Fixture AD ADNET-007 $R known-bad WARN 'IPv6 only partially restricted (no FAIL path)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents'=@{ Value='32' } } } } }
New-Fixture AD ADNET-007 $R throttled SKIP 'NetworkConfig failed' $skNet
New-Fixture AD ADNET-010 $R clean PASS 'WebClient (WebDAV) disabled (4)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Services=@{ WebClient=@{ StartType=4 } } } } }
New-Fixture AD ADNET-010 $R known-bad FAIL 'WebClient (WebDAV) auto-start (2)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Services=@{ WebClient=@{ StartType=2 } } } } }
New-Fixture AD ADNET-010 $R throttled SKIP 'NetworkConfig failed' $skNet

# ── ADLOG ──
New-Fixture AD ADLOG-001 $R no-data SKIP 'Connection metadata absent (PASS/FAIL need SYSVOL filesystem access)' @{ Errors=@{} }
New-Fixture AD ADLOG-002 $R clean PASS 'PowerShell Script Block Logging enabled (1)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'=@{ Value='1' } } } } }
New-Fixture AD ADLOG-002 $R known-bad FAIL 'Script Block Logging explicitly disabled (0)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'=@{ Value='0' } } } } }
New-Fixture AD ADLOG-002 $R throttled SKIP 'NetworkConfig failed' $skNet
New-Fixture AD ADLOG-004 $R clean PASS 'Process-creation cmdline auditing enabled (1)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{ 'MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'=@{ Value='1' } } } } }
New-Fixture AD ADLOG-004 $R known-bad WARN 'Cmdline auditing not verifiable (no FAIL path)' @{ Errors=@{}; Network=@{ DefaultDomainPolicy=@{ Registry=@{} } } }
New-Fixture AD ADLOG-004 $R throttled SKIP 'NetworkConfig failed' $skNet
New-Fixture AD ADLOG-005 $R always-warn WARN 'Defender Tamper Protection set in MDE cloud (LDAP-blind)' @{ Errors=@{} }
New-Fixture AD ADLOG-006 $R always-warn WARN 'WEF SubscriptionManager requires host registry check' @{ Errors=@{} }

# ── ADSCRIPT ──
New-Fixture AD ADSCRIPT-001 $R clean PASS 'NETLOGON write restricted to admins' @{ Errors=@{}; LogonScripts=@{ NetlogonPermissions=@{ Owner='BUILTIN\Administrators'; AccessRules=@(@{ AccessType='Allow'; Identity='BUILTIN\Administrators'; Rights='FullControl' },@{ AccessType='Allow'; Identity='NT AUTHORITY\SYSTEM'; Rights='Read' }) } } }
New-Fixture AD ADSCRIPT-001 $R known-bad FAIL 'NETLOGON writable by Everyone' @{ Errors=@{}; LogonScripts=@{ NetlogonPermissions=@{ Owner='BUILTIN\Administrators'; AccessRules=@(@{ AccessType='Allow'; Identity='BUILTIN\Administrators'; Rights='FullControl' },@{ AccessType='Allow'; Identity='Everyone'; Rights='Write' }) } } }
New-Fixture AD ADSCRIPT-001 $R throttled SKIP 'LogonScripts failed' $skLS
New-Fixture AD ADSCRIPT-002 $R clean PASS 'SYSVOL write restricted to admins' @{ Errors=@{}; LogonScripts=@{ SysvolPermissions=@{ Owner='BUILTIN\Administrators'; AccessRules=@(@{ AccessType='Allow'; Identity='BUILTIN\Administrators'; Rights='FullControl' },@{ AccessType='Allow'; Identity='NT AUTHORITY\SYSTEM'; Rights='Read' }) } } }
New-Fixture AD ADSCRIPT-002 $R known-bad FAIL 'SYSVOL writable by Authenticated Users' @{ Errors=@{}; LogonScripts=@{ SysvolPermissions=@{ Owner='BUILTIN\Administrators'; AccessRules=@(@{ AccessType='Allow'; Identity='BUILTIN\Administrators'; Rights='FullControl' },@{ AccessType='Allow'; Identity='Authenticated Users'; Rights='Write' }) } } }
New-Fixture AD ADSCRIPT-002 $R throttled SKIP 'LogonScripts failed' $skLS
New-Fixture AD ADSCRIPT-005 $R clean PASS 'No LOLBins referenced in logon scripts' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ RelativePath='logon.bat'; LOLBinsUsage=$false; LOLBinsFound=@() }) } }
New-Fixture AD ADSCRIPT-005 $R known-bad FAIL 'Logon script references LOLBins' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ RelativePath='login.ps1'; LOLBinsUsage=$true; LOLBinsFound=@('certutil.exe','msbuild.exe') }) } }
New-Fixture AD ADSCRIPT-005 $R throttled SKIP 'LogonScripts failed' $skLS
New-Fixture AD ADSCRIPT-008 $R clean PASS 'No external resource references in scripts' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ RelativePath='startup.bat'; ExternalResources=$false; ExternalResourceList=@() }) } }
New-Fixture AD ADSCRIPT-008 $R known-bad FAIL 'Logon script references external resources' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ RelativePath='deploy.ps1'; ExternalResources=$true; ExternalResourceList=@('http://internal/config.xml') }) } }
New-Fixture AD ADSCRIPT-008 $R throttled SKIP 'LogonScripts failed' $skLS
New-Fixture AD ADSCRIPT-010 $R clean PASS 'No UNC paths to non-DC servers in scripts' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ RelativePath='local.ps1'; UNCPaths=@(); ExternalResources=$false; ExternalResourceList=@() }) } }
New-Fixture AD ADSCRIPT-010 $R known-bad FAIL 'Logon script references a non-DC UNC path' @{ Errors=@{}; LogonScripts=@{ ScriptAnalysis=@(@{ RelativePath='remote.ps1'; UNCPaths=@('\\fileserver\share'); ExternalResources=$true; ExternalResourceList=@('\\fileserver\share\tools.exe') }) } }
New-Fixture AD ADSCRIPT-010 $R throttled SKIP 'LogonScripts failed' $skLS

# ── ADTRADE ──
New-Fixture AD ADTRADE-002 $R clean PASS 'All config-partition servers match known DCs' @{ Errors=@{}; Tradecraft=@{ ConfigPartitionServers=@(@{ DNSHostName='dc1.t.l'; CN='dc1' }) }; DomainControllers=@(@{ FQDN='dc1.t.l'; Name='dc1' }) }
New-Fixture AD ADTRADE-002 $R known-bad FAIL 'Orphan server object under Sites (DCShadow indicator)' @{ Errors=@{}; Tradecraft=@{ ConfigPartitionServers=@(@{ DNSHostName='rogue.t.l'; CN='rogue' }) }; DomainControllers=@(@{ FQDN='dc1.t.l'; Name='dc1' }) }
New-Fixture AD ADTRADE-002 $R throttled SKIP 'TradecraftSignals failed' $skTC
New-Fixture AD ADTRADE-004 $R clean PASS 'No RODCs (PRP hygiene N/A)' @{ Errors=@{}; Tradecraft=@{ Rodcs=@() } }
New-Fixture AD ADTRADE-004 $R known-bad WARN 'RODC present (verify PRP out-of-band)' @{ Errors=@{}; Tradecraft=@{ Rodcs=@(@{ DNSHostName='rodc1.t.l' }) } }
New-Fixture AD ADTRADE-004 $R throttled SKIP 'TradecraftSignals failed' $skTC
New-Fixture AD ADTRADE-005 $R clean PASS 'Seamless SSO key rotated within 90 days' @{ Errors=@{}; Tradecraft=@{ SeamlessSsoAccount=@{ PwdLastSet='2026-05-01T00:00:00Z'; DistinguishedName='CN=AZUREADSSOACC,...' } } }
New-Fixture AD ADTRADE-005 $R known-bad FAIL 'Seamless SSO key not rotated in >90 days' @{ Errors=@{}; Tradecraft=@{ SeamlessSsoAccount=@{ PwdLastSet='2026-01-01T00:00:00Z'; DistinguishedName='CN=AZUREADSSOACC,...' } } }
New-Fixture AD ADTRADE-005 $R throttled SKIP 'TradecraftSignals failed' $skTC
New-Fixture AD ADTRADE-008 $R clean PASS 'Key Admins / Enterprise Key Admins empty' @{ Errors=@{}; Tradecraft=@{ KeyAdminGroupsFound=$true; EnterpriseKeyAdmins=@(@{ ObjectClass='group' }); KeyAdmins=@(@{ ObjectClass='group' }) } }
New-Fixture AD ADTRADE-008 $R known-bad FAIL 'A user is a member of Key Admins' @{ Errors=@{}; Tradecraft=@{ KeyAdminGroupsFound=$true; EnterpriseKeyAdmins=@(@{ ObjectClass='group' }); KeyAdmins=@(@{ ObjectClass='group' },@{ ObjectClass='user'; SamAccountName='bad' }) } }
New-Fixture AD ADTRADE-008 $R no-data SKIP 'Key Admins groups not resolved' @{ Errors=@{}; Tradecraft=@{ KeyAdminGroupsFound=$false } }
New-Fixture AD ADTRADE-009 $R clean PASS 'Cert Publishers contains only computer accounts' @{ Errors=@{}; Tradecraft=@{ CertPublishersFound=$true; CertPublishers=@(@{ ObjectClass='computer'; SamAccountName='ca1$' }) } }
New-Fixture AD ADTRADE-009 $R known-bad FAIL 'A user is a member of Cert Publishers' @{ Errors=@{}; Tradecraft=@{ CertPublishersFound=$true; CertPublishers=@(@{ ObjectClass='computer'; SamAccountName='ca1$' },@{ ObjectClass='user'; SamAccountName='bad' }) } }
New-Fixture AD ADTRADE-009 $R no-data SKIP 'Cert Publishers group not resolved' @{ Errors=@{}; Tradecraft=@{ CertPublishersFound=$false } }
New-Fixture AD ADTRADE-010 $R clean PASS 'gMSA present, none broadly retrievable' @{ Errors=@{}; Tradecraft=@{ GmsaCollected=$true; GmsaAccounts=@(@{ SamAccountName='svc-app$'; BroadlyRetrievable=$false; NonTier0Retrievable=$false }) } }
New-Fixture AD ADTRADE-010 $R known-bad FAIL 'A gMSA password is broadly retrievable' @{ Errors=@{}; Tradecraft=@{ GmsaCollected=$true; GmsaAccounts=@(@{ SamAccountName='svc-app$'; BroadlyRetrievable=$true; NonTier0Retrievable=$false }) } }
New-Fixture AD ADTRADE-010 $R no-data SKIP 'gMSA enumeration did not complete' @{ Errors=@{}; Tradecraft=@{ GmsaCollected=$false } }

Write-Host "`nDone (high round 2)."
