#requires -version 7.0
<#
    High-tier fixtures, Round 6 (final): AD password policy + Intune.
    ADPWD (10) + INTUNE (10). Synthetic data only.
    Re-run: pwsh Tests/Fixtures/_generate-fixtures-high-6.ps1

    Notes:
      ADPWD-001 clean PASS needs a [TimeSpan] MaxPasswordAge (not JSON-representable) —
        FAIL + SKIP covered, clean deferred.
      ADPWD-011/012/014 gate on ModuleAvailability.DSInternals (false => SKIP).
      INTUNE-021 is unimplemented (always SKIP).
      INTUNE-006/009/011/016/017 return WARN (not FAIL) when the policy is absent.
    (EIDPIM-005/007/008/013 remain excluded — undefined $privilegedUsers, in the fix task.)
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Platform,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; platform=$Platform; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 14 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$R='AD'; $I='Entra'
$skPwd=@{ Errors=@{ PasswordPolicies='collector error' }; PasswordPolicies=$null }
$skInt=@{ Errors=@{ Intune='Graph 429' }; Intune=@{ Errors=@{} } }
function NoDS { @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$false }; PasswordPolicies=@{} } }

# ── AD password policy ──
New-Fixture AD ADPWD-001 $R known-bad FAIL 'Default policy weak (length 8, no complexity, history 12)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ MinPasswordLength=8; PasswordComplexity=$false; PasswordHistoryCount=12; LockoutThreshold=0; ReversibleEncryption=$true } } }
New-Fixture AD ADPWD-001 $R throttled SKIP 'Password policy not assessed (clean PASS needs TimeSpan MaxPasswordAge)' $skPwd
New-Fixture AD ADPWD-004 $R clean PASS 'Minimum password length 14' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ MinPasswordLength=14 } } }
New-Fixture AD ADPWD-004 $R known-bad FAIL 'Minimum password length 7 (<8)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ MinPasswordLength=7 } } }
New-Fixture AD ADPWD-004 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-005 $R clean PASS 'Password complexity enabled' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ PasswordComplexity=$true } } }
New-Fixture AD ADPWD-005 $R known-bad FAIL 'Password complexity disabled' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ PasswordComplexity=$false } } }
New-Fixture AD ADPWD-005 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-006 $R clean PASS 'Account lockout threshold 5 (1-10)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ LockoutThreshold=5 } } }
New-Fixture AD ADPWD-006 $R known-bad FAIL 'No account lockout (threshold 0)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ LockoutThreshold=0 } } }
New-Fixture AD ADPWD-006 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-009 $R clean PASS 'No users with password-never-expires' @{ Errors=@{}; PasswordPolicies=@{ UsersPasswordNeverExpires=@() } }
New-Fixture AD ADPWD-009 $R known-bad FAIL 'A user has password-never-expires set' @{ Errors=@{}; PasswordPolicies=@{ UsersPasswordNeverExpires=@(@{ SamAccountName='svc'; AdminCount=0 }) } }
New-Fixture AD ADPWD-009 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-011 $R clean PASS 'No duplicate password hashes' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ DuplicateHashGroups=@() } }
New-Fixture AD ADPWD-011 $R known-bad FAIL 'Accounts share a password hash' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ DuplicateHashGroups=@(@{ Accounts=@(@{ SamAccountName='u1' },@{ SamAccountName='u2' }) }) } }
New-Fixture AD ADPWD-011 $R no-data SKIP 'DSInternals unavailable — hash analysis not performed' (NoDS)
New-Fixture AD ADPWD-012 $R clean PASS 'No HIBP-compromised passwords' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ HIBPCompromisedUsers=@() } }
New-Fixture AD ADPWD-012 $R known-bad FAIL 'An account uses a known-breached password' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ HIBPCompromisedUsers=@(@{ SamAccountName='u1' }) } }
New-Fixture AD ADPWD-012 $R no-data SKIP 'DSInternals unavailable — HIBP comparison not performed' (NoDS)
New-Fixture AD ADPWD-014 $R clean PASS 'No common/weak passwords detected' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ CommonPasswordUsers=@() } }
New-Fixture AD ADPWD-014 $R known-bad FAIL 'An account uses a common password' @{ Errors=@{}; ModuleAvailability=@{ DSInternals=$true }; PasswordPolicies=@{ CommonPasswordUsers=@(@{ SamAccountName='u1' }) } }
New-Fixture AD ADPWD-014 $R no-data SKIP 'DSInternals unavailable — common-password analysis not performed' (NoDS)
New-Fixture AD ADPWD-016 $R clean PASS 'LAPS deployed with >=80% coverage' @{ Errors=@{}; PasswordPolicies=@{ LAPSDeployed=$true; LAPSType='Windows'; LAPSComputers=80; TotalComputers=100 } }
New-Fixture AD ADPWD-016 $R known-bad FAIL 'LAPS not deployed' @{ Errors=@{}; PasswordPolicies=@{ LAPSDeployed=$false; LAPSType='None'; LAPSComputers=0; TotalComputers=100 } }
New-Fixture AD ADPWD-016 $R throttled SKIP 'Password policy not assessed' $skPwd
New-Fixture AD ADPWD-021 $R clean PASS 'Account lockout threshold 5 (1-10)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ LockoutThreshold=5 } } }
New-Fixture AD ADPWD-021 $R known-bad FAIL 'No account lockout (threshold 0)' @{ Errors=@{}; PasswordPolicies=@{ DefaultPolicy=@{ LockoutThreshold=0 } } }
New-Fixture AD ADPWD-021 $R throttled SKIP 'Password policy not assessed' $skPwd

# ── Intune ──
New-Fixture Entra INTUNE-002 $I clean PASS 'All devices compliant' @{ Errors=@{}; Intune=@{ Errors=@{}; ComplianceSummary=@{ compliantDeviceCount=10; nonCompliantDeviceCount=0; inGracePeriodCount=0; notEvaluatedDeviceCount=0; errorDeviceCount=0; conflictDeviceCount=0 } } }
New-Fixture Entra INTUNE-002 $I known-bad FAIL 'Most devices non-compliant (>10%)' @{ Errors=@{}; Intune=@{ Errors=@{}; ComplianceSummary=@{ compliantDeviceCount=5; nonCompliantDeviceCount=20; inGracePeriodCount=0; notEvaluatedDeviceCount=0; errorDeviceCount=0; conflictDeviceCount=0 } } }
New-Fixture Entra INTUNE-002 $I throttled SKIP 'Intune compliance summary not assessed' $skInt
New-Fixture Entra INTUNE-003 $I clean PASS 'All managed devices compliant' @{ Errors=@{}; Intune=@{ Errors=@{}; ManagedDevices=@(@{ deviceName='PC1'; operatingSystem='Windows 11'; complianceState='compliant'; lastSyncDateTime='2026-06-26' },@{ deviceName='PC2'; operatingSystem='Windows 11'; complianceState='compliant'; lastSyncDateTime='2026-06-26' }) } }
New-Fixture Entra INTUNE-003 $I known-bad FAIL 'All managed devices non-compliant (>10%)' @{ Errors=@{}; Intune=@{ Errors=@{}; ManagedDevices=@(@{ deviceName='PC1'; operatingSystem='Windows 11'; complianceState='noncompliant'; lastSyncDateTime='2026-06-26' },@{ deviceName='PC2'; operatingSystem='Windows 11'; complianceState='noncompliant'; lastSyncDateTime='2026-06-26' }) } }
New-Fixture Entra INTUNE-003 $I throttled SKIP 'Intune managed devices not assessed' $skInt
New-Fixture Entra INTUNE-006 $I clean PASS 'Windows Update ring policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='Windows Update Ring'; '@odata.type'='#microsoft.graph.windowsUpdateForBusinessConfiguration' }) } }
New-Fixture Entra INTUNE-006 $I known-bad WARN 'No Windows Update policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='Firewall Policy'; '@odata.type'='#microsoft.graph.windowsFirewallConfiguration' }) } }
New-Fixture Entra INTUNE-006 $I throttled SKIP 'Intune device configurations not assessed' $skInt
New-Fixture Entra INTUNE-007 $I clean PASS 'BitLocker disk encryption policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='BitLocker Encryption Policy'; '@odata.type'='#microsoft.graph.windowsEndpointProtectionConfiguration' }) } }
New-Fixture Entra INTUNE-007 $I known-bad FAIL 'No disk encryption policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='Firewall Policy'; '@odata.type'='#microsoft.graph.windowsFirewallConfiguration' }) } }
New-Fixture Entra INTUNE-007 $I throttled SKIP 'Intune device configurations not assessed' $skInt
New-Fixture Entra INTUNE-009 $I clean PASS 'ASR rules policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='ASR Rules Policy'; '@odata.type'='#microsoft.graph.windows10EndpointProtectionConfiguration' }) } }
New-Fixture Entra INTUNE-009 $I known-bad WARN 'No ASR policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='Firewall Policy'; '@odata.type'='#microsoft.graph.windowsFirewallConfiguration' }) } }
New-Fixture Entra INTUNE-009 $I throttled SKIP 'Intune device configurations not assessed' $skInt
New-Fixture Entra INTUNE-011 $I clean PASS 'App protection policy configured' @{ Errors=@{}; Intune=@{ Errors=@{}; AppProtectionPolicies=@(@{ id='p1'; displayName='iOS App Protection'; '@odata.type'='#microsoft.graph.iosManagedAppProtection' }) } }
New-Fixture Entra INTUNE-011 $I known-bad WARN 'No app protection policy configured' @{ Errors=@{}; Intune=@{ Errors=@{}; AppProtectionPolicies=@() } }
New-Fixture Entra INTUNE-011 $I throttled SKIP 'Intune app protection policies not assessed' $skInt
New-Fixture Entra INTUNE-015 $I clean PASS 'All managed devices encrypted' @{ Errors=@{}; Intune=@{ Errors=@{}; ManagedDevices=@(@{ deviceName='PC1'; operatingSystem='Windows 11'; isEncrypted=$true },@{ deviceName='PC2'; operatingSystem='Windows 11'; isEncrypted=$true }) } }
New-Fixture Entra INTUNE-015 $I known-bad FAIL 'Half of managed devices unencrypted (<90%)' @{ Errors=@{}; Intune=@{ Errors=@{}; ManagedDevices=@(@{ deviceName='PC1'; operatingSystem='Windows 11'; isEncrypted=$true },@{ deviceName='PC2'; operatingSystem='Windows 11'; isEncrypted=$false }) } }
New-Fixture Entra INTUNE-015 $I throttled SKIP 'Intune managed devices not assessed' $skInt
New-Fixture Entra INTUNE-016 $I clean PASS 'Windows Firewall policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='Windows Firewall Policy'; '@odata.type'='#microsoft.graph.windowsFirewallConfiguration' }) } }
New-Fixture Entra INTUNE-016 $I known-bad WARN 'No firewall policy deployed' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='Update Ring'; '@odata.type'='#microsoft.graph.windowsUpdateForBusinessConfiguration' }) } }
New-Fixture Entra INTUNE-016 $I throttled SKIP 'Intune device configurations not assessed' $skInt
New-Fixture Entra INTUNE-017 $I clean PASS 'A security baseline is assigned' @{ Errors=@{}; Intune=@{ Errors=@{}; SecurityBaselines=@(@{ id='b1'; displayName='Windows 11 Security Baseline'; templateType='Windows11'; publishedDateTime='2025-01-01' }) } }
New-Fixture Entra INTUNE-017 $I known-bad WARN 'No security baseline assigned' @{ Errors=@{}; Intune=@{ Errors=@{}; SecurityBaselines=@() } }
New-Fixture Entra INTUNE-017 $I throttled SKIP 'Intune security baselines not assessed' $skInt
New-Fixture Entra INTUNE-021 $I not-implemented SKIP 'Remote-actions audit requires Intune audit log data (not collected)' @{ Errors=@{}; Intune=@{ Errors=@{} } }

Write-Host "`nDone (high round 6)."
