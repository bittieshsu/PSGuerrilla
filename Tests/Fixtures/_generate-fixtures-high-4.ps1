#requires -version 7.0
<#
    High-tier fixtures, Round 4: Microsoft 365.
    M365EXO (27) / M365AUDIT / M365DEF / M365PP / M365SPO / M365TEAMS.
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-high-4.ps1

    Every M365 check routes SKIP through Get-NotAssessedFinding with a
    @('M365Services', ...) source key, so $skExo (M365Services error) is the
    canonical throttle->SKIP fixture for all of them.

    Pinned contracts: M365EXO-025 (no PASS path — DLP rule data not collected),
    M365EXO-029/030 (empty=>SKIP, FAIL unreachable), M365EXO-044 (empty array=>FAIL,
    a probable should-be-SKIP bug — covered via partial=>WARN + absent=>SKIP),
    M365DEF-001 (no FAIL path).
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Platform,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; platform=$Platform; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 14 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$I='Entra'
$skExo=@{ Errors=@{ M365Services='EXO connect failed' }; M365Services=@{ Errors=@{} } }
function Exo($h){ @{ Errors=@{}; M365Services=@{ Errors=@{}; Exchange=$h } } }

# ── Exchange Online ──
New-Fixture Entra M365EXO-001 $I clean PASS 'Mailbox auditing enabled (AuditDisabled false)' (Exo @{ OrganizationConfig=@{ AuditDisabled=$false; Name='Org' } })
New-Fixture Entra M365EXO-001 $I known-bad FAIL 'Mailbox auditing disabled org-wide' (Exo @{ OrganizationConfig=@{ AuditDisabled=$true; Name='Org' } })
New-Fixture Entra M365EXO-001 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-002 $I clean PASS 'An anti-spam policy is configured' (Exo @{ AntiSpamPolicies=@(@{ Name='Default'; IsDefault=$true; SpamAction='MoveToJmf'; HighConfidenceSpamAction='Quarantine'; BulkSpamAction='MoveToJmf'; BulkThreshold=6 }) })
New-Fixture Entra M365EXO-002 $I no-data SKIP 'No anti-spam policy data (empty array guarded to SKIP)' (Exo @{ AntiSpamPolicies=@() })
New-Fixture Entra M365EXO-002 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-003 $I clean PASS 'Anti-phish impersonation protection enabled' (Exo @{ AntiPhishPolicies=@(@{ Name='Default'; Enabled=$true; EnableTargetedUserProtection=$true; EnableTargetedDomainsProtection=$false; EnableMailboxIntelligenceProtection=$false; PhishThresholdLevel=2 }) })
New-Fixture Entra M365EXO-003 $I known-bad WARN 'Anti-phish policy exists but impersonation protection off' (Exo @{ AntiPhishPolicies=@(@{ Name='Default'; Enabled=$true; EnableTargetedUserProtection=$false; EnableTargetedDomainsProtection=$false; EnableMailboxIntelligenceProtection=$false; PhishThresholdLevel=1 }) })
New-Fixture Entra M365EXO-003 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-004 $I clean PASS 'Malware policy with ZAP enabled' (Exo @{ MalwarePolicies=@(@{ Name='Default'; ZapEnabled=$true; EnableFileFilter=$true; EnableInternalSenderAdminNotifications=$true }) })
New-Fixture Entra M365EXO-004 $I known-bad WARN 'Malware policy without ZAP' (Exo @{ MalwarePolicies=@(@{ Name='Default'; ZapEnabled=$false; EnableFileFilter=$true; EnableInternalSenderAdminNotifications=$true }) })
New-Fixture Entra M365EXO-004 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-005 $I clean PASS 'A Safe Attachments policy is configured' (Exo @{ SafeAttachmentPolicies=@(@{ Name='Default'; Action='DynamicDelivery'; Enable=$true; Redirect=$false }) })
New-Fixture Entra M365EXO-005 $I no-data SKIP 'No Safe Attachments policy data (empty array guarded to SKIP)' (Exo @{ SafeAttachmentPolicies=@() })
New-Fixture Entra M365EXO-005 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-009 $I clean PASS 'All DKIM signing configs enabled' (Exo @{ DkimSigningConfig=@(@{ Domain='c.com'; Enabled=$true; Status='Enabled' }) })
New-Fixture Entra M365EXO-009 $I known-bad FAIL 'All DKIM signing configs disabled' (Exo @{ DkimSigningConfig=@(@{ Domain='c.com'; Enabled=$false; Status='Disabled' }) })
New-Fixture Entra M365EXO-009 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-011 $I clean PASS 'No external auto-forwarding configured' (Exo @{ RemoteDomains=@(@{ DomainName='*'; AutoForwardEnabled=$false }); TransportRules=@() })
New-Fixture Entra M365EXO-011 $I known-bad FAIL 'Auto-forward domain and forwarding transport rule (2 issues)' (Exo @{ RemoteDomains=@(@{ DomainName='*'; AutoForwardEnabled=$true }); TransportRules=@(@{ State='Enabled'; RedirectMessageTo='attacker@ext.com'; BlindCopyTo=$null }) })
New-Fixture Entra M365EXO-011 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-012 $I clean PASS 'Mailbox auditing enabled' (Exo @{ OrganizationConfig=@{ AuditDisabled=$false } })
New-Fixture Entra M365EXO-012 $I known-bad FAIL 'Mailbox auditing disabled' (Exo @{ OrganizationConfig=@{ AuditDisabled=$true } })
New-Fixture Entra M365EXO-012 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-013 $I clean PASS 'No remote domain allows auto-forward' (Exo @{ RemoteDomains=@(@{ DomainName='*'; AutoForwardEnabled=$false }) })
New-Fixture Entra M365EXO-013 $I known-bad FAIL 'A remote domain allows auto-forward' (Exo @{ RemoteDomains=@(@{ DomainName='*'; AutoForwardEnabled=$true }) })
New-Fixture Entra M365EXO-013 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-016 $I clean PASS 'DKIM enabled for all domains' (Exo @{ DkimSigningConfig=@(@{ Enabled=$true; Domain='c.com' }) })
New-Fixture Entra M365EXO-016 $I known-bad FAIL 'DKIM disabled for all domains' (Exo @{ DkimSigningConfig=@(@{ Enabled=$false; Domain='c.com' }) })
New-Fixture Entra M365EXO-016 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-018 $I clean PASS 'DMARC p=reject on all domains' (Exo @{ DomainMailSecurity=@(@{ Domain='c.com'; DMARC=@{ Record='v=DMARC1; p=reject'; Policy='reject' } }) })
New-Fixture Entra M365EXO-018 $I known-bad FAIL 'DMARC p=none (no reject)' (Exo @{ DomainMailSecurity=@(@{ Domain='c.com'; DMARC=@{ Record='v=DMARC1; p=none'; Policy='none' } }) })
New-Fixture Entra M365EXO-018 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-020 $I clean PASS 'SMTP AUTH disabled org-wide' (Exo @{ TransportConfig=@{ SmtpClientAuthenticationDisabled=$true } })
New-Fixture Entra M365EXO-020 $I known-bad FAIL 'SMTP AUTH enabled org-wide' (Exo @{ TransportConfig=@{ SmtpClientAuthenticationDisabled=$false } })
New-Fixture Entra M365EXO-020 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-024 $I clean PASS 'An enabled EXO-scoped DLP policy exists' (Exo @{ DlpCompliancePolicies=@(@{ Enabled=$true; Mode='Enforce'; ExchangeLocation=@('All') }) })
New-Fixture Entra M365EXO-024 $I known-bad FAIL 'No DLP policies configured' (Exo @{ DlpCompliancePolicies=@() })
New-Fixture Entra M365EXO-024 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-025 $I present WARN 'DLP policies exist but rule-level data not collected (no PASS path)' (Exo @{ DlpCompliancePolicies=@(@{ Name='P1' }) })
New-Fixture Entra M365EXO-025 $I known-bad FAIL 'No DLP policies configured' (Exo @{ DlpCompliancePolicies=@() })
New-Fixture Entra M365EXO-025 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-026 $I clean PASS 'Malware file filter enabled' (Exo @{ MalwarePolicies=@(@{ EnableFileFilter=$true }) })
New-Fixture Entra M365EXO-026 $I known-bad FAIL 'Malware file filter disabled' (Exo @{ MalwarePolicies=@(@{ EnableFileFilter=$false }) })
New-Fixture Entra M365EXO-026 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-028 $I clean PASS 'Common executable file types blocked' (Exo @{ MalwarePolicies=@(@{ EnableFileFilter=$true; FileTypes=@('exe','cmd','vbe','vbs','js','ps1','bat'); Name='P1' }) })
New-Fixture Entra M365EXO-028 $I known-bad FAIL 'No malware policy enables file filtering' (Exo @{ MalwarePolicies=@(@{ EnableFileFilter=$false; FileTypes=@(); Name='P1' }) })
New-Fixture Entra M365EXO-028 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-029 $I clean PASS 'Anti-malware policy present (inbound scanning)' (Exo @{ MalwarePolicies=@(@{ Name='P1' }) })
New-Fixture Entra M365EXO-029 $I no-data SKIP 'No malware filter policy data' (Exo @{ MalwarePolicies=@() })
New-Fixture Entra M365EXO-030 $I clean PASS 'Anti-malware policy present (quarantine default)' (Exo @{ MalwarePolicies=@(@{ Name='P1' }) })
New-Fixture Entra M365EXO-030 $I no-data SKIP 'No malware filter policy data' (Exo @{ MalwarePolicies=@() })
New-Fixture Entra M365EXO-031 $I clean PASS 'All malware policies have ZAP enabled' (Exo @{ MalwarePolicies=@(@{ ZapEnabled=$true; Name='P1' }) })
New-Fixture Entra M365EXO-031 $I known-bad FAIL 'No malware policy has ZAP enabled' (Exo @{ MalwarePolicies=@(@{ ZapEnabled=$false; Name='P1' }) })
New-Fixture Entra M365EXO-031 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-032 $I clean PASS 'Anti-phish impersonation protection enabled' (Exo @{ AntiPhishPolicies=@(@{ EnableTargetedUserProtection=$true; Name='P1' }) })
New-Fixture Entra M365EXO-032 $I known-bad FAIL 'No anti-phish impersonation protection' (Exo @{ AntiPhishPolicies=@(@{ EnableTargetedUserProtection=$false; EnableTargetedDomainsProtection=$false; EnableOrganizationDomainsProtection=$false; Name='P1' }) })
New-Fixture Entra M365EXO-032 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-035 $I clean PASS 'No connection-filter IP allow-list entries' (Exo @{ ConnectionFilterPolicies=@(@{ Name='Default'; IPAllowList=@() }) })
New-Fixture Entra M365EXO-035 $I known-bad FAIL 'Connection filter has IP allow-list entries' (Exo @{ ConnectionFilterPolicies=@(@{ Name='Default'; IPAllowList=@('192.0.2.1') }) })
New-Fixture Entra M365EXO-035 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-037 $I clean PASS 'Mailbox auditing enabled' (Exo @{ OrganizationConfig=@{ AuditDisabled=$false } })
New-Fixture Entra M365EXO-037 $I known-bad FAIL 'Mailbox auditing disabled' (Exo @{ OrganizationConfig=@{ AuditDisabled=$true } })
New-Fixture Entra M365EXO-037 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-038 $I clean PASS 'An anti-spam (content filter) policy exists' (Exo @{ AntiSpamPolicies=@(@{ Name='Default' }) })
New-Fixture Entra M365EXO-038 $I no-data SKIP 'No anti-spam policy data' (Exo @{ AntiSpamPolicies=@() })
New-Fixture Entra M365EXO-041 $I clean PASS 'Safe Links enabled for email' (Exo @{ SafeLinksPolicies=@(@{ EnableSafeLinksForEmail=$true; Name='P1' }) })
New-Fixture Entra M365EXO-041 $I known-bad FAIL 'Safe Links not enabled for email' (Exo @{ SafeLinksPolicies=@(@{ EnableSafeLinksForEmail=$false; IsEnabled=$false; Name='P1' }) })
New-Fixture Entra M365EXO-041 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-042 $I clean PASS 'Safe Links URL scanning enabled' (Exo @{ SafeLinksPolicies=@(@{ ScanUrls=$true; Name='P1' }) })
New-Fixture Entra M365EXO-042 $I known-bad WARN 'Safe Links URL scanning not enabled' (Exo @{ SafeLinksPolicies=@(@{ ScanUrls=$false; Name='P1' }) })
New-Fixture Entra M365EXO-042 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-044 $I clean PASS 'All required EXO protection alerts enabled' (Exo @{ ProtectionAlerts=@(
    @{ Name='Suspicious email sending patterns detected'; Disabled=$false },
    @{ Name='Suspicious Connector Activity'; Disabled=$false },
    @{ Name='Suspicious Email Forwarding Activity'; Disabled=$false },
    @{ Name='Messages have been delayed'; Disabled=$false },
    @{ Name='Tenant restricted from sending unprovisioned email'; Disabled=$false },
    @{ Name='Tenant restricted from sending email'; Disabled=$false },
    @{ Name='A potentially malicious URL click was detected'; Disabled=$false }) })
New-Fixture Entra M365EXO-044 $I known-bad WARN 'Only some required protection alerts present' (Exo @{ ProtectionAlerts=@(@{ Name='Suspicious Connector Activity'; Disabled=$false }) })
New-Fixture Entra M365EXO-044 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-046 $I clean PASS 'Unified audit log ingestion enabled' (Exo @{ AdminAuditLogConfig=@{ UnifiedAuditLogIngestionEnabled=$true } })
New-Fixture Entra M365EXO-046 $I known-bad FAIL 'Unified audit log ingestion disabled' (Exo @{ AdminAuditLogConfig=@{ UnifiedAuditLogIngestionEnabled=$false } })
New-Fixture Entra M365EXO-046 $I throttled SKIP 'Exchange data not assessed' $skExo

# ── M365 Audit / Defender / Power Platform ──
New-Fixture Entra M365AUDIT-002 $I clean PASS 'Audit log retention >= 365 days' @{ Errors=@{}; M365Services=@{ Errors=@{}; AuditConfig=@{ AuditLogAgeLimit='365.00:00:00'; AdminAuditLogAgeLimit='365.00:00:00' } } }
New-Fixture Entra M365AUDIT-002 $I known-bad FAIL 'Audit log retention 90 days (<180)' @{ Errors=@{}; M365Services=@{ Errors=@{}; AuditConfig=@{ AuditLogAgeLimit='90.00:00:00'; AdminAuditLogAgeLimit=$null } } }
New-Fixture Entra M365AUDIT-002 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365DEF-001 $I clean PASS 'A preset Defender protection policy is enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Defender=@{ ProtectionPolicyRules=@(@{ Name='Standard'; Identity='Standard'; State='Enabled'; Priority=1 }) } } }
New-Fixture Entra M365DEF-001 $I known-bad WARN 'Preset Defender policy present but disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Defender=@{ ProtectionPolicyRules=@(@{ Name='Standard'; Identity='Standard'; State='Disabled'; Priority=1 }) } } }
New-Fixture Entra M365DEF-001 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365PP-001 $I clean PASS 'Environment creation restricted' @{ Errors=@{}; M365Services=@{ Errors=@{}; PowerPlatform=@{ EnvironmentCreationRestricted=$true; DisableEnvironmentCreationByNonAdminUsers=$null } } }
New-Fixture Entra M365PP-001 $I known-bad FAIL 'Environment creation open to non-admins' @{ Errors=@{}; M365Services=@{ Errors=@{}; PowerPlatform=@{ EnvironmentCreationRestricted=$false; DisableEnvironmentCreationByNonAdminUsers=$false } } }
New-Fixture Entra M365PP-001 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365PP-002 $I clean PASS 'Tenant-wide DLP policy configured' @{ Errors=@{}; M365Services=@{ Errors=@{}; PowerPlatform=@{ DlpPolicies=@(@{ DisplayName='Tenant'; EnvironmentType='AllEnvironments'; Scope='Tenant'; IsDefault=$true }) } } }
New-Fixture Entra M365PP-002 $I known-bad FAIL 'No Power Platform DLP policies' @{ Errors=@{}; M365Services=@{ Errors=@{}; PowerPlatform=@{ DlpPolicies=@() } } }
New-Fixture Entra M365PP-002 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365PP-003 $I clean PASS 'Tenant isolation enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; PowerPlatform=@{ TenantIsolationEnabled=$true; TenantIsolationConfig=$null } } }
New-Fixture Entra M365PP-003 $I known-bad FAIL 'Tenant isolation disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; PowerPlatform=@{ TenantIsolationEnabled=$false; TenantIsolationConfig=$null } } }
New-Fixture Entra M365PP-003 $I throttled SKIP 'M365 services not assessed' $skExo

# ── SharePoint / Teams ──
New-Fixture Entra M365SPO-001 $I clean PASS 'External sharing disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ SharingCapability='Disabled' } } }
New-Fixture Entra M365SPO-001 $I known-bad FAIL 'Anonymous external + guest sharing enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ SharingCapability='ExternalUserAndGuestSharing' } } }
New-Fixture Entra M365SPO-001 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365SPO-005 $I clean PASS 'Enabled SPO-scoped DLP policy exists' @{ Errors=@{}; M365Services=@{ Errors=@{}; DlpPolicies=@(@{ Name='P1'; Workload='SharePoint'; Mode='Enable'; Enabled=$null }) } }
New-Fixture Entra M365SPO-005 $I known-bad WARN 'DLP policies exist but none scope SharePoint/OneDrive' @{ Errors=@{}; M365Services=@{ Errors=@{}; DlpPolicies=@(@{ Name='P1'; Workload='Exchange'; Mode='Enable'; Enabled=$true }) } }
New-Fixture Entra M365SPO-005 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365TEAMS-001 $I clean PASS 'Teams external access locked down' @{ Errors=@{}; M365Services=@{ Errors=@{}; Teams=@{ ExternalAccessConfig=@{ AllowFederatedUsers=$false; AllowTeamsConsumer=$false; AllowPublicUsers=$false; AllowedDomains=$null; BlockedDomains=$null } } } }
New-Fixture Entra M365TEAMS-001 $I known-bad FAIL 'Teams external access fully open' @{ Errors=@{}; M365Services=@{ Errors=@{}; Teams=@{ ExternalAccessConfig=@{ AllowFederatedUsers=$true; AllowTeamsConsumer=$true; AllowPublicUsers=$true; AllowedDomains=@(); BlockedDomains=@() } } } }
New-Fixture Entra M365TEAMS-001 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365TEAMS-002 $I clean PASS 'Guest access disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Teams=@{ GuestConfig=@{ AllowGuestUser=$false } } } }
New-Fixture Entra M365TEAMS-002 $I known-bad FAIL 'Guest access with third-party storage enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Teams=@{ GuestConfig=@{ AllowGuestUser=$true; AllowBox=$true } } } }
New-Fixture Entra M365TEAMS-002 $I throttled SKIP 'M365 services not assessed' $skExo
New-Fixture Entra M365TEAMS-004 $I clean PASS 'Anonymous meeting join restricted' @{ Errors=@{}; M365Services=@{ Errors=@{}; Teams=@{ MeetingPolicies=@(@{ Identity='Global'; AllowAnonymousUsersToJoinMeeting=$false; AllowPSTNUsersToBypassLobby=$false }) } } }
New-Fixture Entra M365TEAMS-004 $I known-bad FAIL 'Anonymous join with PSTN lobby bypass' @{ Errors=@{}; M365Services=@{ Errors=@{}; Teams=@{ MeetingPolicies=@(@{ Identity='Global'; AllowAnonymousUsersToJoinMeeting=$true; AllowPSTNUsersToBypassLobby=$true }) } } }
New-Fixture Entra M365TEAMS-004 $I throttled SKIP 'M365 services not assessed' $skExo

Write-Host "`nDone (high round 4)."
