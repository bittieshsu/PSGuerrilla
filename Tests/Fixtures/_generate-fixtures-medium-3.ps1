#requires -version 7.0
<#
    Medium-tier fixtures, Round 3: Microsoft 365 (28 checks).
    M365EXO (17) / M365SPO (3) / M365TEAMS (5) / M365AUDIT (1) / M365DEF (2).
    Synthetic data only. Re-run: pwsh Tests/Fixtures/_generate-fixtures-medium-3.ps1

    Always-SKIP: M365EXO-047, M365EXO-048. Always-WARN: M365EXO-014.
    No-FAIL: M365EXO-033/034/043, M365DEF-003.
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
$skExo=@{ Errors=@{ M365Services='EXO connect failed' }; M365Services=@{ Errors=@{} } }
function Exo($h){ @{ Errors=@{}; M365Services=@{ Errors=@{}; Exchange=$h } } }

# ── Exchange Online ──
New-Fixture Entra M365EXO-008 $I clean PASS 'Default remote domain blocks auto-forward' (Exo @{ RemoteDomains=@(@{ DomainName='*'; AutoForwardEnabled=$false }) })
New-Fixture Entra M365EXO-008 $I known-bad FAIL 'Default remote domain allows auto-forward' (Exo @{ RemoteDomains=@(@{ DomainName='*'; AutoForwardEnabled=$true }) })
New-Fixture Entra M365EXO-008 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-010 $I clean PASS 'No CAS mailbox plan enables POP/IMAP' (Exo @{ CASMailboxPlans=@(@{ Name='P1'; ImapEnabled=$false; PopEnabled=$false }) })
New-Fixture Entra M365EXO-010 $I known-bad FAIL 'Multiple CAS plans enable legacy protocols' (Exo @{ CASMailboxPlans=@(@{ Name='P1'; ImapEnabled=$true; PopEnabled=$false },@{ Name='P2'; ImapEnabled=$false; PopEnabled=$true }) })
New-Fixture Entra M365EXO-010 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-014 $I always-warn WARN 'Approved-sender list is a process artifact (manual)' (Exo @{ DomainMailSecurity=@(@{ Domain='c.com'; SPF=@{ Record='v=spf1 -all' } }) })
New-Fixture Entra M365EXO-014 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-019 $I clean PASS 'DMARC records specify an aggregate (rua) address' (Exo @{ DomainMailSecurity=@(@{ Domain='c.com'; DMARC=@{ Record='v=DMARC1;p=reject;rua=mailto:r@c.com' } }) })
New-Fixture Entra M365EXO-019 $I known-bad FAIL 'No DMARC record specifies an aggregate address' (Exo @{ DomainMailSecurity=@(@{ Domain='c.com'; DMARC=@{ Record='v=DMARC1;p=none' } }) })
New-Fixture Entra M365EXO-019 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-021 $I clean PASS 'No sharing policy shares contacts with all domains' (Exo @{ SharingPolicies=@(@{ Name='Default'; Domains=@('contoso.com:CalendarSharing') }) })
New-Fixture Entra M365EXO-021 $I known-bad FAIL 'A sharing policy shares contacts with all domains (*)' (Exo @{ SharingPolicies=@(@{ Name='Open'; Domains=@('*:ContactsSharing') }) })
New-Fixture Entra M365EXO-021 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-022 $I clean PASS 'No sharing policy shares calendar with all domains' (Exo @{ SharingPolicies=@(@{ Name='Default'; Domains=@('contoso.com:ContactsSharing') }) })
New-Fixture Entra M365EXO-022 $I known-bad FAIL 'A sharing policy shares calendar with all domains (*)' (Exo @{ SharingPolicies=@(@{ Name='Open'; Domains=@('*:CalendarSharing') }) })
New-Fixture Entra M365EXO-022 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-023 $I clean PASS 'External sender tagging enabled' (Exo @{ ExternalInOutlook=@(@{ Enabled=$true }) })
New-Fixture Entra M365EXO-023 $I known-bad FAIL 'No external sender tag and no marking transport rule' (Exo @{ ExternalInOutlook=@(@{ Enabled=$false }); TransportRules=@() })
New-Fixture Entra M365EXO-023 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-027 $I clean PASS 'Common-attachment file filter enabled' (Exo @{ MalwarePolicies=@(@{ EnableFileFilter=$true }) })
New-Fixture Entra M365EXO-027 $I known-bad FAIL 'No malware policy enables the file filter' (Exo @{ MalwarePolicies=@(@{ EnableFileFilter=$false }) })
New-Fixture Entra M365EXO-027 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-033 $I clean PASS 'User safety tips / spoof intelligence enabled' (Exo @{ AntiPhishPolicies=@(@{ EnableFirstContactSafetyTips=$true }) })
New-Fixture Entra M365EXO-033 $I known-bad WARN 'No safety tips / spoof intelligence enabled' (Exo @{ AntiPhishPolicies=@(@{ EnableFirstContactSafetyTips=$false; EnableSimilarUsersSafetyTips=$false; EnableSimilarDomainsSafetyTips=$false; EnableSpoofIntelligence=$false }) })
New-Fixture Entra M365EXO-033 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-034 $I clean PASS 'Mailbox intelligence enabled' (Exo @{ AntiPhishPolicies=@(@{ EnableMailboxIntelligence=$true }) })
New-Fixture Entra M365EXO-034 $I known-bad WARN 'Mailbox intelligence not enabled' (Exo @{ AntiPhishPolicies=@(@{ EnableMailboxIntelligence=$false }) })
New-Fixture Entra M365EXO-034 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-036 $I clean PASS 'Connection filter safe-list disabled' (Exo @{ ConnectionFilterPolicies=@(@{ EnableSafeList=$false; Name='P1' }) })
New-Fixture Entra M365EXO-036 $I known-bad FAIL 'Connection filter safe-list enabled' (Exo @{ ConnectionFilterPolicies=@(@{ EnableSafeList=$true; Name='P1' }) })
New-Fixture Entra M365EXO-036 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-039 $I clean PASS 'Spam actions quarantine/JMF (no delete/allow)' (Exo @{ AntiSpamPolicies=@(@{ SpamAction='MoveToJmf'; HighConfidenceSpamAction='Quarantine'; Name='P1' }) })
New-Fixture Entra M365EXO-039 $I known-bad FAIL 'A spam action is set to a non-approved value' (Exo @{ AntiSpamPolicies=@(@{ SpamAction='Delete'; HighConfidenceSpamAction='Quarantine'; Name='P1' }) })
New-Fixture Entra M365EXO-039 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-040 $I clean PASS 'No anti-spam allowed-sender domains' (Exo @{ AntiSpamPolicies=@(@{ AllowedSenderDomains=@(); Name='P1' }) })
New-Fixture Entra M365EXO-040 $I known-bad FAIL 'An anti-spam policy has allowed-sender domains' (Exo @{ AntiSpamPolicies=@(@{ AllowedSenderDomains=@('example.com'); Name='P1' }) })
New-Fixture Entra M365EXO-040 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-043 $I clean PASS 'Safe Links click tracking enabled' (Exo @{ SafeLinksPolicies=@(@{ DoNotTrackUserClicks=$false }) })
New-Fixture Entra M365EXO-043 $I known-bad WARN 'Safe Links click tracking disabled' (Exo @{ SafeLinksPolicies=@(@{ DoNotTrackUserClicks=$true }) })
New-Fixture Entra M365EXO-043 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-045 $I clean PASS 'Enabled protection alerts have recipients' (Exo @{ ProtectionAlerts=@(@{ Disabled=$false; NotifyUser=@('admin@c.com'); Name='A1' }) })
New-Fixture Entra M365EXO-045 $I known-bad FAIL 'Enabled protection alerts have no recipients' (Exo @{ ProtectionAlerts=@(@{ Disabled=$false; NotifyUser=@(); Name='A1' }) })
New-Fixture Entra M365EXO-045 $I throttled SKIP 'Exchange data not assessed' $skExo
New-Fixture Entra M365EXO-047 $I not-implemented SKIP 'Not assessable agentlessly (always SKIP)' $skExo
New-Fixture Entra M365EXO-048 $I not-implemented SKIP 'Not assessable agentlessly (always SKIP)' $skExo

# ── SharePoint ──
New-Fixture Entra M365SPO-002 $I clean PASS 'Guest access expires within 90 days' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ ExternalUserExpireInDays=45 } } }
New-Fixture Entra M365SPO-002 $I known-bad FAIL 'Guest access expiration not configured' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ ExternalUserExpireInDays=0 } } }
New-Fixture Entra M365SPO-002 $I no-data SKIP 'Guest expiration data unavailable' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ ExternalUserExpireInDays=$null } } }
New-Fixture Entra M365SPO-003 $I clean PASS 'Default sharing link is Direct/SpecificPeople' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ DefaultSharingLinkType='Direct' } } }
New-Fixture Entra M365SPO-003 $I known-bad FAIL 'Default sharing link is AnonymousAccess' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ DefaultSharingLinkType='AnonymousAccess' } } }
New-Fixture Entra M365SPO-003 $I no-data SKIP 'Default sharing link data unavailable' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ DefaultSharingLinkType=$null } } }
New-Fixture Entra M365SPO-004 $I clean PASS 'Self-service site creation disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ SelfServiceSiteCreationDisabled=$true; SelfServiceSiteCreationManagedPath='sites' } } }
New-Fixture Entra M365SPO-004 $I known-bad WARN 'Self-service site creation enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ SelfServiceSiteCreationDisabled=$false; SelfServiceSiteCreationManagedPath='sites' } } }
New-Fixture Entra M365SPO-004 $I no-data SKIP 'Site creation restriction data unavailable' @{ Errors=@{}; M365Services=@{ Errors=@{}; SharePoint=@{ SelfServiceSiteCreationDisabled=$null } } }

# ── Teams ──
function Teams($h){ @{ Errors=@{}; M365Services=@{ Errors=@{}; Teams=$h } } }
New-Fixture Entra M365TEAMS-003 $I clean PASS 'Meeting lobby restricts external/auto-admit' (Teams @{ MeetingPolicies=@(@{ Identity='Global'; AllowExternalParticipantGiveRequestControl=$false; AutoAdmittedUsers='EveryoneInCompany' }) })
New-Fixture Entra M365TEAMS-003 $I known-bad FAIL 'Everyone auto-admitted to meetings' (Teams @{ MeetingPolicies=@(@{ Identity='Global'; AllowExternalParticipantGiveRequestControl=$true; AutoAdmittedUsers='Everyone' }) })
New-Fixture Entra M365TEAMS-003 $I no-data SKIP 'Teams meeting policy data unavailable' (Teams @{ MeetingPolicies=$null })
New-Fixture Entra M365TEAMS-005 $I clean PASS 'Recordings stored in OneDrive (or disabled)' (Teams @{ MeetingPolicies=@(@{ Identity='Global'; AllowCloudRecording=$true; AllowTranscription=$true; RecordingStorageMode='OneDriveForBusiness' }) })
New-Fixture Entra M365TEAMS-005 $I known-bad WARN 'Cloud recording without OneDrive storage' (Teams @{ MeetingPolicies=@(@{ Identity='Global'; AllowCloudRecording=$true; AllowTranscription=$true; RecordingStorageMode='Stream' }) })
New-Fixture Entra M365TEAMS-005 $I no-data SKIP 'Teams meeting policy data unavailable' (Teams @{ MeetingPolicies=$null })
New-Fixture Entra M365TEAMS-006 $I clean PASS 'Chat permission role restricted' (Teams @{ MessagingPolicies=@(@{ Identity='Global'; AllowUrlPreviews=$true; AllowUserChat=$true; ChatPermissionRole='Restricted'; AllowOwnerDeleteMessage=$true; AllowUserDeleteMessage=$true; AllowUserEditMessage=$true }) })
New-Fixture Entra M365TEAMS-006 $I known-bad WARN 'Chat permission role is Full' (Teams @{ MessagingPolicies=@(@{ Identity='Global'; AllowUrlPreviews=$true; AllowUserChat=$true; ChatPermissionRole='Full'; AllowOwnerDeleteMessage=$true; AllowUserDeleteMessage=$true; AllowUserEditMessage=$true }) })
New-Fixture Entra M365TEAMS-006 $I no-data SKIP 'Teams messaging policy data unavailable' (Teams @{ MessagingPolicies=$null })
New-Fixture Entra M365TEAMS-007 $I clean PASS 'Third-party Teams apps restricted to an allow-list' (Teams @{ AppPermissionPolicies=@(@{ Identity='Global'; DefaultCatalogAppsType='BlockAllApps'; GlobalCatalogAppsType='AllowedAppList'; PrivateCatalogAppsType='AllowedAppList' }) })
New-Fixture Entra M365TEAMS-007 $I known-bad FAIL 'Third-party Teams app control unknown/unset' (Teams @{ AppPermissionPolicies=@(@{ Identity='Global'; DefaultCatalogAppsType='Unknown'; GlobalCatalogAppsType='Unknown'; PrivateCatalogAppsType='Unknown' }) })
New-Fixture Entra M365TEAMS-007 $I no-data SKIP 'Teams app permission policy data unavailable' (Teams @{ AppPermissionPolicies=$null })
New-Fixture Entra M365TEAMS-008 $I clean PASS 'No third-party cloud storage providers enabled' (Teams @{ GuestConfig=@{ AllowBox=$false; AllowDropBox=$false; AllowGoogleDrive=$false; AllowShareFile=$false; AllowEgnyte=$false } })
New-Fixture Entra M365TEAMS-008 $I known-bad FAIL 'Three+ third-party cloud storage providers enabled' (Teams @{ GuestConfig=@{ AllowBox=$true; AllowDropBox=$true; AllowGoogleDrive=$true; AllowShareFile=$false; AllowEgnyte=$false } })
New-Fixture Entra M365TEAMS-008 $I no-data SKIP 'Teams client/guest config data unavailable' (Teams @{ GuestConfig=$null })

# ── Audit / Defender ──
New-Fixture Entra M365AUDIT-003 $I clean PASS 'Unified + admin audit logging enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; AuditConfig=@{ UnifiedAuditLogIngestionEnabled=$true; AdminAuditLogEnabled=$true; LogLevel='Verbose' } } }
New-Fixture Entra M365AUDIT-003 $I known-bad FAIL 'Unified audit log ingestion disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; AuditConfig=@{ UnifiedAuditLogIngestionEnabled=$false; AdminAuditLogEnabled=$false; LogLevel='Minimal' } } }
New-Fixture Entra M365AUDIT-003 $I throttled SKIP 'Audit config not assessed' $skExo
New-Fixture Entra M365DEF-002 $I clean PASS 'No high-severity Defender alerts disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Defender=@{ ProtectionAlerts=@(@{ Name='A1'; Severity='High'; Category='ThreatProtection'; IsEnabled=$true; Disabled=$false }) } } }
New-Fixture Entra M365DEF-002 $I known-bad FAIL 'A high-severity Defender alert is disabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Defender=@{ ProtectionAlerts=@(@{ Name='Crit'; Severity='High'; Category='ThreatProtection'; IsEnabled=$false; Disabled=$true }) } } }
New-Fixture Entra M365DEF-002 $I no-data SKIP 'Defender protection alert data unavailable' @{ Errors=@{}; M365Services=@{ Errors=@{}; Defender=@{ ProtectionAlerts=$null } } }
New-Fixture Entra M365DEF-003 $I clean PASS 'AIR and Threat Explorer enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Defender=@{ AIRConfiguration=@{ Enabled=$true }; ThreatExplorerEnabled=$true; ProtectionPolicyRules=@(@{ Name='Standard'; State='Enabled' }) } } }
New-Fixture Entra M365DEF-003 $I known-bad WARN 'AIR / Threat Explorer not fully enabled' @{ Errors=@{}; M365Services=@{ Errors=@{}; Defender=@{ AIRConfiguration=@{ Enabled=$false }; ThreatExplorerEnabled=$false; ProtectionPolicyRules=@(@{ Name='Standard'; State='Enabled' }) } } }
New-Fixture Entra M365DEF-003 $I throttled SKIP 'Defender data not assessed' $skExo

Write-Host "`nDone (medium round 3)."
