@{
    RootModule        = 'Guerrilla.psm1'
    ModuleVersion     = '2.55.0'
    GUID              = 'f7a3b2c1-4d5e-6f78-9a0b-1c2d3e4f5a6b'
    Author            = 'Jim Tyler, Microsoft MVP'
    CompanyName       = 'Jim Tyler'
    Copyright         = '(c) 2026 Jim Tyler. All rights reserved.'
    Description       = 'Agentless, read-only, point-in-time security assessment for PowerShell 7 across three platforms: on-premises Active Directory (211 checks across 15 categories including transitive Tier-0 attack-path analysis, certificate-services ESC1-ESC16, NTLM-relay preconditions, telemetry posture, and adversary tradecraft indicators), the Entra ID / Azure / Intune / M365 identity plane (257 checks including a full 44-control EIDSCA baseline, conditional access, PIM, application and OAuth governance, Exchange Online, SharePoint, Teams, Defender, and entitlement-management hygiene), and Google Workspace (190 checks aligned to the CISA SCuBA baselines, plus the K12 candidate baseline checks with student-OU scoping). 658 checks total, each mapped to NIST 800-53, MITRE ATT&CK, CIS, EIDSCA, and CISA SCuBA where applicable and carrying a CISA Zero Trust pillar and weight, and each verdict validated by a golden-fixture test (1,928 fixtures). Every run is recorded locally and compared against your previous run: the report opens with what changed, including newly failing checks, confirmed remediations, and any check that went dark. Local history on your machine, no accounts, no telemetry.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Set-Safehouse'
        'Test-Safehouse'
        'Get-Safehouse'
        'Invoke-GWSAudit'
        'Invoke-ADAudit'
        'Invoke-EntraAudit'
        # Deprecated wrappers for the renamed audits; removed in the next major version.
        'Invoke-Fortification'
        'Invoke-Reconnaissance'
        'Invoke-Infiltration'
        'Invoke-Campaign'
        'Get-GuerrillaScore'
        'Get-GuerrillaMaturity'
        'Get-QuickWins'
        'Get-ComplianceCrosswalk'
        'Test-GuerrillaConditionalAccess'
        'Export-BudgetJustification'
        'Export-ExecutiveSummary'
        'Export-TechnicalReport'
        'Export-RemediationPlaybook'
        'Export-RemediationScripts'
        'Set-RiskAcceptance'
        'Get-RiskAcceptance'
        'Get-TrendReport'
        'Export-ReportPdf'
        'Export-Dashboard'
        'Export-BloodHoundData'
        'Export-GuerrillaJUnit'
        'Get-GuerrillaCIGate'
        'Show-Guerrilla'
        'Get-ZeroTrustScore'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @(
        'Set-ReconConfig'
        'Get-ReconConfig'
        'Invoke-ADRecon'
        'Invoke-CloudRecon'
    )
    FormatsToProcess   = @('Guerrilla.format.ps1xml')
    PrivateData = @{
        PSData = @{
            Tags       = @('GoogleWorkspace', 'ActiveDirectory', 'EntraID', 'AzureAD', 'Intune', 'M365', 'Security', 'SecurityAssessment', 'ADSecurity', 'CloudSecurity', 'NTLMRelay', 'TierZero', 'GUI', 'WPF', 'Guerrilla')
            LicenseUri = 'https://creativecommons.org/licenses/by/4.0/'
            ProjectUri = 'https://guerrilla.army'
            ReleaseNotes = 'Guerrilla (formerly PSGuerrilla). v2.55.0: Eleven new Google Workspace checks close most of what remains of the config-readable CISA SCuBA gap, taking Google Workspace SCuBA policy coverage from 99 to 110 of 138. ADMIN-023 requires between two and eight super admins, so a single lost account cannot lock the organization out and no more admins than necessary hold an unconstrained path to the tenant. ADMIN-024 requires Marketplace installs to be confined to an allowlist and fails when internally published apps are exempted from it. ADMIN-025 requires multi-party approval for sensitive admin actions. AUTH-019 requires conflicting unmanaged accounts to be replaced with managed ones. LOG-007 requires every system-defined alerting rule to be active, not merely one of them. DRIVE-023 requires Drive for Desktop to be disabled or restricted to authorized devices. EMAIL-032 requires comprehensive mail storage. EMAIL-033 and EMAIL-034 require that attachment and spoofing protections move flagged mail to spam or quarantine rather than leaving it in the inbox, because detecting a malicious message and leaving it in front of the user produces a label and not an outcome. EMAIL-035 and EMAIL-036 fail where domains bypass spam filtering or an override list hides warning banners for all senders. Ten of the eleven read Cloud Identity policies the scan already collects and the eleventh counts super admins from the directory, so none of them needs a new API scope, new domain-wide delegation, or a collector change. Field names and enum direction were verified against the published CISA assessment logic before any verdict code was written, which is what caught that GWS.GMAIL.5.5 governs attachment consequences and 7.6 governs spoofing, the opposite of what the baseline titles imply. Google Workspace coverage is now 190 checks and the total is 658, each validated by a golden-fixture test (1,928 fixtures). The remaining 28 Google Workspace policies are not closable from configuration and the changelog says why for each: 14 are designated Manual by CISA, 8 are derived from audit logs rather than settings, 2 are DNS, 3 are queued, and 1 needs a collector that does not exist yet. The honest ceiling for configuration alone is 116 of 138. Separately, the README platform table had understated Google Workspace since v2.53.0 because the derived-counts gate matched only numbers followed by the word checks and could not see a bare table cell; the gate now reconciles the table itself. v2.53.1: Generated reports now localize into 13 languages. Every HTML report honors a -ReportLanguage code (Invoke-ADAudit, Invoke-EntraAudit, Invoke-GWSAudit, Invoke-Campaign and the Export-TechnicalReport/ExecutiveSummary/RemediationPlaybook/BudgetJustification cmdlets, or output.reportLanguage in config): the report shell and all 643 checks'' static content (name, description, recommended value, remediation steps) render in Spanish, French, German, Italian, Hebrew, Portuguese, Dutch, Danish, Russian, Simplified Chinese, Japanese, Korean, and Hindi. The html lang and dir attributes follow the selected language, right-to-left languages mirror the layout, and each translated string carries per-key provenance. Live collected evidence stays as collected: only the check definitions are translated, and any string a language is missing falls back to English. A localization gate of 154 checks fails the build if a shipped language is missing a check, shell key, category label, or format placeholder, with a poison self-test proving the gate can fail. All 13 translations are machine-draft pending native review, and test reports (-TestMode) render in the selected language too. This supersedes the v2.52.0 note that generated reports were English only. v2.53.0: Seven new Google Workspace checks plus a service-account key-handling hardening. DRIVE-018 enumerates every shared drive and flags those whose external-sharing restriction (domainUsersOnly) is not enforced, the drive-level gate that permits contents to be shared outside the organization. GTRADE-007 surfaces admin roles assigned to a group rather than a user: every direct or nested member inherits the role and anyone who can edit the group''s membership can grant it to themselves, the Google Workspace analogue of an Active Directory nested-group-to-Tier-0 path; broad-privilege grants FAIL and narrow ones WARN for review. Five more checks extend the K12 candidate baseline (GWS-K12-011 through 015): student Gmail auto-forwarding, Google Takeout data export, legacy IMAP/POP authentication for students, Google Vault export/retention/eDiscovery privilege sprawl, and audit-logging license coverage. Where a control''s state is not exposed by any readable policy surface (Takeout, per-user audit-log SKU), the check reports Not Assessed with a manual-review direction rather than assuming a value it cannot read. Google Workspace coverage is now 175 checks and the total is 643, each validated by a golden-fixture test (1,854 fixtures). Separately, when a scan stages a Google service-account private key to a temporary file, the file is now created with owner-only permissions (mode 0600 on Unix, an inheritance-protected single-user ACL on Windows) locked in before the key is written, under a full-entropy random name, closing a window where the key briefly sat readable in the shared temp directory. v2.52.0: The desktop GUI now speaks 41 languages, four of them right-to-left. Every user-visible string in Show-Guerrilla comes from locale catalogs (English source plus 40 translations, each carrying all 171 keys with per-key translation provenance). A header selector switches the whole window live, the choice persists in config, and first launch follows the OS display language when a matching catalog exists. Right-to-left languages (Arabic, Persian, Hebrew, Urdu) mirror the entire layout from a catalog-declared direction flag, while the run log and source inspector stay left-to-right because cmdlet output is English regardless of UI language. Adding a language is adding one catalog file: the selector discovers them at runtime, and codes may be script-qualified (Traditional Chinese ships as zh-Hant alongside Simplified zh). A localization gate of 259 checks fails the build if any string is missing from English, a shipped language is incomplete, a format placeholder is dropped, or a text direction is invalid, with a poison self-test proving the gate can fail. The 40 translations ship as machine-draft pending native review. Generated reports remain English only: this release localizes the application interface, not the HTML output. v2.51.0: The desktop GUI is multilingual, starting with Spanish, on an architecture built to scale. Every user-visible string comes from locale catalogs (English source plus Spanish with per-key translation provenance, the same machine-draft / human-reviewed convention the website uses). A language selector in the header switches the whole window live with no restart, exactly the way the theme toggle works, and the choice persists in config next to the theme; first launch follows the OS display language when a matching catalog exists. Adding a future language is adding one catalog file: the selector discovers catalogs at runtime. Localized labels are decoupled from the canonical values passed to cmdlets, and a new localization gate fails the build if a GUI string is missing from the English catalog or a shipped language is incomplete, with a poison self-test proving the gate can fail. See CHANGELOG.md for earlier releases.'
        }
    }
}
