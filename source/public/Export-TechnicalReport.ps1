# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-TechnicalReport {
    <#
    .SYNOPSIS
        Generates a full technical security assessment report with remediation commands.
    .DESCRIPTION
        Produces a detailed HTML report for IT staff and security administrators. Includes
        every finding with check ID, current vs recommended values, severity, remediation
        steps, PowerShell commands, and compliance references.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Technical-Report.html
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER IncludePass
        Include passing checks in the report. Default: false (only FAIL/WARN).
    .EXAMPLE
        Export-TechnicalReport -OrganizationName 'Springfield USD'
    .EXAMPLE
        Export-TechnicalReport -IncludePass -OutputPath ./full-report.html
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [switch]$IncludePass,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [string]$Language = ''
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Technical-Report.html' }

    $dataDir = Get-GuerrillaDataRoot
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return [PSCustomObject]@{ Success = $false; Message = 'No findings'; Path = $null }
    }

    if (-not $Language) { $Language = Resolve-GuerrillaReportLanguage -Configured '' }
    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw
    $Findings = Get-GuerrillaLocalizedFindings -Findings $Findings -Language $Language
    $timestampStr = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    $html = [System.Text.StringBuilder]::new(131072)

    # Risk acceptance lookup
    $riskAcceptances = @{}
    try {
        foreach ($ra in (Get-RiskAcceptance -Status Active)) {
            $riskAcceptances[$ra.CheckId] = $ra
        }
    } catch { }

    # Stats
    $totalChecks = $Findings.Count
    $failCount = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($Findings | Where-Object Status -eq 'WARN').Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $critCount = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count

    # Category breakdown
    $categories = @($Findings | Group-Object Category | Sort-Object { @($_.Group | Where-Object Status -eq 'FAIL').Count } -Descending)

    # Filter findings for display
    $displayFindings = if ($IncludePass) { $Findings } else { @($Findings | Where-Object Status -in @('FAIL', 'WARN')) }
    $displayFindings = @($displayFindings | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }}, CheckId)

    $extraCss = @'
.finding { background: var(--g-surface); border-radius: var(--radius); margin: 1rem 0; overflow: hidden; }
.finding-header { padding: 0.9rem 1.4rem; border-bottom: 1px solid var(--g-border); display: flex; justify-content: space-between; align-items: center; gap: 0.8rem; flex-wrap: wrap; }
.finding-header .badges { display: flex; gap: 0.4rem; flex-wrap: wrap; }
.finding-body { padding: 0.9rem 1.4rem 1.1rem; }
.finding-body dl { margin: 0; }
.finding-body dt { color: var(--g-heading); font-weight: 600; margin-top: 0.7em; font-size: 0.85rem; }
.finding-body dd { margin: 0.15em 0 0.5em 0; font-size: 0.95rem; word-break: break-word; }
.finding-accepted { color: var(--g-muted); font-style: italic; }
@media print { .finding { break-inside: avoid; border: 1px solid var(--g-border); } }
'@

    $subtitle = "$(& $esc $OrganizationName) &middot; $(& $t 'common.generated'): $timestampStr"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title (& $tr 'technical.title') `
        -Subtitle $subtitle `
        -HtmlTitle "$(& $tr 'technical.htmlTitle') - $OrganizationName" `
        -TopbarMeta (& $tr 'technical.topbar') `
        -Style $Style -ExtraCss $extraCss))

    [void]$html.Append(@"
<div class="stat-grid">
  <div class="stat"><span class="value">$totalChecks</span><span class="label">$(& $t 'common.totalChecks')</span></div>
  <div class="stat"><span class="value" style="color:var(--g-ok)">$passCount</span><span class="label">$(& $t 'common.pass')</span></div>
  <div class="stat"><span class="value" style="color:var(--g-bad)">$failCount</span><span class="label">$(& $t 'common.fail')</span></div>
  <div class="stat"><span class="value" style="color:var(--g-warn)">$warnCount</span><span class="label">$(& $t 'common.warn')</span></div>
  <div class="stat"><span class="value" style="color:var(--g-sev-critical)">$critCount</span><span class="label">$(& $t 'common.critical')</span></div>
</div>

<h2>$(& $t 'common.categoryBreakdown')</h2>
<div class="table-wrap">
<table>
<thead><tr><th>$(& $t 'common.thCategory')</th><th>$(& $t 'common.pass')</th><th>$(& $t 'common.fail')</th><th>$(& $t 'common.warn')</th><th>$(& $t 'technical.thTotal')</th></tr></thead>
<tbody>
"@)

    foreach ($cat in $categories) {
        $cp = @($cat.Group | Where-Object Status -eq 'PASS').Count
        $cf = @($cat.Group | Where-Object Status -eq 'FAIL').Count
        $cw = @($cat.Group | Where-Object Status -eq 'WARN').Count
        $catLabel = & $esc (Get-GuerrillaLocalizedCategoryName -Name "$($cat.Name)" -Language $Language)
        [void]$html.Append("<tr><td>$catLabel</td><td><span class='verdict-pass'>$cp</span></td><td><span class='verdict-fail'>$cf</span></td><td><span class='verdict-warn'>$cw</span></td><td>$($cat.Count)</td></tr>`n")
    }

    [void]$html.Append('</tbody></table></div>')

    # Security Maturity + Attack Paths (shared sections). Maturity spans all checks; the attack-path
    # section only renders when AD attack-path findings are present (-OmitIfAbsent).
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $Findings -Esc $esc -Language $Language))
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $Findings -Esc $esc -Language $Language))
    [void]$html.Append((Get-GuerrillaCartographyHtml -Findings $Findings -Esc $esc -Language $Language))
    [void]$html.Append((Get-GuerrillaAttackPathSectionHtml -Findings $Findings -Esc $esc -OmitIfAbsent -Language $Language))

    [void]$html.Append(@"
<h2>$(& $tr 'technical.detailedFindings' $displayFindings.Count)</h2>
"@)

    foreach ($finding in $displayFindings) {
        $checkId = $finding.CheckId ?? $finding.Id ?? 'N/A'
        $name = & $esc ($finding.Name ?? $finding.CheckName ?? $checkId)
        $sev = $finding.Severity ?? 'Medium'
        $status = $finding.Status ?? 'FAIL'

        # Check risk acceptance
        $isAccepted = $riskAcceptances.ContainsKey($checkId)
        $statusDisplay = if ($isAccepted) { & $t 'common.accepted' } else { & $esc "$status" }
        $sevClass = ("$sev").ToLower()
        $statusClass = if ($isAccepted) { 'accepted' } else { ("$status").ToLower() }

        [void]$html.Append(@"
<div class="finding">
<div class="finding-header">
<div><strong>$(& $esc $checkId)</strong> &middot; $name</div>
<div class="badges"><span class="badge badge-sev-$sevClass">$(& $esc "$sev")</span> <span class="badge badge-status-$statusClass">$statusDisplay</span></div>
</div>
<div class="finding-body">
<dl>
$(if ($finding.Description) { "<dt>$(& $t 'technical.descriptionLabel')</dt><dd>$(& $esc $finding.Description)</dd>" })
$(if ($finding.RecommendedValue) { "<dt>$(& $t 'technical.recommendedLabel')</dt><dd>$(& $esc $finding.RecommendedValue)</dd>" })
$(if ($finding.RemediationSteps) { "<dt>$(& $t 'technical.remediationStepsLabel')</dt><dd>$(& $esc $finding.RemediationSteps)</dd>" })
$(if ($finding.RemediationUrl) { "<dt>$(& $t 'technical.referenceLabel')</dt><dd><a href='$(& $esc $finding.RemediationUrl)'>$(& $esc $finding.RemediationUrl)</a></dd>" })
$(if ($isAccepted) { "<dt>$(& $t 'technical.riskAcceptanceLabel')</dt><dd class='finding-accepted'>$(& $tr 'technical.acceptedBy' (& $esc $riskAcceptances[$checkId].AcceptedBy) (& $esc $riskAcceptances[$checkId].Justification))</dd>" })
$(if ($finding.Compliance) {
    $compHtml = "<dt>$(& $t 'technical.complianceLabel')</dt><dd>"
    if ($finding.Compliance.nistSp80053) { $compHtml += "NIST: $($finding.Compliance.nistSp80053 -join ', ') | " }
    if ($finding.Compliance.mitreAttack) { $compHtml += "MITRE: $($finding.Compliance.mitreAttack -join ', ') | " }
    if ($finding.Compliance.cisBenchmark) { $compHtml += "CIS: $($finding.Compliance.cisBenchmark -join ', ')" }
    $compHtml += '</dd>'
    $compHtml
})
</dl>
</div>
</div>
"@)
    }

    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote (& $tr 'technical.footer') `
        -TimestampText $timestampStr))

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.TechnicalReport'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Technical report exported to $OutputPath"
        FindingsCount = $displayFindings.Count
    }
}
