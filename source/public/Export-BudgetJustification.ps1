# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-BudgetJustification {
    <#
    .SYNOPSIS
        Generates a board-ready budget justification document from audit findings.
    .DESCRIPTION
        Produces an HTML document suitable for presenting to school boards, executives,
        or budget committees. Groups remediation items by cost tier, shows total cost
        estimates, and maps findings to compliance requirements.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Budget-Justification.html in current directory.
    .PARAMETER ProfileName
        Baseline profile context. Default: uses configured profile.
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER ConfigPath
        Override config file path.
    .PARAMETER Style
        Report style: Auto (follow the OS), Light, or Dark. Legacy names accepted.
    .EXAMPLE
        Export-BudgetJustification -OrganizationName 'Springfield USD'
        Generates a budget justification report for the district.
    .EXAMPLE
        $findings = Invoke-GWSAudit -PassThru; Export-BudgetJustification -Findings $findings -OutputPath ./budget.html
        Generates report from specific findings.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,

        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [string]$ProfileName,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [string]$Language = ''
    )

    # Load config
    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = $null
    if ($cfgPath -and (Test-Path $cfgPath)) {
        $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
    }

    if (-not $ProfileName) { $ProfileName = $config.profile ?? 'Default' }
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Budget-Justification.html' }

    # Load findings from state if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        $dataDir = Get-GuerrillaDataRoot
        $findingsFiles = @()
        if (Test-Path $dataDir) {
            $findingsFiles = @(Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)
        }
        if ($findingsFiles.Count -gt 0) {
            $Findings = @()
            foreach ($f in $findingsFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $Findings += @($data)
                } catch { Write-Verbose "Failed to load findings: $_" }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return [PSCustomObject]@{ Success = $false; Message = 'No findings'; Path = $null }
    }

    if (-not $Language) { $Language = Resolve-GuerrillaReportLanguage -Configured '' }
    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw
    $Findings = Get-GuerrillaLocalizedFindings -Findings $Findings -Language $Language

    # Load remediation costs
    $remPath = Join-Path $script:ModuleRoot 'Data/RemediationCosts.json'
    $remData = $null
    if (Test-Path $remPath) {
        $remData = Get-Content -Path $remPath -Raw | ConvertFrom-Json -AsHashtable
    }

    # Get all actionable findings with cost info
    $allFixes = Get-ResourceConstrainedFixes -Findings $Findings -MaxCostTier 'Medium' -RemediationData $remData

    # Also get high/enterprise items
    $tierOrder = @{ 'Free' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Enterprise' = 4 }
    $highCostFixes = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($finding in $Findings) {
        if ($finding.Status -notin @('FAIL', 'WARN')) { continue }
        $checkId = $finding.CheckId ?? $finding.Id ?? ''
        $prefix = if ($checkId -match '^([A-Z0-9]+)-') { $Matches[1] } else { '' }
        $costInfo = $remData.overrides.$checkId ?? $remData.categoryDefaults.$prefix
        if (-not $costInfo) { continue }
        $tier = $costInfo.costTier ?? 'Medium'
        if ($tierOrder[$tier] -gt 2) {
            $highCostFixes.Add([PSCustomObject]@{
                CheckId    = $checkId
                CheckName  = $finding.Name ?? $checkId
                Severity   = $finding.Severity ?? 'Medium'
                Status     = $finding.Status
                CostTier   = $tier
                Effort     = $costInfo.effort ?? 'High'
                Category   = $finding.Category ?? $prefix
                Notes      = $costInfo.notes ?? ''
            })
        }
    }

    # Calculate summary stats
    $failCount = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($Findings | Where-Object Status -eq 'WARN').Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $totalChecks = $Findings.Count
    $criticalFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
    $highFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count

    # Guerrilla Score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings } catch { }
    $score = $scoreResult.Score ?? 'N/A'
    $label = $scoreResult.Label ?? ''

    $scoreNum = 0
    $scoreIsNumeric = [int]::TryParse("$score", [ref]$scoreNum)
    $scoreColor = if ($scoreIsNumeric) { Get-GuerrillaScoreColorVar -Score $scoreNum } else { 'var(--g-sev-info)' }

    # Group fixes by cost tier
    $freeFixes = @($allFixes | Where-Object CostTier -eq 'Free')
    $lowFixes = @($allFixes | Where-Object CostTier -eq 'Low')
    $medFixes = @($allFixes | Where-Object CostTier -eq 'Medium')

    # Cost estimates from RemediationCosts.json tiers
    $costRanges = $remData.costTiers ?? @{}

    # Build compliance impact summary
    $complianceMappings = @()
    try { $complianceMappings = Get-ComplianceCrosswalk -Findings $Findings -FailOnly } catch { }
    $complianceFrameworks = @($complianceMappings | Group-Object Framework | ForEach-Object {
        [PSCustomObject]@{ Framework = $_.Name; GapCount = $_.Count }
    })

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Build fix rows HTML
    $fixRowsHtml = { param($fixes)
        $rows = ''
        foreach ($fix in $fixes) {
            $sevClass = switch ("$($fix.Severity)") {
                'Critical' { 'critical' }
                'High'     { 'high' }
                'Medium'   { 'medium' }
                'Low'      { 'low' }
                default    { 'info' }
            }
            $rows += @"
<tr>
<td><code>$([System.Web.HttpUtility]::HtmlEncode($fix.CheckId))</code></td>
<td>$([System.Web.HttpUtility]::HtmlEncode($fix.CheckName))</td>
<td><span class="badge badge-sev-$sevClass">$([System.Web.HttpUtility]::HtmlEncode($fix.Severity))</span></td>
<td>$([System.Web.HttpUtility]::HtmlEncode($fix.Effort))</td>
<td>~$($fix.EstimatedHours)h</td>
</tr>
"@
        }
        return $rows
    }

    $freeRows = & $fixRowsHtml $freeFixes
    $lowRows = & $fixRowsHtml $lowFixes
    $medRows = & $fixRowsHtml $medFixes

    $complianceRows = ''
    foreach ($fw in $complianceFrameworks) {
        $complianceRows += "<tr><td>$(& $esc ([string]$fw.Framework))</td><td><span class=`"verdict-fail`">$(& $tr 'budget.gaps' $fw.GapCount)</span></td></tr>`n"
    }

    $extraCss = @'
.phase { background: var(--g-surface); border-radius: var(--radius); padding: 1.1rem 1.4rem; margin: 1.2rem 0; }
.phase-head { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
.phase-title { font-weight: 600; font-size: 1.1rem; color: var(--g-heading); }
.phase-cost { color: var(--g-ok); font-weight: 600; white-space: nowrap; }
.phase > p:first-of-type { margin-top: 0.4em; }
'@

    $subtitle = "<strong>$(& $esc $OrganizationName)</strong> &middot; $(& $t 'budget.profileLabel'): $(& $esc $ProfileName) &middot; $(& $t 'common.generated'): $timestamp UTC"
    $shellStart = Get-GuerrillaReportShellStart `
        -Title (& $tr 'budget.title') `
        -Subtitle $subtitle `
        -HtmlTitle "$(& $tr 'budget.htmlTitle') - $OrganizationName - $timestamp UTC" `
        -TopbarMeta (& $tr 'budget.topbar') `
        -Style $Style -Language $Language -ExtraCss $extraCss

    $html = @"
$shellStart
<h2>$(& $t 'budget.executiveSummary')</h2>
<div class="stat-grid">
<div class="stat">
<span class="value" style="color:$scoreColor">$score</span>
<span class="label">$(& $t 'budget.guerrillaScore')$(if ($label) { " ($(& $esc $label))" })</span>
</div>
<div class="stat">
<span class="value" style="color:var(--g-sev-critical)">$criticalFails</span>
<span class="label">$(& $t 'budget.criticalFailures')</span>
</div>
<div class="stat">
<span class="value" style="color:var(--g-sev-high)">$highFails</span>
<span class="label">$(& $t 'budget.highFailures')</span>
</div>
<div class="stat">
<span class="value">$totalChecks</span>
<span class="label">$(& $tr 'budget.totalChecksBreakdown' $passCount $failCount $warnCount)</span>
</div>
</div>

$(if ($complianceFrameworks.Count -gt 0) {
@"
<h2>$(& $t 'budget.complianceImpact')</h2>
<p>$(& $t 'budget.complianceIntro')</p>
<div class="table-wrap">
<table>
<thead><tr><th>$(& $t 'budget.thFramework')</th><th>$(& $t 'budget.thGapsFound')</th></tr></thead>
<tbody>
$complianceRows
</tbody>
</table>
</div>
"@
})

<h2>$(& $t 'budget.investmentPhases')</h2>

<div class="phase">
<div class="phase-head">
<span class="phase-title">$(& $t 'budget.phase1Title')</span>
<span class="phase-cost">$($costRanges.Free.annualCostRange ?? '$0')</span>
</div>
<p>$(& $tr 'budget.phase1Desc')</p>
$(if ($freeFixes.Count -gt 0) {
@"
<div class="table-wrap">
<table>
<thead><tr><th>$(& $t 'budget.thCheck')</th><th>$(& $t 'budget.thFinding')</th><th>$(& $t 'budget.thSeverity')</th><th>$(& $t 'budget.thEffort')</th><th>$(& $t 'budget.thTime')</th></tr></thead>
<tbody>
$freeRows
</tbody>
</table>
</div>
<p><strong>$(& $t 'budget.actions' $freeFixes.Count)</strong> &middot; $(& $tr 'budget.estimatedEffort' ([Math]::Round(($freeFixes | Measure-Object EstimatedHours -Sum).Sum, 1)))</p>
"@
} else { "<p>$(& $t 'budget.noFree')</p>" })
</div>

<div class="phase">
<div class="phase-head">
<span class="phase-title">$(& $t 'budget.phase2Title')</span>
<span class="phase-cost">$($costRanges.Low.annualCostRange ?? '$0 - $500')</span>
</div>
<p>$(& $t 'budget.phase2Desc')</p>
$(if ($lowFixes.Count -gt 0) {
@"
<div class="table-wrap">
<table>
<thead><tr><th>$(& $t 'budget.thCheck')</th><th>$(& $t 'budget.thFinding')</th><th>$(& $t 'budget.thSeverity')</th><th>$(& $t 'budget.thEffort')</th><th>$(& $t 'budget.thTime')</th></tr></thead>
<tbody>
$lowRows
</tbody>
</table>
</div>
<p><strong>$(& $t 'budget.actions' $lowFixes.Count)</strong> &middot; $(& $tr 'budget.estimatedEffort' ([Math]::Round(($lowFixes | Measure-Object EstimatedHours -Sum).Sum, 1)))</p>
"@
} else { "<p>$(& $t 'budget.noLow')</p>" })
</div>

<div class="phase">
<div class="phase-head">
<span class="phase-title">$(& $t 'budget.phase3Title')</span>
<span class="phase-cost">$($costRanges.Medium.annualCostRange ?? '$500 - $5,000')</span>
</div>
<p>$(& $t 'budget.phase3Desc')</p>
$(if ($medFixes.Count -gt 0) {
@"
<div class="table-wrap">
<table>
<thead><tr><th>$(& $t 'budget.thCheck')</th><th>$(& $t 'budget.thFinding')</th><th>$(& $t 'budget.thSeverity')</th><th>$(& $t 'budget.thEffort')</th><th>$(& $t 'budget.thTime')</th></tr></thead>
<tbody>
$medRows
</tbody>
</table>
</div>
<p><strong>$(& $t 'budget.actions' $medFixes.Count)</strong> &middot; $(& $tr 'budget.estimatedEffort' ([Math]::Round(($medFixes | Measure-Object EstimatedHours -Sum).Sum, 1)))</p>
"@
} else { "<p>$(& $t 'budget.noMed')</p>" })
</div>

$(if ($highCostFixes.Count -gt 0) {
@"
<div class="phase">
<div class="phase-head">
<span class="phase-title">$(& $t 'budget.phase4Title')</span>
<span class="phase-cost">$($costRanges.High.annualCostRange ?? '$5,000+')</span>
</div>
<p>$(& $tr 'budget.phase4Desc')</p>
<p>$(& $tr 'budget.phase4Body' $highCostFixes.Count)</p>
</div>
"@
})

<p style="color:var(--g-muted);font-size:0.9rem;font-style:italic;">$(& $t 'budget.disclaimer')</p>
$(Get-GuerrillaReportShellEnd -FooterNote (& $tr 'budget.footer') -TimestampText "$timestamp UTC")
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.BudgetJustification'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Budget justification exported to $OutputPath"
        Summary    = [PSCustomObject]@{
            GuerrillaScore  = $score
            TotalChecks     = $totalChecks
            CriticalFails   = $criticalFails
            HighFails       = $highFails
            FreeFixCount    = $freeFixes.Count
            LowCostFixCount = $lowFixes.Count
            MedCostFixCount = $medFixes.Count
            HighCostFixCount = $highCostFixes.Count
            ComplianceGaps   = $complianceFrameworks
        }
    }
}
