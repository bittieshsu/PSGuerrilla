# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ExecutiveSummary {
    <#
    .SYNOPSIS
        Generates a non-technical board-ready one-pager HTML report.
    .DESCRIPTION
        Produces a concise executive summary suitable for school boards, leadership,
        and non-technical stakeholders. Includes the Guerrilla Score, key risk areas,
        compliance gaps, and top recommended actions — all in plain language.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Executive-Summary.html
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER ProfileName
        Baseline profile context. Default: configured profile.
    .PARAMETER Style
        Report style: Auto (follow the OS), Light, or Dark. Legacy names accepted.
    .EXAMPLE
        Export-ExecutiveSummary -OrganizationName 'Springfield USD'
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [string]$ProfileName,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [string]$Language = ''
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Executive-Summary.html' }

    $dataDir = Get-GuerrillaDataRoot

    # Load findings if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    if (-not $Language) { $Language = Resolve-GuerrillaReportLanguage -Configured '' }
    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw
    $Findings = Get-GuerrillaLocalizedFindings -Findings $Findings -Language $Language
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Calculate score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings } catch { }
    $score = $scoreResult.Score ?? 'N/A'
    $label = $scoreResult.Label ?? ''

    $scoreNum = 0
    $scoreIsNumeric = [int]::TryParse("$score", [ref]$scoreNum)
    $scoreColor = if ($scoreIsNumeric) { Get-GuerrillaScoreColorVar -Score $scoreNum } else { 'var(--g-sev-info)' }

    # Maturity model (CMMI-style 1-5) — the executive maturity rating
    $maturity = $null
    try { $maturity = Get-GuerrillaMaturity -Findings $Findings } catch { }
    $matColors = @{
        '1' = 'var(--g-sev-critical)'
        '2' = 'var(--g-sev-high)'
        '3' = 'var(--g-sev-medium)'
        '4' = 'var(--g-sev-low)'
        '5' = 'var(--g-ok)'
    }
    $maturityStat = ''
    $maturitySection = ''
    if ($maturity -and $maturity.OverallLevel) {
        $matLevel = [int]$maturity.OverallLevel
        $matColor = $matColors["$matLevel"] ?? 'var(--g-sev-info)'
        $matLabel = & $esc ([string]$maturity.OverallLabel)
        $maturityStat = "<div class=`"stat`"><span class=`"value`" style=`"color:$matColor`">$matLevel/5</span><span class=`"label`">$(& $tr 'exec.maturityStat' $matLabel)</span></div>"

        $catRows = ''
        foreach ($k in ($maturity.CategoryLevels.Keys | Sort-Object { [int]$maturity.CategoryLevels[$_].Level })) {
            $cl = $maturity.CategoryLevels[$k]
            $cc = $matColors["$([int]$cl.Level)"] ?? 'var(--g-sev-info)'
            $catName = & $esc (Get-GuerrillaLocalizedCategoryName -Name ([string]$cl.Category) -Language $Language)
            $catRows += "<tr><td>$catName</td><td style=`"color:$cc;font-weight:600;`">$(& $t 'exec.matLevelCell' ([int]$cl.Level))</td><td>$(& $esc ([string]$cl.Label))</td></tr>"
        }
        $blockerHtml = ''
        if ($maturity.NextLevel) {
            $bl = (@($maturity.NextLevelBlockers | Select-Object -First 8 | ForEach-Object { "<li>$(& $esc ([string]$_))</li>" }) -join '')
            if ($bl) { $blockerHtml = "<p>$(& $tr 'exec.maturityToReach' ([int]$maturity.NextLevel))</p><ul>$bl</ul>" }
        }
        $maturitySection = @"
<h2>$(& $t 'exec.maturityHeading')</h2>
<div class="card">
<p>$(& $tr 'exec.maturityOverall' $matColor $matLevel $matLabel)</p>
$blockerHtml
<div class="table-wrap">
<table><thead><tr><th>$(& $t 'exec.thCategory')</th><th>$(& $t 'exec.thLevel')</th><th>$(& $t 'exec.thMaturity')</th></tr></thead><tbody>$catRows</tbody></table>
</div>
</div>
"@
    }

    # Key stats
    $totalFindings = ($Findings ?? @()).Count
    $criticalFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
    $highFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $passRate = if ($totalFindings -gt 0) { [Math]::Round(100 * $passCount / $totalFindings, 0) } else { 0 }

    # Compliance
    $complianceGaps = @()
    try {
        $complianceGaps = @(Get-ComplianceCrosswalk -Findings $Findings -FailOnly | Group-Object Framework | ForEach-Object {
            [PSCustomObject]@{ Framework = $_.Name; Gaps = $_.Count }
        })
    } catch { }

    # Quick wins
    $quickWins = @()
    try { $quickWins = @(Get-QuickWins -Findings $Findings -Top 5 -MaxCostTier Free) } catch { }

    # Top critical findings for narrative
    $topCritical = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' } | Select-Object -First 5)
    $topHigh = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' } | Select-Object -First 5)

    # Build critical findings rows
    $criticalRows = ''
    foreach ($f in $topCritical) {
        $criticalRows += "<li><strong>$(& $esc ($f.Name ?? $f.CheckId ?? 'Unknown'))</strong> &middot; $(& $esc ($f.Description ?? ''))</li>`n"
    }
    foreach ($f in $topHigh) {
        $criticalRows += "<li><strong>$(& $esc ($f.Name ?? $f.CheckId ?? 'Unknown'))</strong> &middot; $(& $esc ($f.Description ?? ''))</li>`n"
    }

    # Quick wins rows
    $quickWinRows = ''
    foreach ($qw in $quickWins) {
        $quickWinRows += "<li><strong>$(& $esc $qw.CheckName)</strong> $(& $tr 'exec.quickWinItem' (& $esc $qw.Severity) $qw.EstimatedHours)</li>`n"
    }

    # Compliance rows
    $complianceHtml = ''
    foreach ($cg in $complianceGaps) {
        $complianceHtml += "<span class=`"badge`"><strong>$(& $esc ([string]$cg.Framework))</strong>: $(& $tr 'exec.gaps' $cg.Gaps)</span>`n"
    }

    $html = [System.Text.StringBuilder]::new(32768)

    $subtitle = "$(& $esc $OrganizationName) &middot; $(if ($ProfileName) { "$(& $esc $ProfileName) $(& $t 'exec.profileSuffix') &middot; " })$timestamp UTC"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title (& $tr 'exec.title') `
        -Subtitle $subtitle `
        -HtmlTitle "$(& $tr 'exec.htmlTitle') - $OrganizationName - $timestamp UTC" `
        -TopbarMeta (& $tr 'exec.topbar') `
        -Style $Style))

    $circumference = 2 * [Math]::PI * 50
    $dashOffset = if ($scoreIsNumeric) { $circumference * (1 - ($scoreNum / 100)) } else { $circumference }
    $verdict = if (-not $scoreIsNumeric) { & $t 'exec.verdictNoScore' }
        elseif ($scoreNum -ge 75) { & $t 'exec.verdict75' }
        elseif ($scoreNum -ge 50) { & $t 'exec.verdict50' }
        else { & $t 'exec.verdict0' }

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="var(--g-surface-alt)" stroke-width="10"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="$scoreColor" stroke-width="10"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashOffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value">$score</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$(& $tr 'exec.securityPosture' (& $esc $label))</div>
    <div class="desc">$verdict</div>
  </div>
</div>

<div class="stat-grid">
<div class="stat"><span class="value">$totalFindings</span><span class="label">$(& $t 'common.totalChecks')</span></div>
<div class="stat"><span class="value" style="color:var(--g-ok)">$passRate%</span><span class="label">$(& $t 'exec.passRate')</span></div>
<div class="stat"><span class="value" style="color:var(--g-sev-critical)">$criticalFails</span><span class="label">$(& $t 'exec.criticalIssues')</span></div>
<div class="stat"><span class="value" style="color:var(--g-sev-high)">$highFails</span><span class="label">$(& $t 'exec.highIssues')</span></div>
$maturityStat
</div>

$maturitySection
$(if ($criticalRows) {
@"
<h2>$(& $t 'exec.keyFindings')</h2>
<div class="card">
<ul>
$criticalRows
</ul>
</div>
"@
})

$(if ($complianceHtml) {
@"
<h2>$(& $t 'exec.complianceImpact')</h2>
<div class="card">
<p>$(& $t 'exec.complianceIntro')</p>
$complianceHtml
</div>
"@
})

$(if ($quickWinRows) {
@"
<h2>$(& $t 'exec.quickWins')</h2>
<div class="card">
<p>$(& $t 'exec.quickWinsIntro')</p>
<ol>
$quickWinRows
</ol>
</div>
"@
})

<h2>$(& $t 'exec.nextSteps')</h2>
<div class="card">
<ol>
<li>$(& $tr 'exec.nextStep1')</li>
<li>$(& $t 'exec.nextStep2')</li>
<li>$(& $t 'exec.nextStep3')</li>
<li>$(& $t 'exec.nextStep4')</li>
</ol>
</div>

<p style="color:var(--g-muted);font-size:0.9rem;font-style:italic;">$(& $t 'exec.disclaimer')</p>
"@)

    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote (& $tr 'exec.footer') `
        -TimestampText "$timestamp UTC"))

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.ExecutiveSummary'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Executive summary exported to $OutputPath"
        Score      = $score
        Label      = $label
    }
}
