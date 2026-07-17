# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ADReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [int]$OverallScore,

        [Parameter(Mandatory)]
        [string]$ScoreLabel,

        [Parameter(Mandatory)]
        [hashtable]$CategoryScores,

        [string]$DomainName = '',
        [AllowNull()]$RunDiff,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [hashtable]$Branding,

        # When a BloodHound OpenGraph export was written, its path — surfaced as a report callout.
        [string]$BloodHoundPath,

        [string]$Language = 'en'
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $Findings = Get-GuerrillaLocalizedFindings -Findings $Findings -Language $Language
    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw

    $timestampStr = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    # --- Counts ---
    $totalChecks = $Findings.Count
    $passCount   = @($Findings | Where-Object Status -eq 'PASS').Count
    $failCount   = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount   = @($Findings | Where-Object Status -eq 'WARN').Count
    $skipCount   = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($Findings | Where-Object Status -eq 'FAIL')
    $critCount    = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount    = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount     = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount     = @($failFindings | Where-Object Severity -eq 'Low').Count

    $scoreColor = Get-GuerrillaScoreColorVar -Score $OverallScore

    $html = [System.Text.StringBuilder]::new(65536)

    # ═══ SHELL + HEADER ═══
    $subtitle = "$(& $t 'common.domain'): $(& $esc $DomainName) &middot; $(& $t 'common.generated'): $timestampStr"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title (& $tr 'ad.title') `
        -Subtitle $subtitle `
        -HtmlTitle "$(& $tr 'ad.htmlTitle')$(if ($DomainName) { " - $DomainName" }) - $timestampStr" `
        -TopbarMeta (& $tr 'ad.topbar') `
        -Style $Style -Language $Language -Branding $Branding))

    # ═══ SCORE PANEL ═══
    $circumference = 2 * [Math]::PI * 50
    $dashoffset = $circumference * (1 - ($OverallScore / 100))

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="var(--g-surface-alt)" stroke-width="10"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="$scoreColor" stroke-width="10"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashoffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value">$OverallScore</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$(& $esc $ScoreLabel)</div>
    <div class="desc">$(& $t 'ad.postureDesc')</div>
    <div class="desc">$(& $tr 'common.checksSummary' $totalChecks $passCount $failCount $warnCount $skipCount)</div>
  </div>
</div>
"@)

    # ═══ WHAT CHANGED SINCE LAST RUN — shared section, before findings ═══
    [void]$html.Append((Get-GuerrillaComparisonSectionHtml -RunDiff $RunDiff -Esc $esc -Language $Language))

    # ═══ EXECUTIVE SUMMARY ═══
    $verdict = switch ($true) {
        ($OverallScore -ge 90) { & $t 'ad.verdict90'; break }
        ($OverallScore -ge 75) { & $t 'ad.verdict75'; break }
        ($OverallScore -ge 60) { & $t 'ad.verdict60'; break }
        ($OverallScore -ge 40) { & $t 'ad.verdict40'; break }
        default { & $t 'ad.verdict0' }
    }
    $noticeClass = if ($OverallScore -ge 75) { 'notice-ok' } elseif ($OverallScore -ge 60) { 'notice-warn' } else { 'notice-bad' }

    [void]$html.Append(@"
<div class="notice $noticeClass">
  <h3>$(& $t 'common.executiveSummary')</h3>
  <p>$verdict</p>
  <p>$(& $tr 'ad.sevSummary' $critCount $highCount $medCount $lowCount)</p>
</div>
"@)

    # ═══ SECURITY MATURITY (CMMI 1-5) — shared section ═══
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $Findings -Esc $esc -Language $Language))

    # ═══ INDICATORS OF EXPOSURE — shared ranked exposure view ═══
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $Findings -Esc $esc -Language $Language))

    # ═══ ATTACK-PATH CARTOGRAPHY (visual map) + ATTACK PATHS list — shared sections ═══
    [void]$html.Append((Get-GuerrillaCartographyHtml -Findings $Findings -Esc $esc -Language $Language))
    [void]$html.Append((Get-GuerrillaAttackPathSectionHtml -Findings $Findings -Esc $esc -Language $Language))

    # ═══ BLOODHOUND EXPORT CALLOUT ═══
    if ($BloodHoundPath) {
        [void]$html.Append(@"
<h2>$(& $t 'ad.bloodhoundHeading')</h2>
<div class="notice">
  <p>$(& $tr 'ad.bloodhoundExport' (& $esc $BloodHoundPath))</p>
  <p>$(& $tr 'ad.bloodhoundImport')</p>
</div>
"@)
    }

    # ═══ STAT CARDS ═══
    [void]$html.Append('<div class="stat-grid">')
    $statCards = @(
        @{ Value = $totalChecks; Label = (& $t 'common.totalChecks'); Color = 'var(--g-heading)' }
        @{ Value = $passCount;   Label = (& $t 'common.passed');      Color = 'var(--g-ok)' }
        @{ Value = $critCount;   Label = (& $t 'common.critical');    Color = 'var(--g-sev-critical)' }
        @{ Value = $highCount;   Label = (& $t 'common.high');        Color = 'var(--g-sev-high)' }
        @{ Value = $medCount;    Label = (& $t 'common.medium');      Color = 'var(--g-sev-medium)' }
        @{ Value = $lowCount;    Label = (& $t 'common.low');         Color = 'var(--g-sev-low)' }
    )
    foreach ($card in $statCards) {
        [void]$html.Append(@"
  <div class="stat">
    <span class="value" style="color:$($card.Color)">$($card.Value)</span>
    <span class="label">$($card.Label)</span>
  </div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ CATEGORY SCORES ═══
    [void]$html.Append("<h2>$(& $t 'common.categoryBreakdown')</h2><div class=`"category-grid`">")
    foreach ($cat in ($CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $cs = $cat.Value.Score
        $cc = Get-GuerrillaScoreColorVar -Score $cs
        $catLabel = & $esc (Get-GuerrillaLocalizedCategoryName -Name "$($cat.Key)" -Language $Language)
        [void]$html.Append(@"
  <div class="cat-card">
    <div class="cat-header">
      <div class="cat-name">$catLabel</div>
      <div class="cat-score" style="color:$cc">$cs</div>
    </div>
    <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${cs}%;background:$cc"></div></div>
    <div class="cat-counts">
      <span class="verdict-pass">$(& $t 'common.passLabel') $($cat.Value.Pass)</span>
      <span class="verdict-fail">$(& $t 'common.failLabel') $($cat.Value.Fail)</span>
      <span class="verdict-warn">$(& $t 'common.warnLabel') $($cat.Value.Warn)</span>
      <span class="verdict-na">$(& $t 'common.skipLabel') $($cat.Value.Skip)</span>
    </div>
  </div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ PRIORITY FINDINGS ═══
    $priorityFindings = @($Findings | Where-Object { $_.Status -eq 'FAIL' } |
        Sort-Object @{Expression={@{Critical=0;High=1;Medium=2;Low=3;Info=4}[$_.Severity] ?? 5}},CheckId)

    # ═══ INTERACTIVE FILTER BAR (live status/severity/search over the findings tables below) ═══
    [void]$html.Append((Get-GuerrillaFindingsFilterHtml -Language $Language))

    if ($priorityFindings.Count -gt 0) {
        [void]$html.Append(@"
<h2>$(& $t 'ad.findingsByPriority')</h2>
<div class="table-wrap">
<table class="priority-table">
  <thead><tr><th>$(& $t 'common.thId')</th><th>$(& $t 'common.thSeverity')</th><th>$(& $t 'common.thStatus')</th><th>$(& $t 'common.thCategory')</th><th>$(& $t 'common.thCheck')</th><th>$(& $t 'common.thFinding')</th><th>$(& $t 'common.thRemediation')</th></tr></thead>
  <tbody>
"@)
        foreach ($f in $priorityFindings) {
            $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $sevClass = $f.Severity.ToLower()
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { & $t 'common.accepted' } else { & $esc $f.Status }
            $remediation = if ($f.RemediationSteps) { $f.RemediationSteps } else { $f.RecommendedValue }
            $catLabel = & $esc (Get-GuerrillaLocalizedCategoryName -Name "$($f.Category)" -Language $Language)
            $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())
            [void]$html.Append(@"
    <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
      <td><span class="badge badge-status-$statusClass">$statusLabel</span></td>
      <td>$catLabel</td>
      <td>$(& $esc $f.CheckName)</td>
      <td>$(& $esc $f.CurrentValue)</td>
      <td><small>$(& $esc $remediation)</small></td>
    </tr>
"@)
            if ($f.Status -in @('FAIL', 'WARN')) {
                $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details -Language $Language
                if ($affectedHtml) {
                    [void]$html.Append("<tr class=`"gg-row finding-extra`" data-status=`"$(& $esc $f.Status)`" data-sev=`"$(& $esc $f.Severity)`" data-text=`"$rowText`"><td colspan=`"7`">$affectedHtml</td></tr>")
                }
            }
        }
        [void]$html.Append('</tbody></table></div>')
    }

    # ═══ DETAILED CATEGORY SECTIONS ═══
    [void]$html.Append("<h2>$(& $t 'common.detailedByCategory')</h2>")

    $categoryGroups = $Findings | Group-Object -Property Category | Sort-Object Name
    foreach ($group in $categoryGroups) {
        $catFindings = @($group.Group | Sort-Object @{Expression={@{Critical=0;High=1;Medium=2;Low=3;Info=4}[$_.Severity] ?? 5}},CheckId)
        $catPass = @($catFindings | Where-Object Status -eq 'PASS').Count
        $catFail = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $catWarn = @($catFindings | Where-Object Status -eq 'WARN').Count
        $catLabel = & $esc (Get-GuerrillaLocalizedCategoryName -Name "$($group.Name)" -Language $Language)

        [void]$html.Append(@"
<details class="cat-detail">
  <summary>$catLabel<span class="sum-counts">$(& $tr 'common.summaryCounts' $catFindings.Count $catPass $catFail $catWarn)</span></summary>
  <div class="detail-body">
    <table>
      <thead><tr><th>$(& $t 'common.thId')</th><th>$(& $t 'common.thSeverity')</th><th>$(& $t 'common.thStatus')</th><th>$(& $t 'common.thCheck')</th><th>$(& $t 'common.thCurrentValue')</th><th>$(& $t 'common.thRecommended')</th><th>$(& $t 'common.thRemediation')</th></tr></thead>
      <tbody>
"@)
        foreach ($f in $catFindings) {
            $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $sevClass = $f.Severity.ToLower()
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { & $t 'common.accepted' } else { & $esc $f.Status }
            $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())
            [void]$html.Append(@"
        <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
          <td><code>$(& $esc $f.CheckId)</code></td>
          <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
          <td><span class="badge badge-status-$statusClass">$statusLabel</span></td>
          <td>$(& $esc $f.CheckName)<br><small>$(& $esc $f.Description)</small></td>
          <td>$(& $esc $f.CurrentValue)</td>
          <td>$(& $esc $f.RecommendedValue)</td>
          <td><small>$(& $esc $f.RemediationSteps)</small></td>
        </tr>
"@)
            if ($f.Status -in @('FAIL', 'WARN')) {
                $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details -Language $Language
                if ($affectedHtml) {
                    [void]$html.Append("<tr class=`"gg-row finding-extra`" data-status=`"$(& $esc $f.Status)`" data-sev=`"$(& $esc $f.Severity)`" data-text=`"$rowText`"><td colspan=`"7`">$affectedHtml</td></tr>")
                }
            }
        }
        [void]$html.Append('</tbody></table></div></details>')
    }

    # ═══ COMPLIANCE MAPPING ═══
    $findingsWithCompliance = @($Findings | Where-Object {
        $_.Compliance.MitreAttack.Count -gt 0 -or $_.Compliance.NistSp80053.Count -gt 0 -or
        ($_.Compliance.Anssi ?? @()).Count -gt 0 -or ($_.Compliance.CisAd ?? @()).Count -gt 0
    })
    if ($findingsWithCompliance.Count -gt 0) {
        [void]$html.Append(@"
<h2>$(& $t 'common.complianceMapping')</h2>
<div class="table-wrap">
<table class="compliance-table">
  <thead><tr><th>$(& $t 'common.thCheckId')</th><th>$(& $t 'common.thStatus')</th><th>$(& $t 'common.thMitre')</th><th>$(& $t 'common.thNist')</th><th>$(& $t 'common.thCisAd')</th><th>$(& $t 'common.thAnssi')</th></tr></thead>
  <tbody>
"@)
        foreach ($f in ($findingsWithCompliance | Where-Object Status -eq 'FAIL' | Select-Object -First 50)) {
            $mitre = ($f.Compliance.MitreAttack | ForEach-Object { "<code>$_</code>" }) -join ' '
            $nist = ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$_</code>" }) -join ' '
            $cisAd = (($f.Compliance.CisAd ?? @()) | ForEach-Object { "<code>$_</code>" }) -join ' '
            $anssi = (($f.Compliance.Anssi ?? @()) | ForEach-Object { "<code>$_</code>" }) -join ' '
            $statusClass = $f.Status.ToLower()
            [void]$html.Append(@"
    <tr>
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td><span class="badge badge-status-$statusClass">$(& $esc $f.Status)</span></td>
      <td>$mitre</td><td>$nist</td><td>$cisAd</td><td>$anssi</td>
    </tr>
"@)
        }
        [void]$html.Append('</tbody></table></div>')
    }

    # ═══ FOOTER + SHELL END ═══
    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote (& $tr 'ad.footer') `
        -TimestampText $timestampStr))

    Set-Content -Path $FilePath -Value $html.ToString() -Encoding UTF8
}
