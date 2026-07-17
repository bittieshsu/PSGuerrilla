# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-GWSReportHtml {
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

        [string]$TenantDomain = '',
        [AllowNull()]$RunDiff,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [hashtable]$Branding,

        [string]$Language = 'en'
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $Findings = Get-GuerrillaLocalizedFindings -Findings $Findings -Language $Language
    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw

    # Render the affected accounts/objects captured in a finding's Details as one or more
    # labeled BULLETED lists — delegates to the shared Get-GuerrillaReportAffectedHtml so the
    # GWS, AD, Entra and Campaign reports all surface affected entities identically.
    $renderAffected = {
        param($Details)
        Get-GuerrillaReportAffectedHtml -Details $Details -Language $Language
    }

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

    $scoreColor   = Get-GuerrillaScoreColorVar -Score $OverallScore
    $displayLabel = $ScoreLabel

    $extraCss = @'
.extra-wrap { display: flex; flex-direction: column; gap: 0.5rem; }
.extra-links { display: flex; flex-wrap: wrap; gap: 1.2rem; font-size: 0.88rem; margin-top: 0.2rem; }
.remediation-cell { max-width: 300px; font-size: 0.9em; }
'@

    $html = [System.Text.StringBuilder]::new(65536)

    # ═══ SHELL + HEADER ═══
    $domainLine = if ($TenantDomain) { "$(& $t 'common.domain'): $(& $esc $TenantDomain) &middot; " } else { '' }
    $subtitle = "${domainLine}$(& $t 'common.generated'): $timestampStr &middot; $(& $tr 'gws.configChecksEvaluated' $totalChecks)"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title (& $tr 'gws.title') `
        -Subtitle $subtitle `
        -HtmlTitle "$(& $tr 'gws.htmlTitle')$(if ($TenantDomain) { " - $TenantDomain" }) - $timestampStr" `
        -TopbarMeta (& $tr 'gws.topbar') `
        -Style $Style -Branding $Branding -ExtraCss $extraCss))

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
    <div class="label" style="color:$scoreColor">$(& $esc $displayLabel)</div>
    <div class="desc">$(& $t 'gws.postureDesc')</div>
    <div class="desc">$(& $tr 'common.checksSummary' $totalChecks $passCount $failCount $warnCount $skipCount)</div>
  </div>
</div>
"@)

    # ═══ WHAT CHANGED SINCE LAST RUN — shared section, before findings ═══
    [void]$html.Append((Get-GuerrillaComparisonSectionHtml -RunDiff $RunDiff -Esc $esc -Language $Language))

    # ═══ EXECUTIVE SUMMARY ═══
    $summaryVerdict = if ($critCount -gt 0) {
        & $t 'gws.verdictCrit' $critCount
    } elseif ($highCount -gt 0) {
        & $t 'gws.verdictHigh' $highCount
    } elseif ($medCount -gt 0) {
        & $t 'gws.verdictMed' $medCount
    } elseif ($failCount -gt 0) {
        & $t 'gws.verdictLow' $lowCount
    } else {
        & $t 'gws.verdictPass'
    }
    $noticeClass = if ($critCount -gt 0) { 'notice-bad' } elseif ($highCount -gt 0 -or $medCount -gt 0) { 'notice-warn' } else { 'notice-ok' }

    [void]$html.Append(@"
<div class="notice $noticeClass">
  <h3>$(& $t 'common.executiveSummary')</h3>
  <p><strong>$(& $t 'gws.assessmentLabel')</strong> $summaryVerdict</p>
  <p><strong>$(& $t 'gws.scopeLabel')</strong> $(& $tr 'gws.scope' $totalChecks $CategoryScores.Count)</p>
  <p><strong>$(& $t 'gws.resultsLabel')</strong> $(& $tr 'gws.results' $passCount $failCount $warnCount $skipCount)</p>
"@)
    if ($critCount -gt 0) {
        [void]$html.Append("<p style=`"color:var(--g-bad)`"><strong>$(& $t 'gws.criticalRequire' $critCount)</strong></p>")
    }
    [void]$html.Append('</div>')

    # ═══ STAT CARDS ═══
    [void]$html.Append('<div class="stat-grid">')
    $statCards = @(
        @{ Value = $totalChecks; Label = (& $t 'common.totalChecks'); Color = 'var(--g-heading)' }
        @{ Value = $passCount;   Label = (& $t 'common.passed');      Color = 'var(--g-ok)' }
        @{ Value = $failCount;   Label = (& $t 'common.failed');      Color = 'var(--g-bad)' }
        @{ Value = $warnCount;   Label = (& $t 'common.warnings');    Color = 'var(--g-warn)' }
        @{ Value = $skipCount;   Label = (& $t 'common.skipped');     Color = 'var(--g-muted)' }
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

    # ═══ SECURITY MATURITY + INDICATORS OF EXPOSURE — shared sections ═══
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $Findings -Esc $esc -Language $Language))
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $Findings -Esc $esc -Language $Language))

    # ═══ CATEGORY SCORES ═══
    [void]$html.Append("<h2>$(& $t 'common.categoryScores')</h2><div class=`"category-grid`">")
    foreach ($cat in ($CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $catScore = $cat.Value.Score
        $catColor = Get-GuerrillaScoreColorVar -Score $catScore
        $catLabel = & $esc (Get-GuerrillaLocalizedCategoryName -Name "$($cat.Key)" -Language $Language)
        [void]$html.Append(@"
  <div class="cat-card">
    <div class="cat-header">
      <div class="cat-name">$catLabel</div>
      <div class="cat-score" style="color:$catColor">$catScore</div>
    </div>
    <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${catScore}%;background:$catColor"></div></div>
    <div class="cat-counts">
      <span class="verdict-pass">$(& $t 'common.passLabel') $($cat.Value.Pass)</span>
      <span class="verdict-fail">$(& $t 'common.failLabel') $($cat.Value.Fail)</span>
      <span class="verdict-warn">$(& $t 'common.warnLabel') $($cat.Value.Warn)</span>
    </div>
  </div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ INTERACTIVE FILTER BAR (live status/severity/search over the findings tables below) ═══
    [void]$html.Append((Get-GuerrillaFindingsFilterHtml -Language $Language))

    # ═══ CRITICAL & HIGH FINDINGS TABLE ═══
    $priorityFindings = @($failFindings | Where-Object { $_.Severity -in @('Critical', 'High') } |
        Sort-Object { if ($_.Severity -eq 'Critical') { 0 } else { 1 } }, CheckId)

    if ($priorityFindings.Count -gt 0) {
        [void]$html.Append(@"
<h2>$(& $tr 'gws.priorityCritHigh')</h2>
<div class="table-wrap">
<table class="priority-table">
  <thead><tr><th>$(& $t 'common.thCheckId')</th><th>$(& $t 'common.thCheckName')</th><th>$(& $t 'common.thCategory')</th><th>$(& $t 'common.thSeverity')</th><th>$(& $t 'common.thCurrentValue')</th><th>$(& $t 'common.thRemediation')</th></tr></thead>
  <tbody>
"@)
        foreach ($f in $priorityFindings) {
            $sevClass = $f.Severity.ToLower()
            $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())
            $catLabel = & $esc (Get-GuerrillaLocalizedCategoryName -Name "$($f.Category)" -Language $Language)
            $remParts = [System.Collections.Generic.List[string]]::new()
            if ($f.RemediationUrl) {
                $remParts.Add("<a href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`" rel=`"noopener`">$(& $t 'gws.fixInConsole')</a>")
            }
            if ($f.ReferenceUrl) {
                $remParts.Add("<a href=`"$(& $esc $f.ReferenceUrl)`" target=`"_blank`" rel=`"noopener`">$(& $tr 'gws.whyUnsafe')</a>")
            }
            $remLink = if ($remParts.Count -gt 0) { $remParts -join '<br>' } else { '' }

            [void]$html.Append(@"
    <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td>$(& $esc $f.CheckName)</td>
      <td>$catLabel</td>
      <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
      <td>$(& $esc $f.CurrentValue)</td>
      <td>$remLink</td>
    </tr>
"@)
        }
        [void]$html.Append('</tbody></table></div>')
    }

    # ═══ PER-CATEGORY DETAIL SECTIONS ═══
    [void]$html.Append("<h2>$(& $t 'common.detailedByCategory')</h2>")

    $categories = $Findings | Group-Object -Property Category | Sort-Object Name

    foreach ($catGroup in $categories) {
        $catName     = $catGroup.Name
        $catFindings = @($catGroup.Group | Sort-Object {
            switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
        }, CheckId)

        $catPass = @($catFindings | Where-Object Status -eq 'PASS').Count
        $catFail = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $catWarn = @($catFindings | Where-Object Status -eq 'WARN').Count

        $catHasFailures = $catFail -gt 0
        $openAttr = if ($catHasFailures) { ' open' } else { '' }

        $catInfo = $CategoryScores[$catName]
        $catScoreStr = if ($catInfo) { "$(& $t 'common.thScore'): $($catInfo.Score)/100 &middot; " } else { '' }
        $catLabel = & $esc (Get-GuerrillaLocalizedCategoryName -Name "$catName" -Language $Language)

        [void]$html.Append(@"
<details class="cat-detail"$openAttr>
  <summary>$catLabel<span class="sum-counts">$catScoreStr$(& $tr 'common.summaryCounts' $catFindings.Count $catPass $catFail $catWarn)</span></summary>
  <div class="detail-body">
    <table>
      <thead><tr><th>$(& $t 'common.thCheckId')</th><th>$(& $t 'common.thName')</th><th>$(& $t 'common.thSeverity')</th><th>$(& $t 'common.thStatus')</th><th>$(& $t 'common.thCurrentValue')</th><th>$(& $t 'common.thRecommendedValue')</th><th>$(& $t 'common.thRemediationSteps')</th></tr></thead>
      <tbody>
"@)
        foreach ($f in $catFindings) {
            $isAccepted  = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { & $t 'common.accepted' } else { & $esc $f.Status }
            $sevClass    = $f.Severity.ToLower()
            $rowText     = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())

            $remedSteps = if ($f.RemediationSteps) {
                "<div class=`"remediation-cell`">$(& $esc $f.RemediationSteps)</div>"
            } else { '' }

            [void]$html.Append(@"
        <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
          <td><code>$(& $esc $f.CheckId)</code></td>
          <td>$(& $esc $f.CheckName)</td>
          <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
          <td><span class="badge badge-status-$statusClass">$statusLabel</span></td>
          <td>$(& $esc $f.CurrentValue)</td>
          <td>$(& $esc $f.RecommendedValue)</td>
          <td>$remedSteps</td>
        </tr>
"@)

            # --- Extra row: affected accounts + why-unsafe article + admin console deep-link ---
            $affectedHtml = & $renderAffected $f.Details
            $linkParts = [System.Collections.Generic.List[string]]::new()
            if ($f.Status -in @('FAIL', 'WARN', 'ERROR')) {
                if ($f.ReferenceUrl) {
                    $whyTitle = if ($f.ReferenceTitle) { & $esc $f.ReferenceTitle } else { & $tr 'gws.whyUnsafeDefault' }
                    $linkParts.Add("<span class=`"why`"><a href=`"$(& $esc $f.ReferenceUrl)`" target=`"_blank`" rel=`"noopener`">$(& $tr 'gws.whyUnsafeArticle' $whyTitle)</a></span>")
                }
                if ($f.RemediationUrl) {
                    $linkParts.Add("<a class=`"admin-link`" href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`" rel=`"noopener`">$(& $t 'gws.fixInConsole')</a>")
                }
            }
            $linksHtml = if ($linkParts.Count -gt 0) { "<div class=`"extra-links`">$($linkParts -join '')</div>" } else { '' }
            if ($affectedHtml -or $linksHtml) {
                [void]$html.Append("<tr class=`"gg-row finding-extra`" data-status=`"$(& $esc $f.Status)`" data-sev=`"$(& $esc $f.Severity)`" data-text=`"$rowText`"><td colspan=`"7`"><div class=`"extra-wrap`">$affectedHtml$linksHtml</div></td></tr>")
            }
        }
        [void]$html.Append('</tbody></table></div></details>')
    }

    # ═══ COMPLIANCE CROSS-REFERENCE ═══
    $complianceFindings = @($failFindings | Where-Object {
        ($_.Compliance.NistSp80053 -and $_.Compliance.NistSp80053.Count -gt 0) -or
        ($_.Compliance.MitreAttack -and $_.Compliance.MitreAttack.Count -gt 0) -or
        ($_.Compliance.CisBenchmark -and $_.Compliance.CisBenchmark.Count -gt 0)
    } | Sort-Object {
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }, CheckId)

    if ($complianceFindings.Count -gt 0) {
        [void]$html.Append(@"
<h2>$(& $t 'common.complianceCrossReference')</h2>
<div class="table-wrap">
<table class="compliance-table">
  <thead><tr><th>$(& $t 'common.thCheckId')</th><th>$(& $t 'common.thCheckName')</th><th>$(& $t 'common.thSeverity')</th><th>$(& $t 'common.thNist')</th><th>$(& $t 'common.thMitre')</th><th>$(& $t 'common.thCisBenchmark')</th></tr></thead>
  <tbody>
"@)
        foreach ($f in $complianceFindings) {
            $sevClass = $f.Severity.ToLower()

            $nistCodes = if ($f.Compliance.NistSp80053 -and $f.Compliance.NistSp80053.Count -gt 0) {
                ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '' }

            $mitreCodes = if ($f.Compliance.MitreAttack -and $f.Compliance.MitreAttack.Count -gt 0) {
                ($f.Compliance.MitreAttack | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '' }

            $cisCodes = if ($f.Compliance.CisBenchmark -and $f.Compliance.CisBenchmark.Count -gt 0) {
                ($f.Compliance.CisBenchmark | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '' }

            [void]$html.Append(@"
    <tr>
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td>$(& $esc $f.CheckName)</td>
      <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
      <td>$nistCodes</td>
      <td>$mitreCodes</td>
      <td>$cisCodes</td>
    </tr>
"@)
        }
        [void]$html.Append('</tbody></table></div>')
    }

    # ═══ FOOTER + SHELL END ═══
    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote (& $tr 'gws.footer') `
        -TimestampText $timestampStr))

    [System.IO.File]::WriteAllText($FilePath, $html.ToString(), [System.Text.Encoding]::UTF8)
}
