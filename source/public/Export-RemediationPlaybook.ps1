# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-RemediationPlaybook {
    <#
    .SYNOPSIS
        Generates a step-by-step remediation guide grouped by category and priority.
    .DESCRIPTION
        Produces an HTML playbook organized into phases (critical first, then high, medium, low).
        Each finding includes prerequisites, step-by-step remediation, validation steps,
        effort estimates, and cost tier information.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Remediation-Playbook.html
    .PARAMETER OrganizationName
        Organization name for the report header.
    .PARAMETER MaxCostTier
        Maximum cost tier to include. Default: Medium.
    .PARAMETER Style
        Report style: Auto (follow the OS), Light, or Dark. Legacy names accepted.
    .EXAMPLE
        Export-RemediationPlaybook -OrganizationName 'Springfield USD'
    .EXAMPLE
        Export-RemediationPlaybook -MaxCostTier Free -OutputPath ./free-fixes.html
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [ValidateSet('Free', 'Low', 'Medium', 'High', 'Enterprise')]
        [string]$MaxCostTier = 'Medium',

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [string]$Language = ''
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Remediation-Playbook.html' }

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

    # Load remediation costs
    $remPath = Join-Path $script:ModuleRoot 'Data/RemediationCosts.json'
    $remData = $null
    if (Test-Path $remPath) {
        $remData = Get-Content -Path $remPath -Raw | ConvertFrom-Json -AsHashtable
    }

    $tierOrder = @{ 'Free' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Enterprise' = 4 }
    $maxTierIndex = $tierOrder[$MaxCostTier] ?? 2

    if (-not $Language) { $Language = Resolve-GuerrillaReportLanguage -Configured '' }
    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw
    $Findings = Get-GuerrillaLocalizedFindings -Findings $Findings -Language $Language
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
    $html = [System.Text.StringBuilder]::new(65536)

    # Filter to actionable findings with cost lookup
    $actionable = @($Findings | Where-Object Status -in @('FAIL', 'WARN') | ForEach-Object {
        $checkId = $_.CheckId ?? $_.Id ?? ''
        $prefix = if ($checkId -match '^([A-Z0-9]+)-') { $Matches[1] } else { '' }
        $costInfo = $remData.overrides.$checkId ?? $remData.categoryDefaults.$prefix
        $tier = $costInfo.costTier ?? 'Medium'
        if ($tierOrder[$tier] -le $maxTierIndex) {
            $_ | Add-Member -NotePropertyName '_CostTier' -NotePropertyValue $tier -PassThru -Force |
                 Add-Member -NotePropertyName '_Effort' -NotePropertyValue ($costInfo.effort ?? 'Medium') -PassThru -Force |
                 Add-Member -NotePropertyName '_Notes' -NotePropertyValue ($costInfo.notes ?? '') -PassThru -Force
        }
    })

    # Group by severity phase
    $phases = @(
        @{ Name = (& $t 'playbook.phase1'); Severity = 'Critical' }
        @{ Name = (& $t 'playbook.phase2'); Severity = 'High' }
        @{ Name = (& $t 'playbook.phase3'); Severity = 'Medium' }
        @{ Name = (& $t 'playbook.phase4'); Severity = 'Low' }
    )

    $extraCss = @'
h2.pb-phase { background: var(--g-surface); border-left: 3px solid var(--g-border-strong); border-radius: var(--radius-sm); padding: 0.55rem 1rem; }
.pb-item { background: var(--g-surface); border-radius: var(--radius); padding: 1.1rem 1.3rem; margin: 0.8rem 0; }
.pb-head { display: flex; justify-content: space-between; align-items: baseline; gap: 0.8rem; flex-wrap: wrap; }
.pb-title { font-weight: 600; color: var(--g-heading); }
.pb-meta { display: flex; flex-wrap: wrap; gap: 1rem; color: var(--g-muted); font-size: 0.85rem; margin: 0.35rem 0 0.6rem; }
.pb-item p { margin: 0.4em 0; }
.pb-target, .pb-note { color: var(--g-muted); font-size: 0.92rem; }
.pb-note { font-style: italic; }
'@

    $subtitle = "$(& $esc $OrganizationName) &middot; $(& $tr 'playbook.subtitle' $actionable.Count $MaxCostTier) &middot; $timestamp UTC"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title (& $tr 'playbook.title') `
        -Subtitle $subtitle `
        -HtmlTitle "$(& $tr 'playbook.htmlTitle') - $OrganizationName - $timestamp UTC" `
        -TopbarMeta (& $tr 'playbook.topbar') `
        -Style $Style -Language $Language -ExtraCss $extraCss))

    $itemNum = 0
    foreach ($phase in $phases) {
        $phaseItems = @($actionable | Where-Object Severity -eq $phase.Severity |
            Sort-Object @{Expression={$tierOrder[$_._CostTier]}}, CheckId)
        if ($phaseItems.Count -eq 0) { continue }

        $phaseColor = Get-GuerrillaSeverityColorVar -Severity $phase.Severity
        $sevClass = $phase.Severity.ToLower()
        [void]$html.Append("<h2 class=`"pb-phase`" style=`"border-left-color:$phaseColor;color:$phaseColor;`">$(& $tr 'playbook.phaseItems' $phase.Name $phaseItems.Count)</h2>`n")

        foreach ($item in $phaseItems) {
            $itemNum++
            $checkId = $item.CheckId ?? $item.Id ?? ''
            $effortHours = switch ($item._Effort) { 'Minimal' { '~15min' } 'Low' { '~1h' } 'Medium' { '~4h' } 'High' { '~2d' } 'Major' { '~2w' } default { '~4h' } }

            [void]$html.Append(@"
<div class="pb-item">
<div class="pb-head">
<div class="pb-title">$itemNum. $(& $esc ($item.Name ?? $item.CheckName ?? $checkId))</div>
<span class="badge badge-sev-$sevClass">$(& $esc $item.Severity)</span>
</div>
<div class="pb-meta">
<span>$(& $t 'playbook.idLabel') <code>$(& $esc $checkId)</code></span>
<span>$(& $t 'playbook.costLabel') $($item._CostTier)</span>
<span>$(& $t 'playbook.effortLabel') $effortHours</span>
<span>$(& $t 'playbook.categoryLabel') $(& $esc (Get-GuerrillaLocalizedCategoryName -Name "$($item.Category ?? '')" -Language $Language))</span>
</div>
$(if ($item.Description) { "<p>$(& $esc $item.Description)</p>" })
$(if ($item.RemediationSteps) {
    "<p><strong>$(& $t 'playbook.stepsLabel')</strong> $(& $esc $item.RemediationSteps)</p>"
})
$(if ($item.RecommendedValue) { "<p class='pb-target'><strong>$(& $t 'playbook.targetLabel')</strong> $(& $esc $item.RecommendedValue)</p>" })
$(if ($item._Notes) { "<p class='pb-note'>$(& $t 'playbook.noteLabel') $(& $esc $item._Notes)</p>" })
$(if ($item.RemediationUrl) { "<p><a href='$(& $esc $item.RemediationUrl)'>$(& $esc $item.RemediationUrl)</a></p>" })
</div>
"@)
        }
    }

    [void]$html.Append(@"
<p style="color:var(--g-muted);font-size:0.9rem;font-style:italic;">$(& $t 'playbook.disclaimer')</p>
"@)

    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote (& $tr 'playbook.footer') `
        -TimestampText "$timestamp UTC"))

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.RemediationPlaybook'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Remediation playbook exported to $OutputPath"
        ItemCount  = $itemNum
    }
}
