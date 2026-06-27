#requires -version 7.0
<#
.SYNOPSIS
    Publish golden-fixture test results to Supabase for historical tracking.

.DESCRIPTION
    Inserts one guerrilla_test_runs summary row and one guerrilla_test_results
    row per check/scenario via the Supabase PostgREST REST API. Credentials come
    from -ProjectUrl/-ServiceKey or the SUPABASE_URL / SUPABASE_KEY environment
    variables. Run Tests/Supabase/schema.sql once before first use.

    No secrets are written to disk or logged.

.EXAMPLE
    $r = & Tests/Supabase/Run-And-Publish.ps1   # produces $Summary + $Results
    ./Tests/Supabase/Publish-GuerrillaTestResults.ps1 -Summary $r.Summary -Results $r.Results
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][hashtable]$Summary,        # run-level metadata + totals
    [Parameter(Mandatory)][object[]]$Results,         # per-check result objects
    [string]$ProjectUrl = $env:SUPABASE_URL,
    [string]$ServiceKey = $env:SUPABASE_KEY,
    [string]$RunsTable = 'guerrilla_test_runs',
    [string]$ResultsTable = 'guerrilla_test_results'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ProjectUrl)) {
    throw 'Supabase project URL not provided. Pass -ProjectUrl or set $env:SUPABASE_URL (e.g. https://abcdxyz.supabase.co).'
}
if ([string]::IsNullOrWhiteSpace($ServiceKey)) {
    throw 'Supabase key not provided. Pass -ServiceKey or set $env:SUPABASE_KEY (service_role or an insert-capable key).'
}

$base = $ProjectUrl.TrimEnd('/')
$headers = @{
    apikey          = $ServiceKey
    Authorization   = "Bearer $ServiceKey"
    'Content-Type'  = 'application/json'
}
# Supabase rejects secret (service_role) keys when the request looks like it
# comes from a browser. PowerShell's default User-Agent starts with "Mozilla/…",
# which trips that guard, so send an explicit non-browser agent.
$userAgent = 'PSGuerrilla-TestPublisher/1.0'

# 1) Insert the run summary, asking PostgREST to return the generated id.
$runBody = ($Summary | ConvertTo-Json -Depth 6)
if (-not $PSCmdlet.ShouldProcess("$base/rest/v1/$RunsTable", 'insert test run')) { return }

$runResp = Invoke-RestMethod -Method Post -Uri "$base/rest/v1/$RunsTable" `
    -Headers ($headers + @{ Prefer = 'return=representation' }) -Body $runBody -UserAgent $userAgent
$runId = @($runResp)[0].id
if (-not $runId) { throw 'Supabase did not return a run id; check the table schema and key permissions.' }
Write-Host "Inserted run $runId"

# 2) Bulk-insert the per-check rows tagged with the run id.
$rows = $Results | ForEach-Object {
    [ordered]@{
        run_id          = $runId
        check_id        = $_.CheckId
        family          = $_.Family
        theater         = $_.Theater
        scenario        = $_.Scenario
        severity        = $_.Severity
        expected_status = $_.ExpectedStatus
        actual_status   = $_.ActualStatus
        passed          = [bool]$_.Passed
        fixture_file    = $_.FixtureFile
        description     = $_.Description
    }
}
$resultsBody = ConvertTo-Json -InputObject @($rows) -Depth 6
Invoke-RestMethod -Method Post -Uri "$base/rest/v1/$ResultsTable" `
    -Headers ($headers + @{ Prefer = 'return=minimal' }) -Body $resultsBody -UserAgent $userAgent | Out-Null

Write-Host "Published $($rows.Count) result rows to $ResultsTable."
[PSCustomObject]@{ RunId = $runId; RowCount = $rows.Count }
