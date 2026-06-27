#requires -version 7.0
# One-off inventory helper: lists Critical checks, their expected function,
# whether that function exists, and whether a fixture already covers them.
param([string]$Severity='high')
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..' '..')

$crit = [System.Collections.Generic.List[object]]::new()
foreach ($f in Get-ChildItem 'Data/AuditChecks' -Filter *.json) {
    $j = Get-Content $f.FullName -Raw | ConvertFrom-Json -AsHashtable
    foreach ($c in @($j.checks)) {
        if ("$($c.severity)".ToLower() -eq $Severity) {
            $crit.Add([pscustomobject]@{ Id = $c.id; Name = $c.name; File = $f.Name })
        }
    }
}

function Get-Prefix($id) {
    if     ($id -match '^ADMIN')             { 'Test-Fortification' }   # Google Workspace admin mgmt
    elseif ($id -match '^AZIAM')             { 'Test-Infiltration' }    # Azure IAM
    elseif ($id -match '^EIDSCA')            { 'EIDSCA-RESOLVER' }      # data-driven; no per-check fn (deferred)
    elseif ($id -match '^AD')                { 'Test-Recon' }
    elseif ($id -match '^(EID|M365|INTUNE)') { 'Test-Infiltration' }
    else                                     { 'Test-Fortification' }
}

$haveFix = Get-ChildItem 'Tests/Fixtures' -Recurse -Filter *.json |
    ForEach-Object { ($_.BaseName -split '\.')[0] } | Sort-Object -Unique

$srcJoined = (Get-ChildItem 'Private' -Recurse -Filter *.ps1 | Get-Content -Raw) -join "`n"

$rows = foreach ($c in $crit) {
    $fn = "$(Get-Prefix $c.Id)$($c.Id -replace '-', '')"
    [pscustomobject]@{
        Id         = $c.Id
        Func       = $fn
        FuncExists = [regex]::IsMatch($srcJoined, "function\s+$([regex]::Escape($fn))\b", 'IgnoreCase')
        Covered    = ($haveFix -contains $c.Id)
        File       = $c.File
    }
}

$missing = @($rows | Where-Object { -not $_.FuncExists })
$covered = @($rows | Where-Object Covered)
$todo    = @($rows | Where-Object { $_.FuncExists -and -not $_.Covered })

Write-Host "Critical total: $($rows.Count) | covered: $($covered.Count) | function-missing: $($missing.Count) | remaining-to-do: $($todo.Count)"
Write-Host "`n--- FUNCTION MISSING (cannot fixture as-is) ---"
$missing | Sort-Object Id | Format-Table Id, Func, File -AutoSize | Out-String | Write-Host
Write-Host "--- REMAINING TO DO, grouped by file ---"
$todo | Group-Object File | Sort-Object Name | ForEach-Object {
    Write-Host ("{0} ({1}): {2}" -f $_.Name, $_.Count, (($_.Group.Id) -join ', '))
}
