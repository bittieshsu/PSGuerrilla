# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

function Get-GuerrillaRunHistoryRoot {
    <#
    .SYNOPSIS
        The per-user run-history directory.
    .DESCRIPTION
        Product principle: the run history is created per-user on first run,
        lives on the user's machine under the user's data root, and involves
        zero telemetry and zero network. It is the user's file.
    #>
    [CmdletBinding()]
    param([string]$DataRoot)
    if (-not $DataRoot) { $DataRoot = Get-GuerrillaDataRoot }
    Join-Path $DataRoot 'RunHistory'
}

function Save-GuerrillaRunRecord {
    <#
    .SYNOPSIS
        Persist a completed run's record to the per-user run history.
    .DESCRIPTION
        Called only at the end of a COMPLETED assessment: a crashed or partial
        run writes nothing, so it can never become a comparison baseline.

        Anti-fork guard (same principle as the dev-side ledger): a RunHistory
        directory that contains run records but no valid index.json is not
        ours to write into; refusing beats silently starting a second history
        next to an existing one. A genuinely empty or absent directory is
        initialized with an index.

        Writes are atomic (temp file + rename) so a crash mid-write cannot
        leave a truncated record that later parses as a baseline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [string]$DataRoot
    )

    foreach ($required in 'schemaVersion', 'generatedAt', 'runId', 'scope', 'checks') {
        if ($null -eq $Record.$required) {
            throw "Run record is missing '$required'; refusing to persist an incomplete record."
        }
    }

    $root = Get-GuerrillaRunHistoryRoot -DataRoot $DataRoot
    $indexPath = Join-Path $root 'index.json'

    if (Test-Path $root) {
        $existingRuns = @(Get-ChildItem -Path $root -Filter 'run-*.json' -File -ErrorAction SilentlyContinue)
        if ($existingRuns.Count -gt 0) {
            $indexOk = $false
            if (Test-Path $indexPath) {
                try {
                    $idx = Get-Content -Path $indexPath -Raw | ConvertFrom-Json
                    if ($idx.schemaVersion -eq 1 -and $idx.store -eq 'guerrilla-run-history') { $indexOk = $true }
                } catch { }
            }
            if (-not $indexOk) {
                throw ("RunHistory at '$root' contains run records but no valid index.json. " +
                    'Refusing to write: this directory is not a recognized Guerrilla run history, and ' +
                    'silently starting a second history next to an existing one would fork it. ' +
                    'Move or repair the directory before the next run.')
            }
        }
    } else {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }

    if (-not (Test-Path $indexPath)) {
        [ordered]@{
            schemaVersion = 1
            store         = 'guerrilla-run-history'
            createdAt     = [datetime]::UtcNow.ToString('o')
            principle     = 'Per-user local run history. Your file, your machine. No accounts, no telemetry, no network.'
        } | ConvertTo-Json | Set-Content -Path $indexPath -Encoding utf8
    }

    $stamp = ([datetime]$Record.generatedAt).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $idFragment = ("$($Record.runId)" -replace '[^A-Za-z0-9-]', '')
    if ($idFragment.Length -gt 12) { $idFragment = $idFragment.Substring(0, 12) }
    $finalPath = Join-Path $root "run-$stamp-$idFragment.json"

    $tmpPath = "$finalPath.tmp"
    $Record | ConvertTo-Json -Depth 8 | Set-Content -Path $tmpPath -Encoding utf8
    Move-Item -Path $tmpPath -Destination $finalPath -Force

    return $finalPath
}

function Get-GuerrillaPreviousRun {
    <#
    .SYNOPSIS
        The newest recorded run comparable to the one about to be recorded.
    .DESCRIPTION
        Comparable means: same schema, same target (privacy-preserving hash)
        and the same platform set. An AD-only run is never diffed against a
        full campaign; the checks that "vanished" would be scope, not drift.
        Returns $null when no comparable baseline exists (first run ever, or
        first run at this scope): the caller reports that plainly and
        fabricates nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Platforms,
        [Parameter(Mandatory)][string]$TargetHash,
        [string]$DataRoot
    )

    $root = Get-GuerrillaRunHistoryRoot -DataRoot $DataRoot
    if (-not (Test-Path $root)) { return $null }

    $wanted = @($Platforms | Sort-Object) -join ','
    $best = $null
    foreach ($file in (Get-ChildItem -Path $root -Filter 'run-*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $rec = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        } catch {
            Write-Verbose "RunHistory: skipping unreadable record $($file.Name): $_"
            continue
        }
        if ($rec.schemaVersion -ne 1) { continue }
        if ("$($rec.scope.targetHash)" -ne $TargetHash) { continue }
        if ((@($rec.scope.platforms | Sort-Object) -join ',') -ne $wanted) { continue }
        if ($null -eq $best -or ([datetime]$rec.generatedAt) -gt ([datetime]$best.generatedAt)) { $best = $rec }
    }
    return $best
}
