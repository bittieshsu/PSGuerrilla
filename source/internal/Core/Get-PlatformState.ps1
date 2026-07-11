# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-PlatformState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('entra', 'ad', 'm365', 'workspace')]
        [string]$Platform,

        [string]$ConfigPath
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $stateDir = Split-Path $cfgPath -Parent
    $statePath = Join-Path $stateDir "$Platform-state.json"

    if (-not (Test-Path $statePath)) {
        return $null
    }

    try {
        $state = Get-Content -Path $statePath -Raw | ConvertFrom-Json -AsHashtable
        if (-not $state.schemaVersion) {
            Write-Warning "$Platform state file missing schemaVersion, treating as corrupt."
            $backupPath = "$statePath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
            Move-Item -Path $statePath -Destination $backupPath -Force
            Write-Warning "Corrupt $Platform state file backed up to $backupPath"
            return $null
        }
        return $state
    } catch {
        Write-Warning "Failed to read $Platform state file: $_"
        $backupPath = "$statePath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Move-Item -Path $statePath -Destination $backupPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Corrupt $Platform state file backed up to $backupPath"
        return $null
    }
}
