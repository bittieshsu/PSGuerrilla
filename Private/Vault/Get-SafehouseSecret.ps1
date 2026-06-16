# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-SafehouseSecret {
    <#
    .SYNOPSIS
        Reads a secret from the safehouse vault, returning $null on any miss.
    .DESCRIPTION
        A graceful counterpart to Get-GuerrillaCredential. Where Get-GuerrillaCredential
        THROWS when a credential is missing (correct for the mission-config path, where a
        referenced key must exist), this returns $null when SecretManagement isn't
        installed, the vault doesn't exist, or the key isn't stored.

        It exists for "fall back to the safehouse" credential resolution: scan cmdlets
        call it for the default vault keys (GUERRILLA_GWS_SA, GUERRILLA_GRAPH_TENANT, …)
        as a last resort after parameters and config.json, where a miss is normal and
        should not be an error.
    .PARAMETER VaultKey
        The secret name to read (e.g. 'GUERRILLA_GWS_SA').
    .PARAMETER VaultName
        The SecretManagement vault. Default: PSGuerrilla.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultKey,

        [string]$VaultName = 'PSGuerrilla'
    )

    if (-not (Get-Command Get-SecretVault -ErrorAction SilentlyContinue)) { return $null }
    if (-not (Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue)) { return $null }

    try {
        Get-Secret -Name $VaultKey -Vault $VaultName -AsPlainText -ErrorAction Stop
    } catch {
        $null
    }
}
