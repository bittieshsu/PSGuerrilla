# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-GuerrillaDeprecation {
    <#
    .SYNOPSIS
        Emits a deprecation warning for a renamed command, once per session per name.
    #>
    param(
        [Parameter(Mandatory)][string]$Old,
        [Parameter(Mandatory)][string]$New
    )
    if (-not $script:GuerrillaDeprecationWarned) { $script:GuerrillaDeprecationWarned = @{} }
    if (-not $script:GuerrillaDeprecationWarned[$Old]) {
        $script:GuerrillaDeprecationWarned[$Old] = $true
        Write-Warning "$Old is deprecated and will be removed in a future major version. Use $New instead."
    }
}
