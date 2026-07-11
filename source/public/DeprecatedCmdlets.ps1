# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Deprecated entry points kept for one deprecation cycle. The audits were renamed so
# platforms are named what they are: AD, Entra, GWS. Each wrapper forwards every
# argument to its replacement and warns once per session. Removed in the next major
# version (see CHANGELOG).

function Invoke-Reconnaissance {
    <#
    .SYNOPSIS
        DEPRECATED. Use Invoke-ADAudit.
    .DESCRIPTION
        Invoke-Reconnaissance was renamed to Invoke-ADAudit. This wrapper forwards all
        arguments to Invoke-ADAudit, warns once per session, and will be removed in the
        next major version.
    .EXAMPLE
        Invoke-ADAudit -Server dc01.contoso.com
    #>
    Write-GuerrillaDeprecation -Old 'Invoke-Reconnaissance' -New 'Invoke-ADAudit'
    Invoke-ADAudit @args
}

function Invoke-Infiltration {
    <#
    .SYNOPSIS
        DEPRECATED. Use Invoke-EntraAudit.
    .DESCRIPTION
        Invoke-Infiltration was renamed to Invoke-EntraAudit. This wrapper forwards all
        arguments to Invoke-EntraAudit, warns once per session, and will be removed in
        the next major version.
    .EXAMPLE
        Invoke-EntraAudit -TenantId $tenantId -ClientId $clientId -DeviceCode
    #>
    Write-GuerrillaDeprecation -Old 'Invoke-Infiltration' -New 'Invoke-EntraAudit'
    Invoke-EntraAudit @args
}

function Invoke-Fortification {
    <#
    .SYNOPSIS
        DEPRECATED. Use Invoke-GWSAudit.
    .DESCRIPTION
        Invoke-Fortification was renamed to Invoke-GWSAudit. This wrapper forwards all
        arguments to Invoke-GWSAudit, warns once per session, and will be removed in the
        next major version.
    .EXAMPLE
        Invoke-GWSAudit -ServiceAccountKeyPath key.json -AdminEmail admin@contoso.com
    #>
    Write-GuerrillaDeprecation -Old 'Invoke-Fortification' -New 'Invoke-GWSAudit'
    Invoke-GWSAudit @args
}
