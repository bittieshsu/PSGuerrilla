#requires -version 7.0
<#
    Medium-tier fixtures, Round 5 (addendum): Intune (5 checks).
    INTUNE-005/012/013/019/022. Synthetic data only.
    Re-run: pwsh Tests/Fixtures/_generate-fixtures-medium-5.ps1

    INTUNE-012/013 no-FAIL (PASS/WARN). INTUNE-019 always-PASS. INTUNE-022 always-SKIP.
#>
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function New-Fixture {
    param([string]$Family,[string]$CheckId,[string]$Platform,[string]$Scenario,[string]$ExpectedStatus,[string]$Description,[hashtable]$AuditData)
    $obj=[ordered]@{ checkId=$CheckId; platform=$Platform; scenario=$Scenario; expectedStatus=$ExpectedStatus; description=$Description; auditData=$AuditData }
    $obj | ConvertTo-Json -Depth 14 | Set-Content -Path (Join-Path $root $Family "$CheckId.$Scenario.json") -Encoding utf8
    Write-Host "  $Family/$CheckId.$Scenario -> $ExpectedStatus"
}
$I='Entra'
$skInt=@{ Errors=@{ Intune='Graph 429' }; Intune=@{ Errors=@{} } }

New-Fixture Entra INTUNE-005 $I clean PASS 'All configuration profiles are assigned' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(@{ id='c1'; displayName='P1'; '@odata.type'='#microsoft.graph.deviceConfiguration'; assignments=@(@{}) }) } }
New-Fixture Entra INTUNE-005 $I known-bad FAIL 'Many configuration profiles are unassigned (>3)' @{ Errors=@{}; Intune=@{ Errors=@{}; DeviceConfigurations=@(
    @{ id='c1'; displayName='P1'; '@odata.type'='#microsoft.graph.deviceConfiguration'; assignments=@() },
    @{ id='c2'; displayName='P2'; '@odata.type'='#microsoft.graph.deviceConfiguration'; assignments=@() },
    @{ id='c3'; displayName='P3'; '@odata.type'='#microsoft.graph.deviceConfiguration'; assignments=@() },
    @{ id='c4'; displayName='P4'; '@odata.type'='#microsoft.graph.deviceConfiguration'; assignments=@() }) } }
New-Fixture Entra INTUNE-005 $I throttled SKIP 'Intune device configurations not assessed' $skInt
New-Fixture Entra INTUNE-012 $I clean PASS 'App protection policy has conditional launch settings' @{ Errors=@{}; Intune=@{ Errors=@{}; AppProtectionPolicies=@(@{ id='p1'; displayName='P1'; '@odata.type'='#microsoft.graph.managedAppProtection'; minimumRequiredOsVersion='11.0' }) } }
New-Fixture Entra INTUNE-012 $I known-bad WARN 'App protection policies lack conditional launch settings' @{ Errors=@{}; Intune=@{ Errors=@{}; AppProtectionPolicies=@(@{ id='p1'; displayName='P1'; '@odata.type'='#microsoft.graph.windowsInformationProtectionPolicy'; minimumRequiredOsVersion=$null; minimumRequiredAppVersion=$null; maximumRequiredOsVersion=$null }) } }
New-Fixture Entra INTUNE-012 $I throttled SKIP 'Intune app protection policies not assessed' $skInt
New-Fixture Entra INTUNE-013 $I clean PASS 'Enrollment configurations present' @{ Errors=@{}; Intune=@{ Errors=@{}; EnrollmentConfigurations=@(@{ id='e1'; displayName='E1'; '@odata.type'='#microsoft.graph.deviceEnrollmentPlatformRestrictions'; priority=0 }) } }
New-Fixture Entra INTUNE-013 $I known-bad WARN 'No enrollment configurations found' @{ Errors=@{}; Intune=@{ Errors=@{}; EnrollmentConfigurations=@() } }
New-Fixture Entra INTUNE-013 $I throttled SKIP 'Intune enrollment configurations not assessed' $skInt
New-Fixture Entra INTUNE-019 $I clean PASS 'Win32 app inventory compiled (informational)' @{ Errors=@{}; Intune=@{ Errors=@{}; MobileApps=@(@{ id='a1'; displayName='A1'; '@odata.type'='#microsoft.graph.win32LobApp'; publisher='MyOrg'; fileName='a1.exe' }) } }
New-Fixture Entra INTUNE-019 $I throttled SKIP 'Intune mobile apps not assessed' $skInt
New-Fixture Entra INTUNE-022 $I not-implemented SKIP 'OneDrive sync config needs admin/registry data not in Graph' @{ Errors=@{}; Intune=@{ Errors=@{} } }

Write-Host "`nDone (medium round 5 addendum)."
