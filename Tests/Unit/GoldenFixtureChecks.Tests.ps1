# Golden-fixture tests for the highest-severity security checks.
#
# Each fixture under Tests/Fixtures/<Family>/ is a synthetic, hand-crafted
# collector payload ($AuditData) plus the verdict it should produce. No real
# tenant data is used. The fixture is pumped through the REAL check function
# (Test-Recon* / Test-Infiltration* / Test-Fortification*) and we assert the
# returned Status. This encodes the invariant:
#
#     clean data => PASS        known-bad data => FAIL/WARN
#     throttle/collection error or missing data => SKIP (never PASS)
#
# The SKIP cases are the regression guard for the "absence of evidence scored
# as compliance" failure mode. Fixture authoring/execution helpers live in
# Tests/Helpers/TestHelpers.psm1 and are shared with the Supabase publisher.

Import-Module (Join-Path $PSScriptRoot '..' 'Helpers' 'TestHelpers.psm1') -Force

BeforeDiscovery {
    $FixtureCases = Get-GuerrillaFixtureCases
}

Describe 'Golden-fixture check verdicts' {

    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..' 'Helpers' 'TestHelpers.psm1') -Force
        Import-Guerrilla
    }

    It '<Family>/<CheckId> [<Scenario>] => <ExpectedStatus>' -ForEach $FixtureCases {

        $Definition | Should -Not -BeNullOrEmpty -Because "check id $CheckId must exist in Data/AuditChecks"

        $result = Invoke-GuerrillaCheckFixture -AuditData $AuditData -Definition $Definition -FunctionName $FunctionName

        $result        | Should -Not -BeNullOrEmpty -Because 'a check must always return a finding'
        $result.Status | Should -Be $ExpectedStatus -Because $Description
    }
}
