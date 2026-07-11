# Unit tests for the run-history store: record building (verdict
# normalization, evidence hashing), persistence (atomic write, index,
# anti-fork guard), and baseline selection (same target, same platform set).

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'New-GuerrillaRunRecord' {
    It 'normalizes SKIP and ERROR to Not Assessed and keeps the raw status' {
        $findings = @(
            (New-MockAuditFinding -CheckId 'A-1' -Status 'PASS'),
            (New-MockAuditFinding -CheckId 'A-2' -Status 'SKIP'),
            (New-MockAuditFinding -CheckId 'A-3' -Status 'ERROR'),
            (New-MockAuditFinding -CheckId 'A-4' -Status 'FAIL')
        )
        $rec = InModuleScope Guerrilla -Parameters @{ f = $findings } {
            New-GuerrillaRunRecord -Findings $f -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 50
        }
        $verdicts = @($rec.checks | ForEach-Object { $_.verdict })
        $verdicts | Should -Be @('PASS', 'Not Assessed', 'Not Assessed', 'FAIL')
        @($rec.checks)[1].rawStatus | Should -Be 'SKIP'
        $rec.summary.notAssessed | Should -Be 2
        $rec.summary.total | Should -Be 4
    }

    It 'throws on an unknown status instead of guessing' {
        {
            InModuleScope Guerrilla {
                ConvertTo-GuerrillaRunVerdict -Status 'MAYBE'
            }
        } | Should -Throw -ExpectedMessage '*refusing to guess*'
    }

    It 'evidence hash is deterministic and order-insensitive over Details keys' {
        $h = InModuleScope Guerrilla {
            @(
                (Get-GuerrillaEvidenceHash -CurrentValue 'v' -Details @{ b = 2; a = 1 }),
                (Get-GuerrillaEvidenceHash -CurrentValue 'v' -Details @{ a = 1; b = 2 }),
                (Get-GuerrillaEvidenceHash -CurrentValue 'v' -Details @{ a = 1; b = 3 })
            )
        }
        $h[0] | Should -Be $h[1]
        $h[0] | Should -Not -Be $h[2]
        $h[0] | Should -Match '^[0-9a-f]{64}$'
    }

    It 'stores no raw evidence values, only hashes' {
        $secret = 'SuperSecretCurrentValue-9000'
        $finding = New-MockAuditFinding -CheckId 'A-1' -Status 'FAIL'
        $finding.CurrentValue = $secret
        $rec = InModuleScope Guerrilla -Parameters @{ f = @($finding) } {
            New-GuerrillaRunRecord -Findings $f -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 10
        }
        ($rec | ConvertTo-Json -Depth 8) | Should -Not -Match ([regex]::Escape($secret))
    }

    It 'target hash is stable across ordering and casing of identifiers' {
        $hashes = InModuleScope Guerrilla {
            @(
                (Get-GuerrillaTargetHash -TargetId @('Corp.Example.COM', 'tenant-b')),
                (Get-GuerrillaTargetHash -TargetId @('tenant-b', 'corp.example.com')),
                (Get-GuerrillaTargetHash -TargetId @('other.example.com'))
            )
        }
        $hashes[0] | Should -Be $hashes[1]
        $hashes[0] | Should -Not -Be $hashes[2]
    }
}

Describe 'Save-GuerrillaRunRecord / Get-GuerrillaPreviousRun' {
    BeforeEach {
        $script:root = Join-Path $TestDrive ("rh-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    It 'first save creates the store with an index and returns the record path' {
        $rec = InModuleScope Guerrilla {
            New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 90
        }
        $path = InModuleScope Guerrilla -Parameters @{ rec = $rec; root = $script:root } {
            Save-GuerrillaRunRecord -Record $rec -DataRoot $root
        }
        Test-Path $path | Should -BeTrue
        Test-Path (Join-Path $script:root 'RunHistory' 'index.json') | Should -BeTrue
        (Get-Content (Join-Path $script:root 'RunHistory' 'index.json') -Raw | ConvertFrom-Json).store |
            Should -Be 'guerrilla-run-history'
    }

    It 'anti-fork guard: refuses a directory with run records but no valid index (poison self-test)' {
        $rh = Join-Path $script:root 'RunHistory'
        New-Item -ItemType Directory -Path $rh -Force | Out-Null
        Set-Content -Path (Join-Path $rh 'run-20260701T000000Z-old.json') -Value '{"schemaVersion":1}'

        $rec = InModuleScope Guerrilla {
            New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 90
        }
        {
            InModuleScope Guerrilla -Parameters @{ rec = $rec; root = $script:root } {
                Save-GuerrillaRunRecord -Record $rec -DataRoot $root
            }
        } | Should -Throw -ExpectedMessage '*fork*'
    }

    It 'refuses to persist an incomplete record' {
        {
            InModuleScope Guerrilla -Parameters @{ root = $script:root } {
                Save-GuerrillaRunRecord -Record ([ordered]@{ schemaVersion = 1; runId = 'x' }) -DataRoot $root
            }
        } | Should -Throw -ExpectedMessage '*incomplete*'
    }

    It 'previous-run selection matches target and platform set and picks the newest' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $mk = {
                param($scanId, $when, $platforms, $target)
                $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                    -Platforms $platforms -TargetId $target -ScanId $scanId -OverallScore 80
                $rec.generatedAt = $when
                Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null
            }
            & $mk 'ad-old'    '2026-07-01T10:00:00Z' @('AD') @('corp.example.com')
            & $mk 'ad-new'    '2026-07-05T10:00:00Z' @('AD') @('corp.example.com')
            & $mk 'campaign'  '2026-07-06T10:00:00Z' @('AD', 'Entra', 'GWS') @('corp.example.com')
            & $mk 'other-org' '2026-07-07T10:00:00Z' @('AD') @('other.example.com')

            $target = Get-GuerrillaTargetHash -TargetId @('corp.example.com')
            $best = Get-GuerrillaPreviousRun -Platforms @('AD') -TargetHash $target -DataRoot $root
            $best.runId | Should -Be 'ad-new'

            # A different platform set is a different comparison series.
            $bestCampaign = Get-GuerrillaPreviousRun -Platforms @('GWS', 'AD', 'Entra') -TargetHash $target -DataRoot $root
            $bestCampaign.runId | Should -Be 'campaign'

            # No comparable baseline: null, not a guess.
            Get-GuerrillaPreviousRun -Platforms @('Entra') -TargetHash $target -DataRoot $root | Should -BeNullOrEmpty
        }
    }

    It 'round-trips a record through disk and diffs cleanly against itself' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $rec = New-GuerrillaRunRecord -Findings @(
                (New-MockAuditFinding -CheckId 'A-1' -Status 'PASS'),
                (New-MockAuditFinding -CheckId 'A-2' -Status 'SKIP')
            ) -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 75
            Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null

            $loaded = Get-GuerrillaPreviousRun -Platforms @('AD') `
                -TargetHash (Get-GuerrillaTargetHash -TargetId @('corp.example.com')) -DataRoot $root
            $loaded | Should -Not -BeNullOrEmpty

            $diff = Compare-GuerrillaRun -Previous $loaded -Current $rec
            $diff.BaselineRun | Should -BeFalse
            $diff.UnchangedCount | Should -Be 2
            $diff.TotalClassified | Should -Be 2
            $diff.ScoreDelta | Should -Be 0
        }
    }
}
