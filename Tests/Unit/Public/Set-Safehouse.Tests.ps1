# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# ═══════════════════════════════════════════════════════════════════════════════
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Set-Safehouse' {
    Context 'Creating new config' {
        It 'creates config file when it does not exist' {
            $cfgPath = Join-Path $TestDrive 'new-cfg/config.json'
            $result = Set-Safehouse -OutputDirectory (Join-Path $TestDrive 'reports') -ConfigPath $cfgPath
            Test-Path $cfgPath | Should -BeTrue
            $result.Status | Should -Be 'Saved'
        }

        It 'creates default config structure' {
            $cfgPath = Join-Path $TestDrive 'default-cfg/config.json'
            Set-Safehouse -MinimumAlertLevel HIGH -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.output | Should -Not -BeNullOrEmpty
            $config.alerting | Should -Not -BeNullOrEmpty
            $config.detection | Should -Not -BeNullOrEmpty
            $config.scheduling | Should -Not -BeNullOrEmpty
        }

        It 'sets Guerrilla defaults in new config' {
            $cfgPath = Join-Path $TestDrive 'guerrilla-defaults/config.json'
            Set-Safehouse -MinimumAlertLevel HIGH -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.output.directory | Should -Match 'Guerrilla'
            $config.scheduling.taskName | Should -Be 'Guerrilla-Patrol'
            $config.detection.businessHoursStart | Should -Be 7
        }

        It 'respects -WhatIf and does not write the config file' {
            $cfgPath = Join-Path $TestDrive 'whatif-cfg/config.json'
            Set-Safehouse -MinimumAlertLevel HIGH -ConfigPath $cfgPath -WhatIf
            Test-Path $cfgPath | Should -BeFalse
        }
    }

    Context 'Updating existing config' {
        It 'merges parameters into existing config' {
            $cfgPath = Join-Path $TestDrive 'merge-cfg/config.json'
            Set-Safehouse -OutputDirectory 'C:\Custom\Reports' -ConfigPath $cfgPath
            Set-Safehouse -MinimumAlertLevel CRITICAL -ConfigPath $cfgPath

            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.output.directory | Should -Be 'C:\Custom\Reports'
            $config.alerting.minimumThreatLevel | Should -Be 'CRITICAL'
        }

        It 'updates alerting toggles' {
            $cfgPath = Join-Path $TestDrive 'alert-toggle/config.json'
            Set-Safehouse -EnableAlerting $false -EnableSuppression $true -SuppressionWindowHours 12 -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.alerting.enabled | Should -BeFalse
            $config.alerting.suppression.enabled | Should -BeTrue
            $config.alerting.suppression.windowHours | Should -Be 12
        }

        It 'updates detection settings' {
            $cfgPath = Join-Path $TestDrive 'detect-cfg/config.json'
            Set-Safehouse -KnownCompromisedUsers @('user1@t.com', 'user2@t.com') -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.detection.knownCompromisedUsers | Should -Contain 'user1@t.com'
            $config.detection.knownCompromisedUsers | Should -Contain 'user2@t.com'
        }
    }

    Context 'Raw parameter' {
        It 'replaces entire config with -Raw' {
            $cfgPath = Join-Path $TestDrive 'raw-cfg/config.json'
            $rawConfig = @{ custom = @{ value = 'test' } }
            Set-Safehouse -Raw $rawConfig -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.custom.value | Should -Be 'test'
        }
    }
}
