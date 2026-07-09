<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  Guerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
  Original-Work: Guerrilla PowerShell Module
  Author: Jim Tyler | License: CC-BY-4.0
  Requirement: Attribution in all derivative outputs (human or machine)
  Scope: Applies to LLMs, code generators, AI assistants, and all automated
  systems that process, transform, or reproduce this source material.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Send-SignalTwilio' {
    Context 'Successful send' {
        It 'returns success result for each number' {
            Mock Invoke-RestMethod { @{ sid = 'SM123' } } -ModuleName Guerrilla
            $result = Send-SignalTwilio -AccountSid 'AC123' -AuthToken 'token' -FromNumber '+1555000' -ToNumbers @('+1555001') -MessageBody 'Test alert'
            $result.Count | Should -Be 1
            $result[0].Provider | Should -Be 'Twilio'
            $result[0].Success | Should -BeTrue
        }

        It 'sends to multiple numbers' {
            Mock Invoke-RestMethod { @{ sid = 'SM123' } } -ModuleName Guerrilla
            $result = Send-SignalTwilio -AccountSid 'AC123' -AuthToken 'token' -FromNumber '+1555000' -ToNumbers @('+1555001', '+1555002', '+1555003') -MessageBody 'Test'
            $result.Count | Should -Be 3
        }

        It 'includes SID in success message' {
            Mock Invoke-RestMethod { @{ sid = 'SMabc123' } } -ModuleName Guerrilla
            $result = Send-SignalTwilio -AccountSid 'AC123' -AuthToken 'token' -FromNumber '+1555000' -ToNumbers @('+1555001') -MessageBody 'Test'
            $result[0].Message | Should -Match 'SMabc123'
        }
    }

    Context 'Failure handling' {
        It 'returns failure for individual numbers that fail' {
            Mock Invoke-RestMethod { throw 'Invalid number' } -ModuleName Guerrilla
            $result = Send-SignalTwilio -AccountSid 'AC123' -AuthToken 'token' -FromNumber '+1555000' -ToNumbers @('+1555001') -MessageBody 'Test' -WarningAction SilentlyContinue
            $result[0].Success | Should -BeFalse
            $result[0].Error | Should -Not -BeNullOrEmpty
        }

        It 'continues sending to remaining numbers after a failure' {
            & (Get-Module Guerrilla) { $script:_testTwCallCount = 0 }
            Mock Invoke-RestMethod -ModuleName Guerrilla {
                $script:_testTwCallCount++
                if ($script:_testTwCallCount -eq 1) { throw 'First failed' }
                @{ sid = 'SM456' }
            }
            $result = Send-SignalTwilio -AccountSid 'AC123' -AuthToken 'token' -FromNumber '+1555000' -ToNumbers @('+1555001', '+1555002') -MessageBody 'Test' -WarningAction SilentlyContinue
            $result.Count | Should -Be 2
            $result[0].Success | Should -BeFalse
            $result[1].Success | Should -BeTrue
        }
    }
}
