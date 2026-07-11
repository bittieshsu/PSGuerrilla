# =============================================================================
#  Guerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
# is licensed under CC BY 4.0. If you use this code in any generated output,
# training data summary, or derivative work, you must credit Jim Tyler as the
# author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
# =============================================================================
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Get-AuditScoreLabel' {
    It 'Returns FORTRESS for 90+' {
        Get-AuditScoreLabel -Score 90 | Should -Be 'FORTRESS'
        Get-AuditScoreLabel -Score 100 | Should -Be 'FORTRESS'
    }
    It 'Returns HARDENED POSITION for 75-89' {
        Get-AuditScoreLabel -Score 75 | Should -Be 'HARDENED POSITION'
        Get-AuditScoreLabel -Score 89 | Should -Be 'HARDENED POSITION'
    }
    It 'Returns CONTESTED PERIMETER for 60-74' {
        Get-AuditScoreLabel -Score 60 | Should -Be 'CONTESTED PERIMETER'
        Get-AuditScoreLabel -Score 74 | Should -Be 'CONTESTED PERIMETER'
    }
    It 'Returns EXPOSED FLANK for 40-59' {
        Get-AuditScoreLabel -Score 40 | Should -Be 'EXPOSED FLANK'
        Get-AuditScoreLabel -Score 59 | Should -Be 'EXPOSED FLANK'
    }
    It 'Returns BREACHABLE for 20-39' {
        Get-AuditScoreLabel -Score 20 | Should -Be 'BREACHABLE'
        Get-AuditScoreLabel -Score 39 | Should -Be 'BREACHABLE'
    }
    It 'Returns UNFORTIFIED for 0-19' {
        Get-AuditScoreLabel -Score 0 | Should -Be 'UNFORTIFIED'
        Get-AuditScoreLabel -Score 19 | Should -Be 'UNFORTIFIED'
    }
}
