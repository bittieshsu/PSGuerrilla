# ─────────────────────────────────────────────────────────────────────────────
# Guerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'New-GuerrillaSecretFile' {
    Context 'File creation and content' {
        It 'Writes the content verbatim and returns the path' {
            $secret = '{"private_key":"TOP-SECRET"}'
            $path = InModuleScope Guerrilla { New-GuerrillaSecretFile -Content $c } -Parameters @{ c = $secret }
            try {
                Test-Path -LiteralPath $path | Should -BeTrue
                (Get-Content -Raw -LiteralPath $path) | Should -BeExactly $secret
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Uses a high-entropy name, not a truncated GUID slice' {
            # The old staging code used an 8-hex-char GUID slice (32 bits). The random
            # component here should be longer than that, so collisions and prediction
            # are far less likely.
            $path = InModuleScope Guerrilla { New-GuerrillaSecretFile -Content 'x' }
            try {
                $leaf = Split-Path $path -Leaf
                $leaf | Should -Match '^guerrilla-sa-[a-z0-9]+\.json$'
                $random = ($leaf -replace '^guerrilla-sa-', '') -replace '\.json$', ''
                $random.Length | Should -BeGreaterThan 8
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Honors a custom prefix' {
            $path = InModuleScope Guerrilla { New-GuerrillaSecretFile -Content 'x' -Prefix 'guerrilla-test-sa' }
            try {
                (Split-Path $path -Leaf) | Should -Match '^guerrilla-test-sa-'
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Permissions are locked to the current user' {
        It 'Creates the file owner-only (no group/other access)' -Skip:($IsWindows) {
            $path = InModuleScope Guerrilla { New-GuerrillaSecretFile -Content 'secret' }
            try {
                # -rw------- : owner read/write, nothing for group or other.
                (Get-Item -LiteralPath $path).UnixMode | Should -Be '-rw-------'
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Protects the DACL from inheritance on Windows' -Skip:(-not $IsWindows) {
            $path = InModuleScope Guerrilla { New-GuerrillaSecretFile -Content 'secret' }
            try {
                $acl = (Get-Item -LiteralPath $path).GetAccessControl()
                $acl.AreAccessRulesProtected | Should -BeTrue
                # Only the current user should hold an access rule.
                $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $identities = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) })
                $identities | Should -Not -BeNullOrEmpty
                ($identities | Where-Object { $_ -ne $me }) | Should -BeNullOrEmpty
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Input validation' {
        It 'Rejects empty content' {
            { InModuleScope Guerrilla { New-GuerrillaSecretFile -Content '' } } | Should -Throw
        }
    }
}
