# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# SPDX-License-Identifier: CC-BY-4.0
#
# ConvertFrom-RegistryPol parses bytes that live in SYSVOL, which means any
# principal able to write a GPO folder controls them. These tests exist mostly to
# pin the hostile-input behaviour: the parser must never throw, never allocate on
# a forged length, and must report truncation rather than silently returning a
# short list that reads like a clean policy.

BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..' '..')).Path
    . (Join-Path $root 'source' 'internal' 'AD' 'Core' 'ConvertFrom-RegistryPol.ps1')

    $script:U = [System.Text.Encoding]::Unicode
    function script:New-PolRecord([string]$Key, [string]$Value, [int]$Type, [byte[]]$Data) {
        $b = [System.Collections.Generic.List[byte]]::new()
        $b.AddRange($U.GetBytes('['));            $b.AddRange($U.GetBytes($Key + [char]0))
        $b.AddRange($U.GetBytes(';'));            $b.AddRange($U.GetBytes($Value + [char]0))
        $b.AddRange($U.GetBytes(';'));            $b.AddRange([BitConverter]::GetBytes([uint32]$Type))
        $b.AddRange($U.GetBytes(';'));            $b.AddRange([BitConverter]::GetBytes([uint32]$Data.Length))
        $b.AddRange($U.GetBytes(';'));            $b.AddRange($Data)
        $b.AddRange($U.GetBytes(']'))
        , $b.ToArray()
    }
    # Records is [object[]] so an empty list binds cleanly; each element is a byte[].
    function script:New-PolFile([object[]]$Records = @(), [uint32]$Signature = 0x67655250, [uint32]$Version = 1) {
        $b = [System.Collections.Generic.List[byte]]::new()
        $b.AddRange([BitConverter]::GetBytes([uint32]$Signature))
        $b.AddRange([BitConverter]::GetBytes([uint32]$Version))
        foreach ($r in $Records) { $b.AddRange([byte[]]$r) }
        , $b.ToArray()
    }
    # Concatenating byte[] with + promotes to object[]; flatten back explicitly.
    function script:Join-Bytes {
        $b = [System.Collections.Generic.List[byte]]::new()
        foreach ($chunk in $args) { $b.AddRange([byte[]]$chunk) }
        , $b.ToArray()
    }
}

Describe 'ConvertFrom-RegistryPol' {

    Context 'well-formed files' {
        It 'parses a REG_SZ and a REG_DWORD record' {
            $bytes = New-PolFile @(
                (New-PolRecord 'Software\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer' 1 ($U.GetBytes('http://wsus.contoso.com' + [char]0))),
                (New-PolRecord 'Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'UseWUServer' 4 ([BitConverter]::GetBytes([uint32]1)))
            )
            $r = ConvertFrom-RegistryPol -Bytes $bytes
            $r.Valid | Should -BeTrue
            $r.Truncated | Should -BeFalse
            $r.Version | Should -Be 1
            $r.Settings.Count | Should -Be 2
            $r.Settings[0].ValueData | Should -Be 'http://wsus.contoso.com'
            $r.Settings[0].ValueTypeName | Should -Be 'REG_SZ'
            $r.Settings[1].ValueData | Should -Be 1
            $r.Settings[1].ValueTypeName | Should -Be 'REG_DWORD'
        }

        It 'decodes every value type it claims to support' {
            $bytes = New-PolFile @(
                (New-PolRecord 'K' 'expand'   2  ($U.GetBytes('%SystemRoot%' + [char]0))),
                (New-PolRecord 'K' 'binary'   3  ([byte[]](1, 2, 3, 4))),
                (New-PolRecord 'K' 'dwordBE'  5  ([byte[]](0, 0, 1, 0))),
                (New-PolRecord 'K' 'qword'    11 ([BitConverter]::GetBytes([uint64]4294967296))),
                (New-PolRecord 'K' 'multi'    7  ($U.GetBytes("one`0two`0`0")))
            )
            $r = ConvertFrom-RegistryPol -Bytes $bytes
            $r.Settings.Count | Should -Be 5
            ($r.Settings | Where-Object ValueName -eq 'expand').ValueData  | Should -Be '%SystemRoot%'
            ($r.Settings | Where-Object ValueName -eq 'binary').ValueData  | Should -Be ([byte[]](1, 2, 3, 4))
            ($r.Settings | Where-Object ValueName -eq 'dwordBE').ValueData | Should -Be 256
            ($r.Settings | Where-Object ValueName -eq 'qword').ValueData   | Should -Be 4294967296
            ($r.Settings | Where-Object ValueName -eq 'multi').ValueData   | Should -Be @('one', 'two')
        }

        It 'accepts a header-only file as valid with no settings' {
            $r = ConvertFrom-RegistryPol -Bytes (New-PolFile)
            $r.Valid | Should -BeTrue
            $r.Truncated | Should -BeFalse
            $r.Settings.Count | Should -Be 0
        }

        It 'tolerates trailing null padding after the last record' {
            $bytes = Join-Bytes (New-PolFile @((New-PolRecord 'K' 'V' 4 ([BitConverter]::GetBytes([uint32]7))))) ([byte[]](0, 0, 0, 0))
            $r = ConvertFrom-RegistryPol -Bytes $bytes
            $r.Truncated | Should -BeFalse
            $r.Settings.Count | Should -Be 1
        }
    }

    Context 'rejects what is not a PReg file' {
        It 'rejects a bad signature without throwing' {
            $r = ConvertFrom-RegistryPol -Bytes (New-PolFile -Signature ([uint32]0x12345678))
            $r.Valid | Should -BeFalse
            $r.Reason | Should -Match 'signature'
        }
        It 'rejects a file shorter than the header' {
            $r = ConvertFrom-RegistryPol -Bytes ([byte[]](80, 82, 101))
            $r.Valid | Should -BeFalse
            $r.Reason | Should -Match 'header'
        }
        It 'returns a reason rather than throwing for a missing file' {
            $r = ConvertFrom-RegistryPol -Path (Join-Path ([System.IO.Path]::GetTempPath()) 'no-such-guerrilla.pol')
            $r.Valid | Should -BeFalse
            $r.Reason | Should -Not -BeNullOrEmpty
        }
    }

    Context 'hostile input' {
        It 'flags truncation and keeps the records it did parse' {
            $good = New-PolFile @((New-PolRecord 'K' 'Good' 4 ([BitConverter]::GetBytes([uint32]1))))
            $partial = New-PolRecord 'K' 'Bad' 4 ([BitConverter]::GetBytes([uint32]1))
            $bytes = Join-Bytes $good ([byte[]]$partial[0..10])   # record cut mid-field
            $r = ConvertFrom-RegistryPol -Bytes $bytes
            $r.Valid | Should -BeTrue
            $r.Truncated | Should -BeTrue
            $r.Settings.Count | Should -Be 1
            $r.Settings[0].ValueName | Should -Be 'Good'
        }

        It 'refuses a forged data length that overruns the buffer, without allocating it' {
            # Declare 2GB of data in a file that is a few dozen bytes long.
            $b = [System.Collections.Generic.List[byte]]::new()
            $b.AddRange([BitConverter]::GetBytes([uint32]0x67655250)); $b.AddRange([BitConverter]::GetBytes([uint32]1))
            $b.AddRange($U.GetBytes('[')); $b.AddRange($U.GetBytes('K' + [char]0))
            $b.AddRange($U.GetBytes(';')); $b.AddRange($U.GetBytes('V' + [char]0))
            $b.AddRange($U.GetBytes(';')); $b.AddRange([BitConverter]::GetBytes([uint32]3))
            $b.AddRange($U.GetBytes(';')); $b.AddRange([BitConverter]::GetBytes([uint32]2147483000))
            $b.AddRange($U.GetBytes(';')); $b.AddRange([byte[]](1, 2, 3, 4))
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = ConvertFrom-RegistryPol -Bytes $b.ToArray()
            $sw.Stop()
            $r.Truncated | Should -BeTrue
            $r.Reason | Should -Match 'overruns'
            $r.Settings.Count | Should -Be 0
            $sw.ElapsedMilliseconds | Should -BeLessThan 2000
        }

        It 'stops at corruption instead of resynchronizing past it' {
            # A resync would let an attacker hide a setting behind deliberate garbage.
            $rec = New-PolRecord 'K' 'Hidden' 4 ([BitConverter]::GetBytes([uint32]1))
            $bytes = Join-Bytes (New-PolFile) ([byte[]](0x41, 0x41)) $rec
            $r = ConvertFrom-RegistryPol -Bytes $bytes
            $r.Truncated | Should -BeTrue
            $r.Settings.Count | Should -Be 0
        }

        It 'survives random bytes after a valid header' {
            $rand = [byte[]]::new(512)
            [System.Random]::new(42).NextBytes($rand)
            $bytes = Join-Bytes (New-PolFile) $rand
            { ConvertFrom-RegistryPol -Bytes $bytes } | Should -Not -Throw
        }
    }
}
