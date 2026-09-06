# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function ConvertFrom-RegistryPol {
    <#
    .SYNOPSIS
        Parses a Group Policy Registry.pol (PReg) file into registry setting objects.
    .DESCRIPTION
        A large amount of real Active Directory posture lives only inside Registry.pol:
        WSUS delivery over HTTP, LLMNR, SMBv1, Defender ASR rules, Terminal Services
        settings. Those are registry-backed policies with no LDAP attribute to read, so
        a scanner that does not open this file cannot assess them at all.

        Format (MS, "Registry Policy File Format"):
          https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format
        Header  : DWORD signature 0x67655250 ("PReg"), DWORD version (1).
        Body    : repeating [key;value;type;size;data]
        Strings : UTF-16LE, null terminated. The delimiters [ ; ] are themselves
                  UTF-16LE characters, so every one is two bytes, not one.

        READ-ONLY: the file is opened as a pure observer (FileShare ReadWrite and
        Delete) so the scan can never block a GPO save or a DFSR replication, and
        never holds a lock on a system it is only supposed to be looking at.

        SECURITY: this parses a file that lives in SYSVOL, which means any principal
        who can write to a GPO folder controls its bytes. The parser therefore treats
        the input as hostile: every read is bounds checked against the buffer, the
        declared data size is validated before allocation so a forged length cannot
        drive a huge allocation, and a malformed record aborts parsing rather than
        resynchronizing (a resync would let an attacker hide settings behind
        deliberate corruption). It returns what it parsed plus a Truncated flag; it
        does not throw, because one bad GPO must not end a domain scan.
    .PARAMETER Path
        Path to a Registry.pol file.
    .PARAMETER Bytes
        Raw file bytes, for callers that already read the file (and for tests).
    .OUTPUTS
        PSCustomObject with Valid, Version, Truncated, Reason, and Settings
        (KeyName, ValueName, ValueType, ValueTypeName, ValueSize, ValueData).
    .EXAMPLE
        ConvertFrom-RegistryPol -Path '\\contoso.com\SYSVOL\contoso.com\Policies\{GUID}\Machine\Registry.pol'
    .EXAMPLE
        $pol = ConvertFrom-RegistryPol -Bytes $bytes
        $pol.Settings | Where-Object KeyName -match 'WindowsUpdate'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'Bytes')][AllowEmptyCollection()][byte[]]$Bytes
    )

    $result = [PSCustomObject]@{
        Valid = $false; Version = 0; Truncated = $false; Reason = ''
        Settings = @()
    }

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        # Read-only is not only "we never write". It also means we never get in the
        # way of the systems we assess. [System.IO.File]::ReadAllBytes opens with
        # FileShare.Read, which on Windows denies WRITERS for the duration of the
        # read: while Guerrilla reads a large Registry.pol over a slow link, a
        # sysadmin saving that GPO in GPMC, or DFSR replicating it, can take a
        # sharing violation caused entirely by the scan. Opening with
        # ReadWrite + Delete makes this a pure observer that never blocks anyone,
        # even a process deleting the file underneath us.
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                                             [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
            try {
                $len = [int][System.Math]::Min($stream.Length, [int]::MaxValue)
                $buffer = New-Object byte[] $len
                $read = 0
                while ($read -lt $len) {
                    $n = $stream.Read($buffer, $read, $len - $read)
                    if ($n -le 0) { break }   # file shrank under us; parse what we got
                    $read += $n
                }
                $Bytes = if ($read -eq $len) { $buffer } else { $buffer[0..([System.Math]::Max($read - 1, 0))] }
            } finally { $stream.Dispose() }
        }
        catch { $result.Reason = "Could not read ${Path}: $($_.Exception.Message)"; return $result }
    }

    # Header: 8 bytes minimum. Signature is a little-endian DWORD 0x67655250,
    # which is the ASCII bytes 'P' 'R' 'e' 'g' in file order.
    if ($null -eq $Bytes -or $Bytes.Length -lt 8) { $result.Reason = 'File is shorter than the 8-byte PReg header'; return $result }
    $sig = [System.BitConverter]::ToUInt32($Bytes, 0)
    if ($sig -ne 0x67655250) { $result.Reason = ('Bad signature 0x{0:X8}; expected 0x67655250 (PReg)' -f $sig); return $result }
    $result.Version = [System.BitConverter]::ToUInt32($Bytes, 4)
    $result.Valid = $true

    $TYPE_NAMES = @{
        0 = 'REG_NONE'; 1 = 'REG_SZ'; 2 = 'REG_EXPAND_SZ'; 3 = 'REG_BINARY'; 4 = 'REG_DWORD'
        5 = 'REG_DWORD_BIG_ENDIAN'; 6 = 'REG_LINK'; 7 = 'REG_MULTI_SZ'; 11 = 'REG_QWORD'
    }
    $OPEN = 0x5B; $SEMI = 0x3B; $CLOSE = 0x5D   # [ ; ]  as UTF-16LE low bytes

    # Reads a null-terminated UTF-16LE string starting at $i. Returns the string and
    # advances past the terminator, or $null when the buffer ends first.
    $readString = {
        param([byte[]]$b, [ref]$i)
        $start = $i.Value
        while ($i.Value + 1 -lt $b.Length) {
            if ($b[$i.Value] -eq 0 -and $b[$i.Value + 1] -eq 0) {
                $s = [System.Text.Encoding]::Unicode.GetString($b, $start, $i.Value - $start)
                $i.Value += 2
                return $s
            }
            $i.Value += 2
        }
        return $null
    }
    # A delimiter is one UTF-16LE character: low byte then a zero high byte.
    $expectChar = {
        param([byte[]]$b, [ref]$i, [int]$ch)
        if ($i.Value + 1 -ge $b.Length) { return $false }
        if ($b[$i.Value] -ne $ch -or $b[$i.Value + 1] -ne 0) { return $false }
        $i.Value += 2
        return $true
    }

    $settings = [System.Collections.Generic.List[object]]::new()
    $i = 8
    while ($i -lt $Bytes.Length) {
        # Trailing padding of nulls is tolerated; anything else that is not '[' is corruption.
        if ($Bytes[$i] -eq 0 -and ($i + 1 -ge $Bytes.Length -or $Bytes[$i + 1] -eq 0)) { $i += 2; continue }

        $ref = [ref]$i
        if (-not (& $expectChar $Bytes $ref $OPEN)) { $result.Truncated = $true; $result.Reason = "Expected '[' at byte $i"; break }
        $key = & $readString $Bytes $ref
        if ($null -eq $key) { $result.Truncated = $true; $result.Reason = 'Key name not terminated'; break }
        if (-not (& $expectChar $Bytes $ref $SEMI)) { $result.Truncated = $true; $result.Reason = "Expected ';' after key '$key'"; break }
        $value = & $readString $Bytes $ref
        if ($null -eq $value) { $result.Truncated = $true; $result.Reason = "Value name not terminated in key '$key'"; break }
        if (-not (& $expectChar $Bytes $ref $SEMI)) { $result.Truncated = $true; $result.Reason = "Expected ';' after value '$value'"; break }

        if ($ref.Value + 4 -gt $Bytes.Length) { $result.Truncated = $true; $result.Reason = 'Type field truncated'; break }
        $type = [System.BitConverter]::ToUInt32($Bytes, $ref.Value); $ref.Value += 4
        if (-not (& $expectChar $Bytes $ref $SEMI)) { $result.Truncated = $true; $result.Reason = 'Expected ";" after type'; break }

        if ($ref.Value + 4 -gt $Bytes.Length) { $result.Truncated = $true; $result.Reason = 'Size field truncated'; break }
        $size = [System.BitConverter]::ToUInt32($Bytes, $ref.Value); $ref.Value += 4
        if (-not (& $expectChar $Bytes $ref $SEMI)) { $result.Truncated = $true; $result.Reason = 'Expected ";" after size' ; break }

        # Bounds check BEFORE trusting the declared size: a forged length must not
        # drive an allocation or read past the buffer.
        if ($size -gt [int]::MaxValue -or $ref.Value + [int]$size -gt $Bytes.Length) {
            $result.Truncated = $true; $result.Reason = "Declared data size $size overruns the file in key '$key'"; break
        }
        $dataStart = $ref.Value; $len = [int]$size; $ref.Value += $len

        $data = switch ($type) {
            4  { if ($len -ge 4) { [System.BitConverter]::ToUInt32($Bytes, $dataStart) } else { $null } }
            5  { if ($len -ge 4) { [uint32](([uint32]$Bytes[$dataStart] -shl 24) -bor ([uint32]$Bytes[$dataStart+1] -shl 16) -bor ([uint32]$Bytes[$dataStart+2] -shl 8) -bor [uint32]$Bytes[$dataStart+3]) } else { $null } }
            11 { if ($len -ge 8) { [System.BitConverter]::ToUInt64($Bytes, $dataStart) } else { $null } }
            7  { @(([System.Text.Encoding]::Unicode.GetString($Bytes, $dataStart, $len)).TrimEnd([char]0) -split "`0" | Where-Object { $_ -ne '' }) }
            3  { $b = New-Object byte[] $len; if ($len) { [Array]::Copy($Bytes, $dataStart, $b, 0, $len) }; ,$b }
            default { ([System.Text.Encoding]::Unicode.GetString($Bytes, $dataStart, $len)).TrimEnd([char]0) }
        }

        if (-not (& $expectChar $Bytes $ref $CLOSE)) { $result.Truncated = $true; $result.Reason = "Expected ']' closing key '$key'"; break }
        $i = $ref.Value

        $settings.Add([PSCustomObject]@{
            KeyName = $key; ValueName = $value; ValueType = [int]$type
            ValueTypeName = ($TYPE_NAMES[[int]$type] ?? "UNKNOWN($type)")
            ValueSize = [int]$size; ValueData = $data
        })
    }

    $result.Settings = @($settings)
    return $result
}
