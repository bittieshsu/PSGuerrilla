# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function New-GuerrillaSecretFile {
    <#
    .SYNOPSIS
        Stages secret content to a temp file that only the current user can read.
    .DESCRIPTION
        Some collectors (Get-GoogleAccessToken) only accept a service-account key by
        file path, so a key resolved from the vault must be written to disk for the
        duration of a scan. This helper does that safely:

          1. Picks a full-entropy name via [System.IO.Path]::GetRandomFileName()
             rather than a truncated GUID slice.
          2. Creates the file EMPTY, then locks it down to owner-only access BEFORE
             any secret bytes are written - so the plaintext key is never world-
             readable, not even for the instant between creation and the ACL change.
               Windows : DACL is inheritance-protected and reduced to a single
                         current-user FullControl ACE (no inherited Users/Everyone).
               Unix    : mode 0600 (owner read/write only), via the managed
                         SetUnixFileMode on PowerShell 7.3+ or chmod on 7.0-7.2.
          3. Writes the content last.

        The caller owns cleanup: delete the returned path in a finally block. This
        function only creates the file.
    .PARAMETER Content
        The secret text to write (e.g. the JSON of a Google service-account key).
    .PARAMETER Prefix
        File-name prefix, so staged keys are recognizable in the temp directory.
    .OUTPUTS
        System.String
    .EXAMPLE
        $keyPath = New-GuerrillaSecretFile -Content $saJson
        try   { Get-GoogleAccessToken -ServiceAccountKeyPath $keyPath -AdminEmail $admin }
        finally { Remove-Item -LiteralPath $keyPath -Force -ErrorAction SilentlyContinue }
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Content,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Prefix = 'guerrilla-sa'
    )

    $random = [System.IO.Path]::GetRandomFileName().Replace('.', '')
    $path   = Join-Path ([System.IO.Path]::GetTempPath()) "$Prefix-$random.json"

    # $IsWindows is automatic in PowerShell 6+; be defensive for 5.1 (all-Windows).
    $onWindows = if (Test-Path variable:IsWindows) { $IsWindows } else { $true }

    # Create the file empty so permissions can be restricted before the secret lands.
    ([System.IO.File]::Create($path)).Dispose()

    if ($onWindows) {
        $fileInfo = [System.IO.FileInfo]::new($path)
        $acl = $fileInfo.GetAccessControl()
        # Protect from inheritance and drop inherited ACEs (Users/Everyone/etc.).
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
        $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $ownerRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $owner,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($ownerRule)
        $fileInfo.SetAccessControl($acl)
    } else {
        $modeSet = $false
        try {
            # Managed path on .NET 7+ (PowerShell 7.3+): no external process needed.
            $mode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
            [System.IO.File]::SetUnixFileMode($path, $mode)
            $modeSet = $true
        } catch {
            $modeSet = $false
        }
        if (-not $modeSet) {
            # PowerShell 7.0-7.2 (.NET 5/6): fall back to chmod. The path is our own
            # random alphanumeric temp name, so there is nothing to escape.
            & 'chmod' '600' $path
        }
    }

    Set-Content -LiteralPath $path -Value $Content -Encoding UTF8 -NoNewline
    return $path
}
