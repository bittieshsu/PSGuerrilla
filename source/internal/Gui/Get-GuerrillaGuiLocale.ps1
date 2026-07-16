# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GUI localization. String catalogs live in Data/Locales/gui.<code>.json.
# English (gui.en.json) is the source language and its entries are plain
# strings; every other locale's entries are { "value": "...", "status":
# "machine-draft" | "human-reviewed" } so translation provenance is data, the
# same convention the website's locale files use. A missing translated key
# falls back to English, so a partial catalog degrades to mixed-language, never
# to a blank control. Adding a language is adding one file: the header
# selector discovers catalogs at runtime and never hardcodes a language list.

function Get-GuerrillaGuiLocaleRoot {
    [CmdletBinding()]
    param()
    $base = $null
    try { $base = $ExecutionContext.SessionState.Module.ModuleBase } catch { }
    if (-not $base) { $base = Join-Path $PSScriptRoot '..' '..' }
    return (Join-Path $base 'Data' 'Locales')
}

function Get-GuerrillaGuiLanguages {
    <#
    .SYNOPSIS
        Discovers the available GUI languages from the catalog files.
    .DESCRIPTION
        Returns one object per gui.<code>.json with Code, native Name, and text
        Direction ('ltr' unless the catalog's _language block declares 'rtl';
        the GUI mirrors its layout for rtl languages). English first, the rest
        alphabetical by code. A catalog without a valid _language block is
        skipped rather than crashing the GUI.
    #>
    [CmdletBinding()]
    param()

    $root = Get-GuerrillaGuiLocaleRoot
    $langs = [System.Collections.Generic.List[object]]::new()
    foreach ($f in (Get-ChildItem -Path $root -Filter 'gui.*.json' -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $doc = Get-Content $f.FullName -Raw | ConvertFrom-Json -AsHashtable
            $meta = $doc['_language']
            if ($meta -and $meta.code -and $meta.name) {
                $dir = if ("$($meta.direction)" -eq 'rtl') { 'rtl' } else { 'ltr' }
                $langs.Add([PSCustomObject]@{ Code = [string]$meta.code; Name = [string]$meta.name; Direction = $dir })
            }
        } catch { }
    }
    return @(@($langs | Where-Object Code -eq 'en') + @($langs | Where-Object Code -ne 'en' | Sort-Object Code))
}

function Get-GuerrillaGuiStringTable {
    <#
    .SYNOPSIS
        Returns the flattened dot-key -> string table for a language, with
        English as the fallback for any key the language does not carry.
    #>
    [CmdletBinding()]
    param([string]$Language = 'en')

    $root = Get-GuerrillaGuiLocaleRoot

    $flatten = {
        param($Node, $Prefix, $Table)
        foreach ($k in $Node.Keys) {
            if ($k -like '_*') { continue }
            $key = if ($Prefix) { "$Prefix.$k" } else { $k }
            $v = $Node[$k]
            if ($v -is [System.Collections.IDictionary]) {
                if ($v.Contains('value')) { $Table[$key] = [string]$v['value'] }
                else { & $flatten $v $key $Table }
            } else {
                $Table[$key] = [string]$v
            }
        }
    }

    $load = {
        param($Code)
        $path = Join-Path $root "gui.$Code.json"
        if (-not (Test-Path $path)) { return $null }
        try { Get-Content $path -Raw | ConvertFrom-Json -AsHashtable } catch { $null }
    }

    $table = @{}
    $en = & $load 'en'
    if ($en) { & $flatten $en '' $table }
    if ($Language -and $Language -ne 'en') {
        $loc = & $load $Language
        if ($loc) { & $flatten $loc '' $table }
    }
    return $table
}

function Resolve-GuerrillaGuiLanguage {
    <#
    .SYNOPSIS
        Picks the startup language: explicit config choice if that catalog
        exists, otherwise the OS UI culture when a matching catalog exists,
        otherwise English.
    #>
    [CmdletBinding()]
    param([string]$Configured)

    $available = @((Get-GuerrillaGuiLanguages).Code)
    if ($Configured -and $Configured -in $available) { return $Configured }
    try {
        $os = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName
        if ($os -in $available) { return $os }
    } catch { }
    return 'en'
}
