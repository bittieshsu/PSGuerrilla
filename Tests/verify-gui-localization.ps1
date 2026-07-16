# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GUI localization gate. Proves the string catalogs and the GUI agree:
#  1. every catalog parses and declares its language;
#  2. catalog keys use dot-separated camelCase segments (no underscores), so a
#     XAML resource name L_a_b maps unambiguously back to key a.b;
#  3. every {DynamicResource L_*} and $session.L['...'] reference in the GUI
#     source resolves to an English catalog key (English must be complete);
#  4. Spanish carries every English key, each as { value, status } with a
#     recognized provenance status (fallback keeps the GUI usable, but a
#     shipped language must be complete);
#  5. the reference scanner proves it can fail (poison self-test): a synthetic
#     source with an unknown key MUST be flagged, or this gate is meaningless.
# Run: pwsh -File Tests/verify-gui-localization.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$localeDir = Join-Path $root 'source' 'Data' 'Locales'
$guiFiles = @(
    Join-Path $root 'source' 'internal' 'Gui' 'Show-GuerrillaWindow.ps1'
    Join-Path $root 'source' 'internal' 'Gui' 'Show-AddCredentialDialog.ps1'
)

# ── 1. Catalogs parse and declare their language ──
$en = $null
try { $en = Get-Content (Join-Path $localeDir 'gui.en.json') -Raw | ConvertFrom-Json -AsHashtable } catch { }
Add-R 'en catalog parses' ($null -ne $en) ''
Add-R 'en declares _language en/English' ($en -and $en._language.code -eq 'en' -and $en._language.name) ''

# Every shipped translation is held to the same bar: discover all non-English
# catalogs rather than naming languages, so a new gui.<code>.json is gated the
# day it lands.
$translations = @{}
foreach ($f in (Get-ChildItem -Path $localeDir -Filter 'gui.*.json' | Where-Object Name -ne 'gui.en.json' | Sort-Object Name)) {
    $code = ($f.Name -replace '^gui\.', '') -replace '\.json$', ''
    $doc = $null
    try { $doc = Get-Content $f.FullName -Raw | ConvertFrom-Json -AsHashtable } catch { }
    Add-R "$code catalog parses" ($null -ne $doc) $f.Name
    Add-R "$code declares _language $code" ($doc -and $doc._language.code -eq $code -and $doc._language.name) ''
    if ($doc -and $doc._language.Contains('direction')) {
        Add-R "$code direction is ltr or rtl" ($doc._language.direction -in @('ltr', 'rtl')) "got=$($doc._language.direction)"
    }
    if ($doc) { $translations[$code] = $doc }
}
Add-R 'at least one translation shipped' ($translations.Count -ge 1) "got=$($translations.Count)"

# Flatten helpers (mirror of the loader's semantics, independent implementation).
function Get-FlatKeys([hashtable]$Node, [string]$Prefix = '') {
    foreach ($k in $Node.Keys) {
        if ($k -like '_*') { continue }
        $key = if ($Prefix) { "$Prefix.$k" } else { $k }
        $v = $Node[$k]
        if ($v -is [System.Collections.IDictionary] -and -not $v.Contains('value')) {
            Get-FlatKeys $v $key
        } else {
            [PSCustomObject]@{ Key = $key; Value = $v }
        }
    }
}

$enFlat = @(Get-FlatKeys $en)
$enKeys = @($enFlat.Key)
Add-R 'en catalog is non-trivial (50+ keys)' ($enKeys.Count -ge 50) "got=$($enKeys.Count)"

# ── 2. Key naming: dot-separated camelCase, no underscores ──
$badNames = @($enKeys | Where-Object { $_ -cnotmatch '^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)*$' })
Add-R 'en keys are dot-separated camelCase (unambiguous L_ mapping)' ($badNames.Count -eq 0) (($badNames | Select-Object -First 5) -join ', ')
$emptyEn = @($enFlat | Where-Object { -not "$($_.Value)".Trim() })
Add-R 'no empty en values' ($emptyEn.Count -eq 0) (($emptyEn.Key | Select-Object -First 5) -join ', ')

# ── 3. Every GUI reference resolves to an English key ──
function Get-GuiStringRefs([string[]]$Files) {
    $refs = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $Files) {
        $src = Get-Content $f -Raw
        foreach ($m in [regex]::Matches($src, '\{DynamicResource\s+L_([A-Za-z0-9_]+)\}')) {
            $refs.Add(($m.Groups[1].Value -replace '_', '.'))
        }
        foreach ($m in [regex]::Matches($src, "L\['([A-Za-z0-9.]+)'\]")) {
            $refs.Add($m.Groups[1].Value)
        }
    }
    return @($refs | Sort-Object -Unique)
}

$refs = Get-GuiStringRefs $guiFiles
Add-R 'GUI references string resources (60+ distinct keys)' ($refs.Count -ge 60) "got=$($refs.Count)"
$unresolved = @($refs | Where-Object { $_ -notin $enKeys })
Add-R 'every GUI reference resolves in en' ($unresolved.Count -eq 0) (($unresolved | Select-Object -First 8) -join ', ')

# Unused en keys are drift, not failure; surface them so they get pruned.
$unused = @($enKeys | Where-Object { $_ -notin $refs })
if ($unused.Count -gt 0) {
    Write-Host "  [note] $($unused.Count) en key(s) not referenced by the GUI: $(($unused | Select-Object -First 8) -join ', ')" -ForegroundColor DarkYellow
}

# ── 4. Every translation: completeness + provenance shape + placeholder parity ──
foreach ($code in ($translations.Keys | Sort-Object)) {
    $locFlat = @(Get-FlatKeys $translations[$code])
    $locKeys = @($locFlat.Key)
    $missing = @($enKeys | Where-Object { $_ -notin $locKeys })
    Add-R "$code carries every en key (shipped language is complete)" ($missing.Count -eq 0) (($missing | Select-Object -First 8) -join ', ')
    $extra = @($locKeys | Where-Object { $_ -notin $enKeys })
    Add-R "$code has no keys en lacks (no orphan strings)" ($extra.Count -eq 0) (($extra | Select-Object -First 5) -join ', ')
    $badShape = @($locFlat | Where-Object {
        -not ($_.Value -is [System.Collections.IDictionary] -and $_.Value.Contains('value') -and
              "$($_.Value['status'])" -in @('machine-draft', 'human-reviewed') -and "$($_.Value['value'])".Trim())
    })
    Add-R "every $code entry is { value, status } with known provenance" ($badShape.Count -eq 0) (($badShape.Key | Select-Object -First 5) -join ', ')
    # A translated format string must keep exactly the source's {n} placeholders;
    # a dropped or invented placeholder is a runtime format error in that language.
    $enByKey = @{}; foreach ($e in $enFlat) { $enByKey[$e.Key] = "$($e.Value)" }
    $phMismatch = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $locFlat) {
        if (-not $enByKey.ContainsKey($e.Key)) { continue }
        $want = @([regex]::Matches($enByKey[$e.Key], '\{\d+\}') | ForEach-Object Value | Sort-Object -Unique)
        $have = @([regex]::Matches("$($e.Value['value'])", '\{\d+\}') | ForEach-Object Value | Sort-Object -Unique)
        if (($want -join ',') -ne ($have -join ',')) { $phMismatch.Add($e.Key) }
    }
    Add-R "$code format placeholders match en" ($phMismatch.Count -eq 0) (($phMismatch | Select-Object -First 5) -join ', ')
}

# ── 5. Loader behavior through the module ──
$loader = & $mod {
    [PSCustomObject]@{
        Langs = Get-GuerrillaGuiLanguages
        En    = Get-GuerrillaGuiStringTable -Language 'en'
        Es    = Get-GuerrillaGuiStringTable -Language 'es'
        Fall  = Resolve-GuerrillaGuiLanguage -Configured 'xx'
        Cfg   = Resolve-GuerrillaGuiLanguage -Configured 'es'
    }
}
$expectCodes = @('en') + @($translations.Keys)
$missingLangs = @($expectCodes | Where-Object { $_ -notin @($loader.Langs.Code) })
Add-R 'loader discovers every catalog' ($missingLangs.Count -eq 0) "got=$($loader.Langs.Code -join ',')"
Add-R 'loader: English listed first' ($loader.Langs[0].Code -eq 'en') ''
# The loader must surface each catalog's declared direction (the GUI mirrors
# layout from this field); undeclared means ltr.
$dirWrong = [System.Collections.Generic.List[string]]::new()
foreach ($code in $translations.Keys) {
    $declared = if ("$($translations[$code]._language.direction)" -eq 'rtl') { 'rtl' } else { 'ltr' }
    $reported = ($loader.Langs | Where-Object Code -eq $code | Select-Object -First 1).Direction
    if ($reported -ne $declared) { $dirWrong.Add("$code declared=$declared reported=$reported") }
}
Add-R 'loader: reports each catalog direction' ($dirWrong.Count -eq 0) (($dirWrong | Select-Object -First 3) -join '; ')
Add-R 'loader: es table covers en keys (fallback merge)' ($loader.Es.Count -eq $loader.En.Count) "en=$($loader.En.Count) es=$($loader.Es.Count)"
Add-R 'loader: unknown config falls back sanely' ($loader.Fall -in @($loader.Langs.Code)) "got=$($loader.Fall)"
Add-R 'loader: configured language wins' ($loader.Cfg -eq 'es') "got=$($loader.Cfg)"

# ── 6. Poison self-test: the scanner must be able to fail ──
$poison = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-loc-poison-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + ".ps1")
Set-Content -Path $poison -Value @'
<Button Content="{DynamicResource L_poison_notARealKey}"/>
$session.L['poison.alsoNotReal']
'@
try {
    $poisonRefs = Get-GuiStringRefs @($poison)
    $poisonUnresolved = @($poisonRefs | Where-Object { $_ -notin $enKeys })
    Add-R 'poison: scanner flags unknown keys (gate can fail)' ($poisonUnresolved.Count -eq 2) "got=$($poisonUnresolved.Count)"
} finally { Remove-Item $poison -ErrorAction SilentlyContinue }

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($x in $results) {
    $mark = if ($x.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($x.Name)"; if ($x.Detail) { $line += "  ($($x.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
