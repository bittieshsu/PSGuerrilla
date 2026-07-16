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
$en = $es = $null
try { $en = Get-Content (Join-Path $localeDir 'gui.en.json') -Raw | ConvertFrom-Json -AsHashtable } catch { }
try { $es = Get-Content (Join-Path $localeDir 'gui.es.json') -Raw | ConvertFrom-Json -AsHashtable } catch { }
Add-R 'en catalog parses' ($null -ne $en) ''
Add-R 'es catalog parses' ($null -ne $es) ''
Add-R 'en declares _language en/English' ($en -and $en._language.code -eq 'en' -and $en._language.name) ''
Add-R 'es declares _language es' ($es -and $es._language.code -eq 'es' -and $es._language.name) ''

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
$esFlat = @(Get-FlatKeys $es)
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

# ── 4. Spanish completeness + provenance shape ──
$esKeys = @($esFlat.Key)
$missingEs = @($enKeys | Where-Object { $_ -notin $esKeys })
Add-R 'es carries every en key (shipped language is complete)' ($missingEs.Count -eq 0) (($missingEs | Select-Object -First 8) -join ', ')
$badShape = @($esFlat | Where-Object {
    -not ($_.Value -is [System.Collections.IDictionary] -and $_.Value.Contains('value') -and
          "$($_.Value['status'])" -in @('machine-draft', 'human-reviewed') -and "$($_.Value['value'])".Trim())
})
Add-R 'every es entry is { value, status } with known provenance' ($badShape.Count -eq 0) (($badShape.Key | Select-Object -First 5) -join ', ')

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
Add-R 'loader discovers en + es' (@($loader.Langs.Code) -contains 'en' -and @($loader.Langs.Code) -contains 'es') "got=$($loader.Langs.Code -join ',')"
Add-R 'loader: English listed first' ($loader.Langs[0].Code -eq 'en') ''
Add-R 'loader: es table covers en keys (fallback merge)' ($loader.Es.Count -eq $loader.En.Count) "en=$($loader.En.Count) es=$($loader.Es.Count)"
Add-R 'loader: unknown config falls back sanely' ($loader.Fall -in @('en', 'es')) "got=$($loader.Fall)"
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
