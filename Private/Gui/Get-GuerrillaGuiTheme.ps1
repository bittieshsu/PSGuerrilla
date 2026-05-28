# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaGuiTheme {
    <#
    .SYNOPSIS
        Returns WPF Color + SolidColorBrush hashtables for the GUI, derived from the
        same RGB palette used by the existing HTML reports and console output.
    .DESCRIPTION
        The module-level $script:Palette stores PSStyle ANSI escape sequences (strings)
        which can't be bound to WPF brushes directly. This helper exposes the equivalent
        [System.Windows.Media.Color] + SolidColorBrush instances for XAML and code-behind
        to consume. Extra "Background", "Panel", "Border" entries fill in the surface
        colors the original console palette didn't need but a window UI does.
    #>
    [CmdletBinding()]
    param()

    Add-Type -AssemblyName PresentationCore -ErrorAction SilentlyContinue

    $rgb = @{
        Amber      = @(0xC6, 0x7A, 0x1F)  # accent, primary buttons
        Khaki      = @(0xB8, 0xA9, 0x7E)  # secondary text
        Gray       = @(0x8B, 0x8B, 0x7A)  # muted text
        Sage       = @(0x6B, 0x8E, 0x6B)  # success / PASS
        Parchment  = @(0xF5, 0xF0, 0xE6)  # primary text on dark surfaces
        Gold       = @(0xD4, 0xA8, 0x43)  # warnings / highlights
        Red        = @(0xCC, 0x55, 0x55)  # failures / critical
        # Surface colors (not in the console palette — needed for a window UI)
        Background = @(0x1A, 0x1A, 0x1A)  # window background
        Panel      = @(0x25, 0x24, 0x20)  # nav rail / card surfaces
        Border     = @(0x55, 0x52, 0x4A)  # subtle separators
        Hover      = @(0x33, 0x32, 0x2C)  # button hover state
    }

    $colors  = @{}
    $brushes = @{}
    foreach ($key in $rgb.Keys) {
        $c = [System.Windows.Media.Color]::FromRgb($rgb[$key][0], $rgb[$key][1], $rgb[$key][2])
        $colors[$key]  = $c
        $brushes[$key] = [System.Windows.Media.SolidColorBrush]::new($c)
        $brushes[$key].Freeze()
    }

    return @{
        Colors  = $colors
        Brushes = $brushes
    }
}
