<#
    Builds the Folder Vault release.

    Produces, in dist\:
      FolderVault-<version>.zip           full package
      FolderVault-<version>-client.zip    what a client PC needs, with its own fingerprints
      FolderVault-<version>-changes.zip   only files added or changed since -PreviousDir,
                                      plus CHANGED-FILES.txt (which also lists removed files)

    * Scripts, documents and .cmd files are saved with Windows (CRLF) line endings.
      .ps1/.psm1/.psd1/.md are saved as UTF-8 WITH BOM, because Windows
      PowerShell 5.1 reads BOM-less files as ANSI. .cmd files stay plain ASCII.
    * SHA256SUMS.txt covers every file in the full package.

    Usage: pwsh ./build/Build-Package.ps1 [-PreviousDir dist/FolderVault-0.1.0]
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string]$PreviousDir
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $root 'dist' }
Import-Module (Join-Path $root 'src/FolderVault.Common.psm1') -Force
$version = Get-FVProductVersion
$name = "FolderVault-$version"
$stage = Join-Path $OutDir $name
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$include = @('src', 'install', 'admin', 'tests', 'docs', 'build', 'README.md', 'CHANGELOG.md', 'PSScriptAnalyzerSettings.psd1',
    'Install.cmd', 'Uninstall.cmd', 'Check-ThisPC.cmd', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md')
$bom = New-Object System.Text.UTF8Encoding($true)
$ascii = New-Object System.Text.ASCIIEncoding
foreach ($i in $include) {
    $src = Join-Path $root $i
    if (-not (Test-Path $src)) { throw "Missing from source: $i" }
    $items = if ((Get-Item $src).PSIsContainer) { Get-ChildItem $src -Recurse -File } else { @(Get-Item $src) }
    foreach ($f in $items) {
        if ($f.Name -like '*.orig') { continue }
        if ($f.FullName -match '[\\/]tests[\\/]\.refs[\\/]') { continue }   # downloaded reference assemblies
        $rel = $f.FullName.Substring($root.Length + 1)
        $dest = Join-Path $stage $rel
        New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
        $text = $null
        if ($f.Extension -in @('.ps1', '.psm1', '.psd1', '.md', '.txt', '.json', '.cmd')) {
            $text = [System.IO.File]::ReadAllText($f.FullName)
            $text = $text.TrimStart([char]0xFEFF) -replace "`r`n", "`n" -replace "`n", "`r`n"
        }
        if ($f.Extension -eq '.cmd') {
            if ($text -match '[^\x00-\x7F]') { throw "$rel contains non-ASCII characters" }
            [System.IO.File]::WriteAllText($dest, $text, $ascii)
        } elseif ($null -ne $text) {
            [System.IO.File]::WriteAllText($dest, $text, $bom)
        } else {
            Copy-Item $f.FullName $dest
        }
    }
}

function Get-RelativeHashes {
    param([string]$Dir)
    $map = @{}
    Get-ChildItem $Dir -Recurse -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object {
        $map[$_.FullName.Substring($Dir.Length + 1).Replace('/', '\')] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
    return $map
}

$now = Get-RelativeHashes $stage
$sums = $now.Keys | Sort-Object | ForEach-Object { '{0}  {1}' -f $now[$_], $_ }
[System.IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS.txt'), (($sums -join "`r`n") + "`r`n"), $bom)

$zip = Join-Path $OutDir "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip
Write-Host "Built $zip"
# The installer shows this fingerprint; put it in the release note so the technician can compare.
$fp = (Get-FileHash (Join-Path $stage 'SHA256SUMS.txt') -Algorithm SHA256).Hash
Write-Host ("Package fingerprint: " + (($fp.Substring(0, 16) -split '(.{4})' | Where-Object { $_ }) -join ' '))

if ($PreviousDir) {
    $prev = Get-RelativeHashes (Resolve-Path $PreviousDir).Path
    $changed = @($now.Keys | Where-Object { -not $prev.ContainsKey($_) -or $prev[$_] -ne $now[$_] } | Sort-Object)
    $removed = @($prev.Keys | Where-Object { -not $now.ContainsKey($_) } | Sort-Object)
    $cstage = Join-Path $OutDir "$name-changes"
    if (Test-Path $cstage) { Remove-Item $cstage -Recurse -Force }
    foreach ($rel in $changed) {
        $d = Join-Path $cstage ($rel.Replace('\', [IO.Path]::DirectorySeparatorChar))
        New-Item -ItemType Directory -Path (Split-Path $d) -Force | Out-Null
        Copy-Item (Join-Path $stage ($rel.Replace('\', [IO.Path]::DirectorySeparatorChar))) $d
    }
    # The new fingerprints file goes too, so a copied-over folder still passes the installer's check.
    Copy-Item (Join-Path $stage 'SHA256SUMS.txt') (Join-Path $cstage 'SHA256SUMS.txt')
    $lines = @("Folder Vault ${version}: files changed since $(Split-Path -Leaf $PreviousDir)", '',
        'Use the FULL package to install or update a PC. This list is for review.', '',
        "Added or changed ($($changed.Count)):") + ($changed | ForEach-Object { "  $_" }) + @('', "Removed ($($removed.Count)):") + ($removed | ForEach-Object { "  $_" })
    [System.IO.File]::WriteAllText((Join-Path $cstage 'CHANGED-FILES.txt'), (($lines -join "`r`n") + "`r`n"), $bom)
    $czip = Join-Path $OutDir "$name-changes.zip"
    if (Test-Path $czip) { Remove-Item $czip -Force }
    Compress-Archive -Path $cstage -DestinationPath $czip
    Write-Host "Built $czip ($($changed.Count) changed, $($removed.Count) removed)"
}

# ---------------------------------------------------------------------------
# Client kit: only what a client PC needs (no tests, build tools or technical
# documents). It has its own SHA256SUMS.txt and fingerprint; the installer's
# package check works the same on it.
# ---------------------------------------------------------------------------
$kitName = "$name-client"
$kit = Join-Path $OutDir $kitName
if (Test-Path $kit) { Remove-Item $kit -Recurse -Force }
New-Item -ItemType Directory -Path $kit -Force | Out-Null
$kitItems = @('Install.cmd', 'Uninstall.cmd', 'Check-ThisPC.cmd', 'README.md', 'CHANGELOG.md', 'LICENSE', 'src', 'install', 'admin',
    'docs\USER-GUIDE.md', 'docs\SETUP-GUIDE.md', 'docs\GLOSSARY.md', 'docs\FOR-MANAGERS.md')
foreach ($i in $kitItems) {
    $from = Join-Path $stage ($i.Replace('\', [System.IO.Path]::DirectorySeparatorChar))
    $to = Join-Path $kit ($i.Replace('\', [System.IO.Path]::DirectorySeparatorChar))
    New-Item -ItemType Directory -Path (Split-Path $to) -Force | Out-Null
    Copy-Item -Path $from -Destination $to -Recurse -Force
}
$kitNow = Get-RelativeHashes $kit
$kitSums = $kitNow.Keys | Sort-Object | ForEach-Object { '{0}  {1}' -f $kitNow[$_], $_ }
[System.IO.File]::WriteAllText((Join-Path $kit 'SHA256SUMS.txt'), (($kitSums -join "`r`n") + "`r`n"), $bom)
$kzip = Join-Path $OutDir "$kitName.zip"
if (Test-Path $kzip) { Remove-Item $kzip -Force }
Compress-Archive -Path $kit -DestinationPath $kzip
$kfp = (Get-FileHash (Join-Path $kit 'SHA256SUMS.txt') -Algorithm SHA256).Hash
Write-Host "Built $kzip"
Write-Host ("Client kit fingerprint: " + (($kfp.Substring(0, 16) -split '(.{4})' | Where-Object { $_ }) -join ' '))
