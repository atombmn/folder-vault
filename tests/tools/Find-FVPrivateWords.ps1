<#
    Before publishing: looks for words you do not want in the public
    repository (your name, company, computer names, user names, towns).

    Put one word per line in a file OUTSIDE the repository (or in
    private-words.txt, which .gitignore keeps out of git), then run:

      pwsh -File tests/tools/Find-FVPrivateWords.ps1 -WordsFile ..\private-words.txt

    Words are matched whole and without regard to case, in every text file
    (code, documents, tests). A word inside a longer word is not matched, so
    add the longer forms too (for example both "contoso" and "contosoltd").
    Output: one line per hit (file, line, word). No output = nothing found.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WordsFile,
    [string]$Root = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)))
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$words = @{}
foreach ($w in [System.IO.File]::ReadAllLines((Resolve-Path $WordsFile))) {
    $t = $w.Trim().ToLowerInvariant()
    if ($t -and -not $t.StartsWith('#')) { $words[$t] = $true }
}
$skip = '[\\/](\.git|dist|\.refs)[\\/]'
$text = '\.(ps1|psm1|psd1|cmd|md|txt|json|yml|yaml|xml|csv|gitignore|gitattributes)$|(^|[\\/])(LICENSE)$'
$hits = 0
foreach ($f in Get-ChildItem -LiteralPath $Root -Recurse -File -Force) {
    if ($f.FullName -match $skip -or $f.FullName -notmatch $text) { continue }
    if ($f.Name -eq 'private-words.txt') { continue }
    $n = 0
    foreach ($line in [System.IO.File]::ReadAllLines($f.FullName)) {
        $n++
        foreach ($m in [regex]::Matches($line, '[\p{L}\p{N}]+')) {
            if ($words.ContainsKey($m.Value.ToLowerInvariant())) {
                $hits++
                '{0}:{1}: {2}' -f $f.FullName.Substring($Root.Length).TrimStart('\', '/'), $n, $m.Value
            }
        }
    }
}
if ($hits -eq 0) { Write-Host 'No private words found.' -ForegroundColor Green }
