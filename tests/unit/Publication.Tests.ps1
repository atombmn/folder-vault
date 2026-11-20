<#
    Hygiene checks for a public repository: no e-mail addresses, no web links
    except to Microsoft and NuGet, and only made-up user names in example
    paths. Your own private words (names, computer names) are checked with
    tests/tools/Find-FVPrivateWords.ps1 and a word list kept out of git.
#>
BeforeAll {
    $script:root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
            $_.FullName -notmatch '[\\/](\.git|dist|\.refs)[\\/]' -and
            $_.FullName -match '\.(ps1|psm1|psd1|cmd|md|yml|gitignore|gitattributes)$|[\\/]LICENSE$' })
    function Find-InFiles { param([string]$Pattern)
        foreach ($f in $files) {
            $n = 0
            foreach ($line in [System.IO.File]::ReadAllLines($f.FullName)) {
                $n++
                foreach ($m in [regex]::Matches($line, $Pattern)) { [pscustomobject]@{ File = $f.Name; Line = $n; Text = $m.Value } }
            }
        }
    }
}

Describe 'Publication hygiene' {
    It 'scans the whole repository' { $files.Count | Should -BeGreaterThan 40 }
    It 'contains no e-mail addresses' {
        @(Find-InFiles '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]*[A-Za-z]{2,}' | Where-Object { $_.Text -notmatch '@(example\.(com|org)|users\.noreply\.github\.com)$' }) |
            ForEach-Object { "$($_.File):$($_.Line) $($_.Text)" } | Should -BeNullOrEmpty
    }
    It 'links only to Microsoft, NuGet and the project''s own GitHub pages' {
        $ok = '^https?://((schemas|learn|support|www)\.microsoft\.com|api\.nuget\.org|www\.nuget\.org|docs\.github\.com|github\.com/(pester|PowerShell)/|github\.com/<your-account|gitforwindows\.org|attack\.mitre\.org|keepachangelog\.com|semver\.org|opensource\.org)'
        @(Find-InFiles 'https?://[^\s)\]>"''`]+' | Where-Object { $_.Text -notmatch $ok }) | ForEach-Object { "$($_.File):$($_.Line) $($_.Text)" } | Should -BeNullOrEmpty
    }
    It 'uses only made-up user names in example paths' {
        $allowed = '^(alice|bob|carol|jsmith|itadmin|fvtest_a|fvtest_b|public|x|a|al|alicea|\.|<user>|<name>)$'
        @(Find-InFiles '(?i)\\Users\\[A-Za-z0-9_.<>-]+' | Where-Object { $_.Text.Substring(7) -notmatch $allowed }) |
            ForEach-Object { "$($_.File):$($_.Line) $($_.Text)" } | Should -BeNullOrEmpty
    }
}
