<#
    Static security and compatibility checks over every script in the package.
#>
BeforeDiscovery {
    $root = Join-Path $PSScriptRoot '..\..'
    $script:files = @(Get-ChildItem -Recurse -Include *.ps1, *.psm1 -Path (Join-Path $root 'src'), (Join-Path $root 'install'), (Join-Path $root 'admin') |
        ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

Describe 'Every script: <Name>' -ForEach $files {
    BeforeAll {
        $tokens = $null; $errors = $null
        $script:ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $script:parseErrors = $errors
        $script:text = [System.IO.File]::ReadAllText($Path)
    }
    It 'parses without errors' { @($parseErrors).Count | Should -Be 0 }
    It 'uses no PowerShell 7-only syntax (ternary, ??, ?., && / ||)' {
        $bad = $ast.FindAll({ param($n)
            $n.GetType().Name -in @('TernaryExpressionAst', 'PipelineChainAst') -or
            ($n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator.ToString() -in @('QuestionQuestion')) -or
            ($n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Operator.ToString() -eq 'QuestionQuestionEquals') -or
            ($n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.NullConditional)
        }, $true)
        @($bad).Count | Should -Be 0
    }
    It 'never evaluates strings as code (Invoke-Expression / iex / AddScript of input)' {
        $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() }
        $cmds | Should -Not -Contain 'Invoke-Expression'
        $cmds | Should -Not -Contain 'iex'
    }
    It 'never disables TLS/certificate validation or downloads code' {
        $text | Should -Not -Match 'ServerCertificateValidationCallback'
        $text | Should -Not -Match 'DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer'
    }
    It 'never uses -Command with interpolated input (only -File)' {
        $text | Should -Not -Match 'powershell(\.exe)?["'']?\s+[^\r\n]*-Command\s'
    }
    It 'does not log raw request objects' {
        $text | Should -Not -Match 'Write-FVLog[^\r\n]*\$req\b'
        $text | Should -Not -Match 'Write-FVLog[^\r\n]*\$Request\b'
    }
}

Describe 'Broker-only modules stay out of user paths' {
    It 'the engine builds every path from Get-FolderVaultFiles or the data directory' {
        $engine = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\src\FolderVault.Engine.psm1')
        # No function in the engine takes a folder path from the user.
        $engine | Should -Not -Match '\$Record\.FolderPath\s*[\),]?\s*(-Destination|-Path|Copy|Move|Remove)'
        $engine | Should -Not -Match 'robocopy'
    }
    It 'the broker never imports the user-side file operations' {
        $b = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\src\FolderVault.Broker.ps1')
        $b | Should -Not -Match 'FolderVault\.UserOps'
    }
}

Describe 'UI XAML is well-formed' {
    It 'every XAML block parses as XML' {
        $ui = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\src\FolderVault.UI.ps1')
        $styles = [regex]::Match($ui, "(?s)\`$script:Styles = @'\r?\n(.*?)\r?\n'@").Groups[1].Value
        $blocks = [regex]::Matches($ui, "(?s)\`$script:\w+Xaml = @'\r?\n(.*?)\r?\n'@")
        $blocks.Count | Should -Be 3
        foreach ($b in $blocks) {
            $x = $b.Groups[1].Value.Replace('<!--STYLES-->', $styles)
            { [xml]$x } | Should -Not -Throw
        }
    }
    It 'every control the code looks up exists in the XAML' {
        $ui = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\src\FolderVault.UI.ps1')
        $names = [regex]::Matches($ui, 'x:Name="(\w+)"') | ForEach-Object { $_.Groups[1].Value }
        $wanted = [regex]::Matches($ui, "Get-Controls \`$w @\(([^)]*)\)") | ForEach-Object { $_.Groups[1].Value -split ',' } | ForEach-Object { $_.Trim().Trim("'") } | Where-Object { $_ }
        foreach ($w in $wanted) { $names | Should -Contain $w }
    }
}


Describe '0.2: light tray, installer file list, launchers' {
    BeforeAll { $script:root = Join-Path $PSScriptRoot '..\..' }
    It 'the tray never loads the WPF window toolkit' {
        $t = Get-Content -Raw (Join-Path $root 'src\FolderVault.Tray.ps1')
        $t | Should -Not -Match 'PresentationFramework|System\.Windows\.Window\b|XamlReader'
    }
    It 'the window script loads WPF only inside Initialize-FVWpf' {
        $u = Get-Content -Raw (Join-Path $root 'src\FolderVault.UI.ps1')
        ([regex]::Matches($u, 'Add-Type -AssemblyName PresentationFramework')).Count | Should -Be 1
        $u | Should -Match 'function Initialize-FVWpf \{\s+if \(\$script:WpfLoaded\) \{ return \}\s+Add-Type -AssemblyName PresentationFramework'
        $u | Should -Not -Match 'System\.Windows\.MessageBox'
    }
    It 'the installer copies every program file in src, and nothing that does not exist' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'install\Install-FolderVault.ps1'), [ref]$tokens, [ref]$errors)
        $assign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$programFiles' }, $true)
        $listed = @($assign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
        $actual = @(Get-ChildItem (Join-Path $root 'src') -File | ForEach-Object { $_.Name })
        @($listed | Sort-Object) | Should -Be @($actual | Sort-Object)
    }
    It '<Name> is a one-command launcher with no bracket blocks' -ForEach @(@{ Name = 'Install.cmd' }, @{ Name = 'Uninstall.cmd' }, @{ Name = 'Check-ThisPC.cmd' }) {
        $c = Get-Content -Raw (Join-Path $root $Name)
        $c | Should -Match '^@echo off'
        $c | Should -Not -Match '\(\s*"'
        $c | Should -Match '-ExecutionPolicy Bypass -File'
        $c | Should -Not -Match '-Command'
        # At least one script the launcher points at must exist in the package
        # (Uninstall.cmd also points at the installed copy in Program Files).
        $refs = @([regex]::Matches($c, '%~dp0([^"%]+\.ps1)') | ForEach-Object { $_.Groups[1].Value.Replace('\', [IO.Path]::DirectorySeparatorChar) })
        $refs.Count | Should -BeGreaterThan 0
        @($refs | Where-Object { Test-Path (Join-Path $root $_) }).Count | Should -BeGreaterThan 0
    }
}

Describe '0.2.1: no script relies on automatic variables inside param()' {
    BeforeDiscovery {
        $r = Join-Path $PSScriptRoot '..\..'
        $script:allScripts = @(Get-ChildItem -Recurse -Include *.ps1 -Path (Join-Path $r 'src'), (Join-Path $r 'install'), (Join-Path $r 'admin'), (Join-Path $r 'build'), (Join-Path $r 'tests\windows') |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
    }
    It '<Name>: param() defaults do not use $PSScriptRoot, $PSCommandPath or $MyInvocation' -ForEach $allScripts {
        $t = $null; $e = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$t, [ref]$e)
        $bad = @()
        if ($null -ne $ast.ParamBlock) {
            foreach ($p in $ast.ParamBlock.Parameters) {
                if ($null -eq $p.DefaultValue) { continue }
                $bad += @($p.DefaultValue.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -in @('PSScriptRoot', 'PSCommandPath', 'MyInvocation') }, $true) | ForEach-Object { $p.Name.Extent.Text })
            }
        }
        $bad | Should -BeNullOrEmpty -Because 'Windows PowerShell 5.1 can leave these empty in param() when a script is run with -File (bug found in 0.2.0: the background service would not start)'
    }
}

Describe '0.2.2: no .Count that breaks under Windows PowerShell 5.1 strict mode' {
    It 'every .Count is on something that is certainly a collection' {
        $root = Join-Path $PSScriptRoot '..\..'
        $files = @(Get-ChildItem -Recurse -Include *.ps1, *.psm1 -Path (Join-Path $root 'src'), (Join-Path $root 'install'), (Join-Path $root 'admin'), (Join-Path $root 'tests\windows') | ForEach-Object { $_.FullName })
        $found = @(& (Join-Path $root 'tests\tools\Find-FVUnsafeCount.ps1') -Path $files)
        ($found | ForEach-Object { "$($_.File):$($_.Line) $($_.Code)" }) | Should -BeNullOrEmpty -Because 'Windows PowerShell 5.1 throws on .Count of a single object or $null under Set-StrictMode 3 (bug found in 0.2.1: the health check crashed). Wrap in @( ) or mark "# count-safe: reason".'
    }
}

Describe '0.2.4: no [ordered] table with number keys' {
    It 'every [ordered] table uses text keys' {
        $root = Join-Path $PSScriptRoot '..\..'
        $bad = @()
        foreach ($f in @(Get-ChildItem -Recurse -Include *.ps1, *.psm1 -Path (Join-Path $root 'src'), (Join-Path $root 'install'), (Join-Path $root 'admin'), (Join-Path $root 'tests\windows'))) {
            $t = $null; $e = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
            foreach ($h in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] -and $n.Parent -is [System.Management.Automation.Language.ConvertExpressionAst] -and $n.Parent.Type.TypeName.Name -eq 'ordered' }, $true)) {
                foreach ($kv in $h.KeyValuePairs) {
                    if ($kv.Item1 -is [System.Management.Automation.Language.ConstantExpressionAst] -and $kv.Item1.Value -is [ValueType]) { $bad += "$($f.Name):$($kv.Item1.Extent.StartLineNumber) key $($kv.Item1.Extent.Text)" }
                }
            }
        }
        $bad | Should -BeNullOrEmpty -Because '$t[1003] on an [ordered] table means "item number 1003", not "key 1003", and throws (bug in 0.2.3: the health check crashed)'
    }
}

Describe '0.2.5: programs are run so their error output cannot stop a script half-way' {
    It 'every redirected error stream on a command call is in Invoke-FVNative or follows ErrorActionPreference = Continue' {
        $root = Join-Path $PSScriptRoot '..\..'
        $bad = @()
        foreach ($f in @(Get-ChildItem -Recurse -Include *.ps1, *.psm1 -Path (Join-Path $root 'src'), (Join-Path $root 'install'), (Join-Path $root 'admin'))) {
            $t = $null; $e = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
            $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                    @($n.Redirections | Where-Object { $_.FromStream -eq 'Error' -or $_.FromStream -eq 'All' }).Count -gt 0 }, $true)
            foreach ($c in $cmds) {
                $fn = $c.Parent
                while ($null -ne $fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                if ($null -ne $fn -and $fn.Name -eq 'Invoke-FVNative') { continue }
                # Otherwise the same block must set ErrorActionPreference to Continue before the call.
                $block = $c.Parent
                while ($null -ne $block -and $block -isnot [System.Management.Automation.Language.StatementBlockAst] -and $block -isnot [System.Management.Automation.Language.NamedBlockAst]) { $block = $block.Parent }
                $guarded = $false
                if ($null -ne $block) {
                    foreach ($st in $block.Statements) {
                        if ($st.Extent.StartOffset -ge $c.Extent.StartOffset) { break }
                        if ($st.Extent.Text -match '^\$ErrorActionPreference\s*=\s*''Continue''') { $guarded = $true }
                    }
                }
                if (-not $guarded) { $bad += "$($f.Name):$($c.Extent.StartLineNumber) $($c.Extent.Text)" }
            }
        }
        $bad | Should -BeNullOrEmpty -Because 'in Windows PowerShell 5.1, 2>$null or 2>&1 on a program turns its error output into a stopping error when ErrorActionPreference is Stop'
    }
    It 'Invoke-FVNative itself sets ErrorActionPreference to Continue before running the program' {
        # PowerShell 7 no longer stops on redirected program errors, so this cannot be shown by running it here.
        $t = $null; $e = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\..\src\FolderVault.Common.psm1'), [ref]$t, [ref]$e)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-FVNative' }, $true)
        $st = @($fn.Body.EndBlock.Statements)
        $iSet = [array]::FindIndex($st, [Predicate[object]] { param($x) $x.Extent.Text -match '^\$ErrorActionPreference\s*=\s*''Continue''$' })
        $iRun = [array]::FindIndex($st, [Predicate[object]] { param($x) $x.Extent.Text -match '2>&1' })
        $iSet | Should -BeGreaterOrEqual 0
        $iRun | Should -BeGreaterThan $iSet
    }
}

Describe '0.3.0: no hex numbers that PowerShell turns negative' {
    It 'no 8-digit hex literal from 0x80000000 up (PowerShell 5.1 reads 0xFFFFFFFF as -1)' {
        $root = Join-Path $PSScriptRoot '..\..'
        $bad = @()
        foreach ($f in @(Get-ChildItem -Recurse -Include *.ps1, *.psm1 -Path (Join-Path $root 'src'), (Join-Path $root 'install'), (Join-Path $root 'admin'))) {
            $t = $null; $e = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
            foreach ($tok in $t) {
                if ($tok.Kind -eq 'Number' -and $tok.Text -match '^0x[89A-Fa-f][0-9A-Fa-f]{7}$') { $bad += "$($f.Name):$($tok.Extent.StartLineNumber) $($tok.Text)" }
            }
        }
        $bad | Should -BeNullOrEmpty
    }
}
