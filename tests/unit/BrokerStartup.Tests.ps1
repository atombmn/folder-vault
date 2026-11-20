<#
    Starts the real background service script the way the scheduled task does
    (powershell -File, no -InstallDir), in a scratch data folder. It cannot get
    far off Windows, which is the point: it must find its own modules, and a
    start-up failure must be written to broker-startup.log, not lost.
#>
Describe 'Background service start-up' -Skip:($IsWindows) {
    BeforeAll {
        $script:broker = (Resolve-Path (Join-Path $PSScriptRoot '..\..\src\FolderVault.Broker.ps1')).Path
        $script:data = Join-Path ([System.IO.Path]::GetTempPath()) ('fvbroker-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $data | Out-Null
        $pwsh = (Get-Process -Id $PID).Path
        $script:out = & $pwsh -NoProfile -File $broker -DataDir $data 2>&1 | Out-String
        $script:code = $LASTEXITCODE
    }
    AfterAll { Get-ChildItem -Force (Split-Path -Parent $data) | Where-Object { $_.Name -like ((Split-Path -Leaf $data) + '*') } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }

    It 'finds its own program folder when started with -File and no -InstallDir' {
        $out | Should -Not -Match "Cannot bind argument to parameter 'Path'"
        $out | Should -Not -Match 'FolderVault\.Common\.psm1.*(not found|was not loaded|cannot be found)'
    }
    It 'exits with code 1 and says why' {
        $code | Should -Be 1
        $out | Should -Match 'failed to start'
    }
    It 'writes the reason to broker-startup.log' {
        # Off Windows the service's backslash path "<data>\Logs\broker-startup.log" becomes
        # one file name next to the data folder, so look beside it as well as inside it.
        $leaf = Split-Path -Leaf $data
        $log = @(Get-ChildItem -Recurse -Force (Split-Path -Parent $data) -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*$leaf*" -and $_.Name -like '*broker-startup.log' })
        $log.Count | Should -Be 1
        [System.IO.File]::ReadAllText($log[0].FullName) | Should -Match 'failed to start: .+ \(script line \d+\)'
    }
}
