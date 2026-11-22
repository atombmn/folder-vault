<#
    Installer package checks (audit fix A-22) and the private set-up folder.
#>
BeforeAll {
    $root = Join-Path $PSScriptRoot '..\..'
    Import-Module (Join-Path $root 'src/FolderVault.Common.psm1') -Force
    Import-Module (Join-Path $root 'install/FolderVault.Setup.psm1') -Force
    $script:BU = 'S-1-5-32-545'; $script:AU = 'S-1-5-11'; $script:Alice = 'S-1-5-21-1-2-3-1001'; $script:Tech = 'S-1-5-21-1-2-3-500'
    function New-Rule { param([string]$Sid, [long]$Rights, [bool]$Allow = $true, [bool]$InheritOnly = $false)
        [pscustomobject]@{ Sid = $Sid; Rights = $Rights; Allow = $Allow; InheritOnly = $InheritOnly } }
    function New-Package {
        $p = Join-Path ([System.IO.Path]::GetTempPath()) ('fvpkg-' + [guid]::NewGuid().ToString('N'))
        foreach ($rel in @('src/FolderVault.Common.psm1', 'src/FolderVault.Engine.psm1', 'install/Install-FolderVault.ps1', 'Install.cmd', 'Uninstall.cmd', 'tests/unit/x.Tests.ps1', 'docs/README.md')) {
            $f = Join-Path $p $rel; [void](New-Item -ItemType Directory -Force -Path (Split-Path $f)); Set-Content -LiteralPath $f -Value "content of $rel"
        }
        $lines = Get-ChildItem -LiteralPath $p -Recurse -File | ForEach-Object {
            '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.FullName.Substring($p.Length + 1).Replace('/', '\') }
        [System.IO.File]::WriteAllText((Join-Path $p 'SHA256SUMS.txt'), ([char]0xFEFF + ($lines -join "`r`n") + "`r`n"))
        return $p
    }
}

Describe 'Who could have changed the package' {
    It 'trusts SYSTEM, Administrators, TrustedInstaller and named admin accounts' {
        $rules = @((New-Rule 'S-1-5-18' 2032127), (New-Rule 'S-1-5-32-544' 2032127), (New-Rule 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' 2032127), (New-Rule $Tech 2032127))
        @(Get-FVUntrustedWriter -OwnerSid 'S-1-5-32-544' -Rules $rules -AdminSids @($Tech)).Count | Should -Be 0
    }
    It 'allows staff to read and run (ReadAndExecute, Synchronize)' {
        @(Get-FVUntrustedWriter -OwnerSid 'S-1-5-32-544' -Rules @((New-Rule $BU 1179817))).Count | Should -Be 0
    }
    It 'flags a staff member with Modify, and Authenticated Users with Modify' {
        $w = @(Get-FVUntrustedWriter -OwnerSid 'S-1-5-32-544' -Rules @((New-Rule $Alice 1245631), (New-Rule $AU 1245631)))
        $w | Should -Contain $Alice
        $w | Should -Contain $AU
    }
    It 'flags a folder owned by a staff member, even with no write rule (an owner can change the permissions)' {
        @(Get-FVUntrustedWriter -OwnerSid $Alice -Rules @()) | Should -Be @("owner $Alice")
    }
    It 'ignores rules that only apply to things created later, and deny rules' {
        @(Get-FVUntrustedWriter -OwnerSid 'S-1-5-32-544' -Rules @((New-Rule $AU 1245631 -InheritOnly $true), (New-Rule $Alice 1245631 -Allow $false))).Count | Should -Be 0
    }
    It 'flags a single write right such as Create files, or change permissions' {
        (Get-FVUntrustedWriter -Rules @((New-Rule $BU 0x2))) | Should -Be $BU
        (Get-FVUntrustedWriter -Rules @((New-Rule $BU 0x40000))) | Should -Be $BU
    }
}

Describe 'Is this the released package' {
    BeforeEach { $script:pkg = New-Package; $script:exp = Read-FVChecksumFile -Path (Join-Path $pkg 'SHA256SUMS.txt') }
    AfterEach { Remove-Item -Recurse -Force $pkg -ErrorAction SilentlyContinue }

    It 'reads the checksum file written by the build, with its byte order mark' {
        $exp.Count | Should -Be 7
        $exp.ContainsKey('src\FolderVault.Common.psm1') | Should -BeTrue
        $exp.ContainsKey('SRC\foldervault.common.psm1') | Should -BeTrue
    }
    It 'passes an untouched package, checking only what the installer uses' {
        $r = Test-FVPackageIntegrity -Root $pkg -Expected $exp
        $r.Ok | Should -BeTrue
        $r.Checked | Should -Be 5
    }
    It 'catches a changed program file' {
        Add-Content -LiteralPath (Join-Path $pkg 'src/FolderVault.Engine.psm1') -Value '# changed'
        $r = Test-FVPackageIntegrity -Root $pkg -Expected $exp
        $r.Ok | Should -BeFalse
        $r.Modified | Should -Be @('src\FolderVault.Engine.psm1')
    }
    It 'catches a missing file and an added script' {
        Remove-Item -LiteralPath (Join-Path $pkg 'Uninstall.cmd')
        Set-Content -LiteralPath (Join-Path $pkg 'src/Extra.psm1') -Value 'x'
        Set-Content -LiteralPath (Join-Path $pkg 'src/notes.txt') -Value 'harmless'
        $r = Test-FVPackageIntegrity -Root $pkg -Expected $exp
        $r.Missing | Should -Be @('Uninstall.cmd')
        $r.Unlisted | Should -Be @('src\Extra.psm1')
    }
    It 'does not care about documents or tests the installer never runs' {
        Add-Content -LiteralPath (Join-Path $pkg 'docs/README.md') -Value 'edited'
        Add-Content -LiteralPath (Join-Path $pkg 'tests/unit/x.Tests.ps1') -Value 'edited'
        (Test-FVPackageIntegrity -Root $pkg -Expected $exp).Ok | Should -BeTrue
    }
    It 'gives a short fingerprint that changes when the checksum file changes' {
        $f = Join-Path $pkg 'SHA256SUMS.txt'
        $a = Get-FVPackageFingerprint -ChecksumFile $f
        $a | Should -Match '^[0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4}$'
        Add-Content -LiteralPath $f -Value ('0' * 64 + '  src\Evil.psm1')
        Get-FVPackageFingerprint -ChecksumFile $f | Should -Not -Be $a
    }
    It 'checks the real package fingerprints file shape from the build' {
        $dist = Get-ChildItem (Join-Path $PSScriptRoot '..\..\dist') -Directory -Filter 'FolderVault-*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*-changes' } | Sort-Object Name | Select-Object -Last 1
        if ($null -eq $dist) { Set-ItResult -Skipped -Because 'no built package'; return }
        $m = Read-FVChecksumFile -Path (Join-Path $dist.FullName 'SHA256SUMS.txt')
        $m.ContainsKey('src\FolderVault.Engine.psm1') | Should -BeTrue
        $m.ContainsKey('Install.cmd') | Should -BeTrue
    }
}

Describe 'Private set-up folder' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    It 'is created with SYSTEM and Administrators only' {
        $p = New-FVAdminOnlyFolder -Prefix 'FolderVault-test-' -Parent ([System.IO.Path]::GetTempPath())
        try {
            $sddl = (Get-Acl -LiteralPath $p).Sddl
            $sddl | Should -Match 'D:PAI'
            $sddl | Should -Not -Match ';;;BU\)|;;;AU\)|;;;WD\)'
        } finally { Remove-FVAdminOnlyFolder -Path $p }
    }
}

Describe 'Stopping old Folder Vault processes (0.4.2)' {
    BeforeAll {
        # Get-CimInstance exists only on Windows; Pester needs a command to mock.
        if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) { function global:Get-CimInstance { param([string]$ClassName, [string]$Filter, $ErrorAction) } }
    }
    BeforeEach {
        $global:FVSP = @{ stopped = New-Object System.Collections.Generic.List[int]; alive = @{ 101 = $true; 102 = $true; 103 = $true } }
        Mock -ModuleName FolderVault.Setup Get-CimInstance { @(
                [pscustomobject]@{ ProcessId = 101; CommandLine = 'powershell.exe -File "C:\Program Files\FolderVault\FolderVault.Broker.ps1"' }
                [pscustomobject]@{ ProcessId = 102; CommandLine = 'powershell.exe -File C:\Other\script.ps1' }
                [pscustomobject]@{ ProcessId = 103; CommandLine = 'powershell.exe -File "C:\Program Files\FolderVault\FolderVault.Tray.ps1"' }) }
        Mock -ModuleName FolderVault.Setup Get-Process { if ($global:FVSP.alive[[int]$Id[0]]) { [pscustomobject]@{ Id = $Id[0] } } }
        Mock -ModuleName FolderVault.Setup Start-Sleep { }
    }
    It 'stops only matching processes and waits until they are gone' {
        Mock -ModuleName FolderVault.Setup Stop-Process { $global:FVSP.stopped.Add([int]$Id[0]); $global:FVSP.alive[[int]$Id[0]] = $false }
        $left = @(Stop-FVProcesses -CommandLineLike @('*FolderVault.Broker.ps1*', '*FolderVault.Tray.ps1*') -ExceptProcessId 1)
        $left.Count | Should -Be 0
        @($global:FVSP.stopped) | Should -Be @(101, 103)
    }
    It 'is not upset by a process that ended by itself before it could be stopped (the 0.4.1 installer error)' {
        # The background service ends because its scheduled task was stopped, between listing and stopping.
        Mock -ModuleName FolderVault.Setup Stop-Process {
            if ([int]$Id[0] -eq 101) { $global:FVSP.alive[101] = $false; throw [Microsoft.PowerShell.Commands.ProcessCommandException]::new("Cannot find a process with the process identifier $($Id[0]).") }
            $global:FVSP.alive[[int]$Id[0]] = $false
        }
        $old = $global:ErrorActionPreference; $global:ErrorActionPreference = 'Stop'
        try { $left = @(Stop-FVProcesses -CommandLineLike @('*FolderVault.Broker.ps1*', '*FolderVault.Tray.ps1*') -ExceptProcessId 1) }
        finally { $global:ErrorActionPreference = $old }
        $left.Count | Should -Be 0
    }
    It 'reports a process that will not stop' {
        Mock -ModuleName FolderVault.Setup Stop-Process { throw [System.ComponentModel.Win32Exception]::new(5) }
        $left = @(Stop-FVProcesses -CommandLineLike @('*FolderVault.Broker.ps1*') -ExceptProcessId 1 -WaitSeconds 0)
        $left | Should -Be @(101)
    }
    It 'never stops itself' {
        Mock -ModuleName FolderVault.Setup Stop-Process { $global:FVSP.stopped.Add([int]$Id[0]); $global:FVSP.alive[[int]$Id[0]] = $false }
        [void](Stop-FVProcesses -CommandLineLike @('*FolderVault*') -ExceptProcessId 101)
        @($global:FVSP.stopped) | Should -Not -Contain 101
    }
}
