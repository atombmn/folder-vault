BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\src\FolderVault.Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\..\admin\FolderVault.Health.psm1') -Force
}

Describe 'Which permissions count as "can change"' {
    It 'read-only rights are not write: <Name>' -ForEach @(
        @{ Name = 'ReadAndExecute, Synchronize (seen on the first test PC, 13 Nov 2026)'; R = [long][System.Security.AccessControl.FileSystemRights]'ReadAndExecute, Synchronize' }
        @{ Name = 'Read'; R = [long][System.Security.AccessControl.FileSystemRights]'Read' }
        @{ Name = '0x1200a9 (what the installer grants Users)'; R = [long]0x1200a9 }
        @{ Name = 'GENERIC_READ as a negative Int32'; R = [long][int]-2147483648 }
        @{ Name = 'GENERIC_EXECUTE'; R = [long]0x20000000 }
    ) { Test-FVGrantsWrite -Rights $R | Should -BeFalse }
    It 'write rights are write: <Name>' -ForEach @(
        @{ Name = 'Modify'; R = [long][System.Security.AccessControl.FileSystemRights]'Modify' }
        @{ Name = 'FullControl'; R = [long][System.Security.AccessControl.FileSystemRights]'FullControl' }
        @{ Name = 'Write'; R = [long][System.Security.AccessControl.FileSystemRights]'Write' }
        @{ Name = 'AppendData only'; R = [long]0x4 }
        @{ Name = 'Delete only'; R = [long]0x10000 }
        @{ Name = 'ChangePermissions only'; R = [long]0x40000 }
        @{ Name = 'TakeOwnership only'; R = [long]0x80000 }
        @{ Name = 'GENERIC_ALL'; R = [long]0x10000000 }
        @{ Name = 'GENERIC_WRITE'; R = [long]0x40000000 }
    ) { Test-FVGrantsWrite -Rights $R | Should -BeTrue }
}

Describe 'Sign-in programs against a baseline' {
    It 'records a baseline the first time, quietly' {
        $v = Get-FVSignInVerdict -Current @('Run: OneDrive = C:\x\OneDrive.exe') -Baseline $null
        $v.Status | Should -Be 'INFO'
        $v.Record | Should -BeTrue
    }
    It 'passes when nothing is new, even with many normal programs' {
        $items = @('Run: OneDrive = a', 'Run: Notion = b', 'Startup: Messages.lnk = c')
        $v = Get-FVSignInVerdict -Current $items -Baseline $items -BaselineDate '13 Nov 2026'
        $v.Status | Should -Be 'PASS'
        $v.Detail | Should -Match '3 known'
    }
    It 'warns about a new program and names it' {
        $v = Get-FVSignInVerdict -Current @('Run: OneDrive = a', 'Run: Updater = C:\Users\x\AppData\Local\Temp\u.exe') -Baseline @('Run: OneDrive = a') -BaselineDate '13 Nov 2026'
        $v.Status | Should -Be 'WARN'
        $v.Detail | Should -Match 'Run: Updater'
        $v.Detail | Should -Match '-ResetBaseline'
        $v.Record | Should -BeFalse
    }
    It 'warns when an existing entry now runs something else' {
        $v = Get-FVSignInVerdict -Current @('Run: OneDrive = C:\evil.exe') -Baseline @('Run: OneDrive = C:\x\OneDrive.exe')
        $v.Status | Should -Be 'WARN'
    }
    It 'does not warn when a program was removed' {
        (Get-FVSignInVerdict -Current @() -Baseline @('Run: Old = a')).Status | Should -Be 'PASS'
    }
    It 'fails on a replaced Folder Vault menu item, baseline or not' {
        (Get-FVSignInVerdict -Current @() -Baseline $null -Overrides @('FolderVault.Unlock')).Status | Should -Be 'FAIL'
        (Get-FVSignInVerdict -Current @() -Baseline @() -Overrides @('FolderVault.Unlock')).Status | Should -Be 'FAIL'
    }
}

Describe 'CPU wording' {
    It 'says when the average still includes start-up' {
        Get-FVCpuText -SamplePercent 0.01 -AveragePercent 0.625 -Minutes 1 | Should -Match 'includes start-up'
        Get-FVCpuText -SamplePercent 0.01 -AveragePercent 0.02 -Minutes 120 | Should -Not -Match 'start-up'
        Get-FVCpuText -SamplePercent 0.01 -AveragePercent 0.02 -Minutes 120 | Should -Match '10-second sample'
    }
}

Describe 'Audit fix A-29: a signed-out person''s registry is always closed again' {
    BeforeEach { $global:FVHU = @{ unloads = 0; openUntil = 0 } }
    It 'retries until Windows has really closed it' {
        Mock -ModuleName FolderVault.Health Invoke-FVNative { $global:FVHU.unloads++; [pscustomobject]@{ ExitCode = 1; Output = @(); Text = '' } }
        Mock -ModuleName FolderVault.Health Test-FVRegistryKey { $global:FVHU.unloads -lt 3 }
        Mock -ModuleName FolderVault.Health Start-Sleep { }
        Dismount-FVUserHive -Name 'FolderVaultHealth1' | Should -BeTrue
        $global:FVHU.unloads | Should -Be 3
    }
    It 'reports failure when it stays open' {
        Mock -ModuleName FolderVault.Health Invoke-FVNative { [pscustomobject]@{ ExitCode = 1; Output = @(); Text = 'Access is denied.' } }
        Mock -ModuleName FolderVault.Health Test-FVRegistryKey { $true }
        Mock -ModuleName FolderVault.Health Start-Sleep { }
        Dismount-FVUserHive -Name 'FolderVaultHealth1' -Attempts 4 | Should -BeFalse
        Should -Invoke -ModuleName FolderVault.Health Invoke-FVNative -Times 4 -Exactly
    }
}
