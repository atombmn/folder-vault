BeforeAll {
    $src = Join-Path $PSScriptRoot '..\..\src'
    Import-Module (Join-Path $src 'FolderVault.Common.psm1') -Force
    Import-Module (Join-Path $src 'FolderVault.Engine.psm1') -Force
    Import-Module (Join-Path $src 'FolderVault.BrokerCore.psm1') -Force

    $script:alice = [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1001'; Name = 'PC\alice'; IsElevatedAdmin = $false; ProfilePath = 'C:\Users\alice' }
    $script:bob = [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1002'; Name = 'PC\bob'; IsElevatedAdmin = $false; ProfilePath = 'C:\Users\bob' }
    $script:admin = [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-500'; Name = 'PC\itadmin'; IsElevatedAdmin = $true; ProfilePath = 'C:\Users\itadmin' }
    $script:goodPw = 'Mangoes ripen in March 2027'
    $script:paths = Get-FVPaths -DataDir 'C:\ProgramData\FolderVault' -InstallDir 'C:\Program Files\FolderVault'

    function New-TestContext {
        param([object[]]$Vaults = @(), [bool]$RegistryOk = $true, $Config)
        if ($null -eq $Config) { $Config = (ConvertTo-FVConfig ([pscustomobject]@{ SharedRoots = @('D:\Shared') })).Config }
        $script:saves = 0
        $script:clock = [datetime]::new(2026, 10, 29, 12, 0, 0, [System.DateTimeKind]::Utc)
        return New-FVBrokerContext -Config $Config -Paths $script:paths -Vaults $Vaults -RegistryOk $RegistryOk -SaveAction { param($v) $script:saves++ } -NowFn { $script:clock }
    }
    function New-TestVault {
        param([string]$Owner, [string]$Scope = 'Profile', [string]$State = 'Locked', [string]$Folder = 'C:\Users\alice\Documents\Fin')
        $id = [guid]::NewGuid().ToString()
        $v = New-FolderVaultRecord -Id $id -Name 'Fin' -FolderPath $Folder -Scope $Scope -OwnerSid $Owner -VhdxPath "C:\ProgramData\FolderVault\Vaults\$id.vhdx" -SizeGB 5 -State $State
        return $v
    }
    function Req { param([hashtable]$H) $H['v'] = 1; return $H }

    $script:log = New-Object System.Collections.Generic.List[string]
    Set-FVLogSink -Sink { param($l, $e, $m) $script:log.Add("[$l][$e] $m") }
}

AfterAll { Set-FVLogSink -Sink $null }

Describe 'Create' {
    BeforeEach {
        Mock -ModuleName FolderVault.BrokerCore Get-FVFreeBytes { 500GB }
        Mock -ModuleName FolderVault.BrokerCore New-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok'; Stage = 'Done'; Data = [pscustomobject]@{ MountPath = 'C:\ProgramData\FolderVault\Mounts\x' }; Detail = '' } }
    }
    It 'creates a profile vault and records it before the engine runs' {
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\Documents\Fin'; name = 'Fin'; password = $goodPw; sizeGB = 5; contentBytes = 1MB })
        $r.ok | Should -BeTrue
        $ctx.Vaults.Count | Should -Be 1
        $ctx.Vaults[0].State | Should -Be 'Creating'
        $ctx.Vaults[0].Scope | Should -Be 'Profile'
        $ctx.Vaults[0].OwnerSid | Should -Be $alice.Sid
        $script:saves | Should -BeGreaterOrEqual 1
    }
    It 'uses the caller identity from the pipe, not anything in the request' {
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\Documents\Fin'; name = 'Fin'; password = $goodPw; sizeGB = 5; contentBytes = 0 })
        $r.ok | Should -BeFalse
        $r.code | Should -Be 'PathOtherUser'
        Should -Invoke -ModuleName FolderVault.BrokerCore New-FolderVaultContainer -Times 0
    }
    It 'refuses <Case>' -ForEach @(
        @{ Case = 'system folder'; P = 'C:\Windows\Temp\x'; Code = 'PathNotAllowed' }
        @{ Case = 'own AppData'; P = 'C:\Users\alice\AppData\Roaming\x'; Code = 'PathNotAllowed' }
        @{ Case = 'own data dir'; P = 'C:\ProgramData\FolderVault\Mounts'; Code = 'PathNotAllowed' }
        @{ Case = 'traversal'; P = 'C:\Users\alice\..\bob\Documents'; Code = 'PathInvalid' }
        @{ Case = 'UNC'; P = '\\pc2\c$\Users'; Code = 'PathInvalid' }
        @{ Case = 'USB stick'; P = 'E:\Payroll'; Code = 'PathNotLocalDisk' }
        @{ Case = 'another person (profile elsewhere)'; P = 'D:\Profiles\carol\x'; Code = 'PathOtherUser' }
        @{ Case = 'the whole OneDrive'; P = 'C:\Users\alice\OneDrive'; Code = 'PathWholeFolder' }
    ) {
        Mock -ModuleName FolderVault.BrokerCore Get-FVMachineLayout { [pscustomobject]@{ ProfilesDirectory = 'C:\Users'; Profiles = @('C:\Users\alice', 'C:\Users\bob', 'D:\Profiles\carol'); FixedDrives = @('C', 'D') } }
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = $P; name = 'X'; password = $goodPw; sizeGB = 5; contentBytes = 0 })
        $r.code | Should -Be $Code
        $ctx.Vaults.Count | Should -Be 0
    }
    It 'enforces password policy server-side' {
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\Documents\Fin'; name = 'Fin'; password = 'short'; sizeGB = 5; contentBytes = 0 })
        $r.code | Should -Be 'PasswordPolicy'
        $r.data.problems | Should -Contain 'TooShort'
    }
    It 'refuses overlapping vaults' {
        $existing = New-TestVault -Owner $alice.Sid -Folder 'C:\Users\alice\Documents\Fin'
        $ctx = New-TestContext -Vaults @($existing)
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\Documents\Fin\Q1'; name = 'Q1'; password = $goodPw; sizeGB = 5; contentBytes = 0 })
        $r.code | Should -Be 'PathOverlaps'
    }
    It 'creates shared vaults inside shared roots' {
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'Create'; path = 'D:\Shared\Finance'; name = 'Finance'; password = $goodPw; sizeGB = 5; contentBytes = 0 })
        $r.ok | Should -BeTrue
        $ctx.Vaults[0].Scope | Should -Be 'Shared'
    }
    It 'removes the record when the engine fails' {
        Mock -ModuleName FolderVault.BrokerCore New-FolderVaultContainer { [pscustomobject]@{ Ok = $false; Code = 'EscrowMissing'; Stage = 'Escrow'; Data = $null; Detail = 'Missing' } }
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\Documents\Fin'; name = 'Fin'; password = $goodPw; sizeGB = 5; contentBytes = 0 })
        $r.code | Should -Be 'EscrowMissing'
        $ctx.Vaults.Count | Should -Be 0
    }
    It 'refuses when there is not enough disk space' {
        Mock -ModuleName FolderVault.BrokerCore Get-FVFreeBytes { 1GB }
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\Documents\Fin'; name = 'Fin'; password = $goodPw; sizeGB = 5; contentBytes = 2GB })
        $r.code | Should -Be 'InsufficientSpace'
    }
}

Describe 'Visibility and authorisation' {
    It 'hides other users'' profile vaults and shows shared ones' {
        $a = New-TestVault -Owner $alice.Sid
        $s = New-TestVault -Owner $alice.Sid -Scope Shared -Folder 'D:\Shared\Fin'
        $ctx = New-TestContext -Vaults @($a, $s)
        $list = (Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'List' })).data.vaults
        @($list).Count | Should -Be 1
        $list[0].scope | Should -Be 'Shared'
    }
    It 'answers NotFound for another user''s vault (no existence oracle)' {
        Mock -ModuleName FolderVault.BrokerCore Open-FolderVaultContainer { throw 'must not be called' }
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        foreach ($op in @(@{ op = 'Unlock'; id = $a.Id; password = 'x' }, @{ op = 'Remove'; id = $a.Id; password = 'x' }, @{ op = 'Lock'; id = $a.Id; force = $true }, @{ op = 'ChangePassword'; id = $a.Id; password = 'x'; newPassword = 'y' })) {
            (Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req $op)).code | Should -Be 'NotFound'
        }
        (Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'Unlock'; id = [guid]::NewGuid().ToString(); password = 'x' })).code | Should -Be 'NotFound'
    }
    It 'lets any user unlock a shared vault' {
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime { [pscustomobject]@{ Exists = $true; Attached = $false; Unlocked = $false; Mounted = $false } }
        Mock -ModuleName FolderVault.BrokerCore Open-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok'; Data = [pscustomobject]@{ MountPath = 'M' } } }
        $s = New-TestVault -Owner $alice.Sid -Scope Shared -Folder 'D:\Shared\Fin'
        $ctx = New-TestContext -Vaults @($s)
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'Unlock'; id = $s.Id; password = $goodPw })
        $r.ok | Should -BeTrue
        $s.UnlockedBySid | Should -Be $bob.Sid
    }
    It 'only the owner can finalise an unfinished vault' {
        $s = New-TestVault -Owner $alice.Sid -Scope Shared -State Creating -Folder 'D:\Shared\Fin'
        $ctx = New-TestContext -Vaults @($s)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'FinalizeCreate'; id = $s.Id })).code | Should -Be 'NotAuthorized'
    }
    It 'refuses admin operations to non-elevated callers and logs it' {
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        $script:log.Clear()
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'AdminList' })).code | Should -Be 'NotAuthorized'
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'AdminReset'; id = $a.Id; recoveryKey = '111111-111111-111111-111111-111111-111111-111111-111111'; newPassword = $goodPw })).code | Should -Be 'NotAuthorized'
        ($script:log -join "`n") | Should -Match 'AdminRefused'
    }
}

Describe 'Password guessing' {
    BeforeEach {
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime { [pscustomobject]@{ Exists = $true; Attached = $false; Unlocked = $false; Mounted = $false } }
        Mock -ModuleName FolderVault.BrokerCore Open-FolderVaultContainer {
            if ($Password -eq $script:goodPw) { return [pscustomobject]@{ Ok = $true; Code = 'Ok'; Data = [pscustomobject]@{ MountPath = 'M' } } }
            return [pscustomobject]@{ Ok = $false; Code = 'BadPassword'; Stage = 'Unlock'; Data = $null; Detail = '' }
        }
    }
    It 'backs off, then locks out, persisting the counters' {
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        for ($i = 1; $i -le 3; $i++) {
            (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = "wrong$i" })).code | Should -Be 'BadPassword'
        }
        # 4th attempt immediately: throttled, engine not called.
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = $goodPw })).code | Should -Be 'Throttled'
        Should -Invoke -ModuleName FolderVault.BrokerCore Open-FolderVaultContainer -Times 3 -Exactly

        for ($i = 4; $i -le 10; $i++) {
            $script:clock = $script:clock.AddSeconds(61)
            (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = "wrong$i" })).code | Should -Be 'BadPassword'
        }
        $script:clock = $script:clock.AddSeconds(61)
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = $goodPw })
        $r.code | Should -Be 'LockedOut'
        $a.FailedCount | Should -Be 10
        $a.LockoutUntilUtc | Should -Not -BeNullOrEmpty

        $script:clock = $script:clock.AddMinutes(16)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = $goodPw })).ok | Should -BeTrue
        $a.FailedCount | Should -Be 0
        $a.State | Should -Be 'Unlocked'
    }
    It 'shares the counter across operations (change password, remove)' {
        Mock -ModuleName FolderVault.BrokerCore Set-FolderVaultPasswordCore { [pscustomobject]@{ Ok = $false; Code = 'BadPassword' } }
        Mock -ModuleName FolderVault.BrokerCore Remove-FolderVaultContainer { [pscustomobject]@{ Ok = $false; Code = 'BadPassword' } }
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        [void](Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'ChangePassword'; id = $a.Id; password = 'w1'; newPassword = $goodPw }))
        [void](Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Remove'; id = $a.Id; password = 'w2' }))
        [void](Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = 'w3' }))
        $a.FailedCount | Should -Be 3
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Remove'; id = $a.Id; password = 'w4' })).code | Should -Be 'Throttled'
    }
    It 'never writes a password to the log' {
        $script:log.Clear()
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        [void](Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = 'Zebra-Secret-998877' }))
        $script:clock = $script:clock.AddSeconds(61)
        [void](Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = $goodPw }))
        $all = $script:log -join "`n"
        $all | Should -Match 'WrongPassword'
        $all | Should -Not -Match 'Zebra'
        $all | Should -Not -Match 'Mangoes'
    }
}

Describe 'Unlock, lock and state rules' {
    It 'returns AlreadyUnlocked without asking the engine to unlock again' {
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime { [pscustomobject]@{ Exists = $true; Attached = $true; Unlocked = $true; Mounted = $true } }
        Mock -ModuleName FolderVault.BrokerCore Open-FolderVaultContainer { throw 'must not be called' }
        $a = New-TestVault -Owner $alice.Sid -State Unlocked
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = 'anything' })).code | Should -Be 'AlreadyUnlocked'
    }
    It 'fully locks an inconsistent (attached, not mounted) vault and then demands the password' {
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime { [pscustomobject]@{ Exists = $true; Attached = $true; Unlocked = $true; Mounted = $false } }
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok' } }
        Mock -ModuleName FolderVault.BrokerCore Open-FolderVaultContainer { [pscustomobject]@{ Ok = $false; Code = 'BadPassword' } }
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = 'wrong' })).code | Should -Be 'BadPassword'
        Should -Invoke -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer -Times 1 -ParameterFilter { $Force -eq $true }
    }
    It 'refuses vaults needing attention' {
        $a = New-TestVault -Owner $alice.Sid -State NeedsAttention
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = $goodPw })).code | Should -Be 'NeedsAttention'
    }
    It 'reports FilesInUse and keeps state when a non-forced lock fails' {
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { [pscustomobject]@{ Ok = $false; Code = 'FilesInUse' } }
        $a = New-TestVault -Owner $alice.Sid -State Unlocked
        $a.UnlockedBySid = $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Lock'; id = $a.Id; force = $false })).code | Should -Be 'FilesInUse'
        $a.State | Should -Be 'Unlocked'
    }
    It 'LockAll locks only what the caller unlocked' {
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok' } }
        $a = New-TestVault -Owner $alice.Sid -State Unlocked; $a.UnlockedBySid = $alice.Sid
        $s = New-TestVault -Owner $alice.Sid -Scope Shared -State Unlocked -Folder 'D:\Shared\X'; $s.UnlockedBySid = $bob.Sid
        $ctx = New-TestContext -Vaults @($a, $s)
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'LockAll'; force = $true })
        @($r.data.locked) | Should -Be @($a.Id)
        $s.State | Should -Be 'Unlocked'
    }
    It 'change password and remove need a locked vault' {
        $a = New-TestVault -Owner $alice.Sid -State Unlocked
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'ChangePassword'; id = $a.Id; password = $goodPw; newPassword = 'Pineapples grow slowly 2028' })).code | Should -Be 'NotLocked'
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Remove'; id = $a.Id; password = $goodPw })).code | Should -Be 'NotLocked'
    }
    It 'checks the new password policy before touching the vault' {
        Mock -ModuleName FolderVault.BrokerCore Set-FolderVaultPasswordCore { throw 'must not be called' }
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'ChangePassword'; id = $a.Id; password = $goodPw; newPassword = 'password123' })).code | Should -Be 'PasswordPolicy'
    }
    It 'turns unexpected engine exceptions into InternalError' {
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime { throw 'disk exploded' }
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Unlock'; id = $a.Id; password = $goodPw })).code | Should -Be 'InternalError'
    }
    It 'removes the record after a successful delete' {
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime { [pscustomobject]@{ Exists = $true; Attached = $false; Unlocked = $false; Mounted = $false } }
        Mock -ModuleName FolderVault.BrokerCore Remove-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok' } }
        $a = New-TestVault -Owner $alice.Sid
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Remove'; id = $a.Id; password = $goodPw })).ok | Should -BeTrue
        $ctx.Vaults.Count | Should -Be 0
    }
}

Describe 'Admin reset' {
    It 'requires a well-formed recovery key, rotates via the engine and clears lockout' {
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime { [pscustomobject]@{ Exists = $true; Attached = $false; Unlocked = $false; Mounted = $false } }
        Mock -ModuleName FolderVault.BrokerCore Set-FolderVaultPasswordCore { [pscustomobject]@{ Ok = $true; Code = 'Ok' } }
        $a = New-TestVault -Owner $alice.Sid -State NeedsAttention
        $a.FailedCount = 10; $a.LockoutUntilUtc = '2026-10-29T12:10:00.0000000Z'
        $ctx = New-TestContext -Vaults @($a)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $admin -Request (Req @{ op = 'AdminReset'; id = $a.Id; recoveryKey = '12345'; newPassword = $goodPw })).code | Should -Be 'BadRecoveryKey'
        # Locked out vaults stay locked out, even for admins: wait it out.
        (Invoke-FVBrokerRequest -Context $ctx -Caller $admin -Request (Req @{ op = 'AdminReset'; id = $a.Id; recoveryKey = '111111-222222-333333-444444-555555-666666-777777-888888'; newPassword = $goodPw })).code | Should -Be 'LockedOut'
        $script:clock = $script:clock.AddMinutes(11)
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $admin -Request (Req @{ op = 'AdminReset'; id = $a.Id; recoveryKey = '111111-222222-333333-444444-555555-666666-777777-888888'; newPassword = $goodPw })
        $r.ok | Should -BeTrue
        $a.State | Should -Be 'Locked'
        $a.FailedCount | Should -Be 0
        Should -Invoke -ModuleName FolderVault.BrokerCore Set-FolderVaultPasswordCore -Times 1 -ParameterFilter { $RecoveryKey -like '111111-*' }
    }
}

Describe 'Watchdog auto-lock' {
    BeforeEach {
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok' } }
    }
    It 'locks on <Reason>' -ForEach @(
        @{ Reason = 'ScreenLocked'; States = @{ 'S-1-5-21-1-2-3-1001' = [pscustomobject]@{ Sessions = 1; LockedSessions = 1 } }; Minutes = 1 }
        @{ Reason = 'SignedOut'; States = @{ }; Minutes = 1 }
        @{ Reason = 'Timeout'; States = @{ 'S-1-5-21-1-2-3-1001' = [pscustomobject]@{ Sessions = 1; LockedSessions = 0 } }; Minutes = 300 }
    ) {
        $a = New-TestVault -Owner $alice.Sid -State Unlocked
        $ctx = New-TestContext -Vaults @($a)
        $a.UnlockedBySid = $alice.Sid
        $a.UnlockedAtUtc = ConvertTo-FVIso ($script:clock.AddMinutes(-$Minutes))
        $script:log.Clear()
        Invoke-FVBrokerWatchdog -Context $ctx -SessionStates $States
        $a.State | Should -Be 'Locked'
        ($script:log -join "`n") | Should -Match "reason=$Reason"
        Should -Invoke -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer -Times 1 -ParameterFilter { $Force -eq $true }
    }
    It 'leaves an active session alone' {
        $a = New-TestVault -Owner $alice.Sid -State Unlocked
        $ctx = New-TestContext -Vaults @($a)
        $a.UnlockedBySid = $alice.Sid; $a.UnlockedAtUtc = ConvertTo-FVIso ($script:clock.AddMinutes(-5))
        Invoke-FVBrokerWatchdog -Context $ctx -SessionStates @{ 'S-1-5-21-1-2-3-1001' = [pscustomobject]@{ Sessions = 1; LockedSessions = 0 } }
        $a.State | Should -Be 'Unlocked'
    }
    It 'applies only the timeout when session information is unavailable' {
        $a = New-TestVault -Owner $alice.Sid -State Unlocked
        $ctx = New-TestContext -Vaults @($a)
        $a.UnlockedBySid = $alice.Sid; $a.UnlockedAtUtc = ConvertTo-FVIso ($script:clock.AddMinutes(-5))
        Invoke-FVBrokerWatchdog -Context $ctx -SessionStates $null
        $a.State | Should -Be 'Unlocked'
        $script:clock = $script:clock.AddMinutes(300)
        Invoke-FVBrokerWatchdog -Context $ctx -SessionStates $null
        $a.State | Should -Be 'Locked'
    }
    It 'respects ForceDismountOnAutoLock = false' {
        $cfg = (ConvertTo-FVConfig ([pscustomobject]@{ ForceDismountOnAutoLock = $false })).Config
        $a = New-TestVault -Owner $alice.Sid -State Unlocked
        $ctx = New-TestContext -Vaults @($a) -Config $cfg
        $a.UnlockedBySid = $alice.Sid; $a.UnlockedAtUtc = ConvertTo-FVIso $script:clock
        Invoke-FVBrokerWatchdog -Context $ctx -SessionStates @{}
        Should -Invoke -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer -Times 1 -ParameterFilter { $Force -eq $false }
    }
}

Describe 'Safe mode when the registry is damaged' {
    It 'refuses every vault operation and never saves' {
        Mock -ModuleName FolderVault.BrokerCore New-FolderVaultContainer { throw 'must not be called' }
        $ctx = New-TestContext -RegistryOk $false
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Ping' })).ok | Should -BeTrue
        foreach ($r in @(@{ op = 'List' }, @{ op = 'Create'; path = 'C:\Users\alice\Documents\F'; name = 'F'; password = $goodPw; sizeGB = 5; contentBytes = 0 })) {
            (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req $r)).code | Should -Be 'RegistryCorrupt'
        }
        Invoke-FVBrokerWatchdog -Context $ctx -SessionStates @{}
        $script:saves | Should -Be 0
    }
}

Describe 'Start-up reconciliation' {
    It 'locks everything and flags missing containers' {
        $a = New-TestVault -Owner $alice.Sid -State Unlocked; $a.UnlockedBySid = $alice.Sid
        $b = New-TestVault -Owner $bob.Sid -State Locked -Folder 'C:\Users\bob\Documents\X'
        $script:aid = $a.Id
        Mock -ModuleName FolderVault.BrokerCore Get-FolderVaultRuntime {
            if ($Record.Id -eq $script:aid) { return [pscustomobject]@{ Exists = $true; Attached = $true; Unlocked = $true; Mounted = $true } }
            return [pscustomobject]@{ Exists = $false; Attached = $false; Unlocked = $false; Mounted = $false }
        }
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok' } }
        Mock -ModuleName FolderVault.BrokerCore New-FVUnlockShortcut { $true }
        $ctx = New-TestContext -Vaults @($a, $b)
        Initialize-FVBrokerState -Context $ctx
        Should -Invoke -ModuleName FolderVault.BrokerCore New-FVUnlockShortcut -Times 1
        $a.State | Should -Be 'Locked'
        $a.UnlockedBySid | Should -BeNullOrEmpty
        $b.State | Should -Be 'NeedsAttention'
        Should -Invoke -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer -Times 1
    }
}

Describe 'Audit fix A-02: only the unlocker may force-lock' {
    It 'downgrades a forced lock from another user to a normal lock' {
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { [pscustomobject]@{ Ok = $false; Code = 'FilesInUse' } }
        $s = New-TestVault -Owner $alice.Sid -Scope Shared -State Unlocked -Folder 'D:\Shared\X'; $s.UnlockedBySid = $alice.Sid
        $ctx = New-TestContext -Vaults @($s)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'Lock'; id = $s.Id; force = $true })).code | Should -Be 'FilesInUse'
        Should -Invoke -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer -Times 1 -ParameterFilter { $Force -eq $false }
    }
    It 'lets the unlocker force it' {
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok' } }
        $s = New-TestVault -Owner $alice.Sid -Scope Shared -State Unlocked -Folder 'D:\Shared\X'; $s.UnlockedBySid = $alice.Sid
        $ctx = New-TestContext -Vaults @($s)
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Lock'; id = $s.Id; force = $true })).ok | Should -BeTrue
        Should -Invoke -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer -Times 1 -ParameterFilter { $Force -eq $true }
    }
}


Describe '0.2: the service rests while everything is locked' {
    It 'Test-FVAnyUnlocked is false for locked or broken vaults and true for open or unfinished ones' {
        Test-FVAnyUnlocked -Context (New-TestContext -Vaults @((New-TestVault -Owner $alice.Sid), (New-TestVault -Owner $bob.Sid -State NeedsAttention -Folder 'C:\Users\bob\Documents\X'))) | Should -BeFalse
        Test-FVAnyUnlocked -Context (New-TestContext -Vaults @((New-TestVault -Owner $alice.Sid -State Unlocked))) | Should -BeTrue
        Test-FVAnyUnlocked -Context (New-TestContext -Vaults @((New-TestVault -Owner $alice.Sid -State Creating))) | Should -BeTrue
        Test-FVAnyUnlocked -Context (New-TestContext -RegistryOk $false) | Should -BeFalse
    }
    It 'the watchdog does no work at all when nothing is unlocked' {
        Mock -ModuleName FolderVault.BrokerCore Close-FolderVaultContainer { throw 'must not be called' }
        $ctx = New-TestContext -Vaults @((New-TestVault -Owner $alice.Sid))
        $script:saves = 0
        { Invoke-FVBrokerWatchdog -Context $ctx -SessionStates @{} } | Should -Not -Throw
        $script:saves | Should -Be 0
    }
}

Describe '0.3.0: personal folders outside the user folder' {
    BeforeEach {
        Mock -ModuleName FolderVault.BrokerCore Get-FVFreeBytes { 500GB }
        Mock -ModuleName FolderVault.BrokerCore New-FolderVaultContainer { [pscustomobject]@{ Ok = $true; Code = 'Ok'; Stage = 'Done'; Data = [pscustomobject]@{ MountPath = 'C:\ProgramData\FolderVault\Mounts\x' }; Detail = '' } }
        Mock -ModuleName FolderVault.BrokerCore Get-FVMachineLayout { [pscustomobject]@{ ProfilesDirectory = 'C:\Users'; Profiles = @('C:\Users\alice', 'C:\Users\bob'); FixedDrives = @('C', 'D') } }
    }
    It 'creates D:\Accounts as a Local vault that only its owner can unlock' {
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'D:\Accounts'; name = 'Accounts'; password = $goodPw; sizeGB = 5; contentBytes = 1MB })
        $r.ok | Should -BeTrue
        $v = $ctx.Vaults[0]
        $v.Scope | Should -Be 'Local'
        $v.State = 'Locked'
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'Unlock'; id = $v.Id; password = $goodPw })
        $r.ok | Should -BeFalse
        @('NotFound', 'NotAuthorized') | Should -Contain $r.code
        $l = Invoke-FVBrokerRequest -Context $ctx -Caller $bob -Request (Req @{ op = 'List' })
        @($l.data.vaults).Count | Should -Be 0
    }
    It 'refuses outside the user folder when IT switched it off, and tells the window' {
        $cfg = (ConvertTo-FVConfig ([pscustomobject]@{ AllowFoldersOutsideProfile = $false })).Config
        $ctx = New-TestContext -Config $cfg
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'D:\Accounts'; name = 'Accounts'; password = $goodPw; sizeGB = 5; contentBytes = 1MB })
        $r.code | Should -Be 'PathOutsideProfile'
        $p = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'GetPolicy' })
        $p.data.allowFoldersOutsideProfile | Should -BeFalse
    }
    It 'accepts a OneDrive folder' {
        $ctx = New-TestContext
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\OneDrive\Documents\VaultTest'; name = 'VaultTest'; password = $goodPw; sizeGB = 5; contentBytes = 1MB })
        $r.ok | Should -BeTrue
        $ctx.Vaults[0].Scope | Should -Be 'Profile'
    }
}

Describe 'Local weak words reach the window and the password check' {
    It 'GetPolicy sends them, and Create refuses a password built on one' {
        $cfg = (ConvertTo-FVConfig ([pscustomobject]@{ LocalWeakWords = @('springfield') })).Config
        $ctx = New-TestContext -Config $cfg
        (Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'GetPolicy' })).data.localWeakWords | Should -Be @('springfield')
        Mock -ModuleName FolderVault.BrokerCore Get-FVFreeBytes { 500GB }
        Mock -ModuleName FolderVault.BrokerCore New-FolderVaultContainer { throw 'must not be called' }
        $r = Invoke-FVBrokerRequest -Context $ctx -Caller $alice -Request (Req @{ op = 'Create'; path = 'C:\Users\alice\Documents\Pay'; name = 'Pay'; password = 'Springfield@2026'; sizeGB = 5; contentBytes = 1MB })
        $r.ok | Should -BeFalse
        $r.code | Should -Be 'PasswordPolicy'
        $r.data.problems | Should -Contain 'Common'
    }
}
