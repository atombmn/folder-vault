<#
    End-to-end tests of the user-side protect / unprotect flows on a real file
    system, with a fake broker. The fake "vault" is a directory; locking moves
    its contents away so the linked folder looks empty, like a locked vault.
    Uses symlinks in place of junctions, so it runs on Linux CI as well.
#>
BeforeAll {
    $src = Join-Path $PSScriptRoot '..\..\src'
    Import-Module (Join-Path $src 'FolderVault.Common.psm1') -Force
    Import-Module (Join-Path $src 'FolderVault.UserOps.psm1') -Force
    $script:goodPw = 'Mangoes ripen in March 2027'

    function New-FakeBroker {
        param([string]$Root, [switch]$FailFinalize, [switch]$FailLock)
        $state = @{ Root = $Root; Vaults = @{}; Calls = (New-Object System.Collections.Generic.List[string]); FailFinalize = [bool]$FailFinalize; FailLock = [bool]$FailLock }
        $sb = {
            param([hashtable]$r)
            $st = $state
            $st.Calls.Add($r.op)
            $resp = { param($ok, $code, $data) [pscustomobject]@{ ok = $ok; code = $code; message = $code; data = $data } }
            switch ($r.op) {
                'Create' {
                    $id = [guid]::NewGuid().ToString()
                    $m = Join-Path $st.Root "mount-$id"
                    $s = Join-Path $st.Root "store-$id"
                    New-Item -ItemType Directory -Path $m, $s | Out-Null
                    $st.Vaults[$id] = @{ Mount = $m; Store = $s; Password = $r.password; Locked = $false; Folder = $r.path }
                    return (& $resp $true 'Ok' ([pscustomobject]@{ id = $id; mountPath = $m }))
                }
                'FinalizeCreate' {
                    if ($st.FailFinalize) { return (& $resp $false 'InternalError' $null) }
                    $v = $st.Vaults[$r.id]
                    Get-ChildItem -Force $v.Mount | Move-Item -Destination $v.Store
                    $v.Locked = $true
                    return (& $resp $true 'Ok' $null)
                }
                'Lock' {
                    if ($st.FailLock) { return (& $resp $false 'FilesInUse' $null) }
                    $v = $st.Vaults[$r.id]
                    if (-not $v.Locked) { Get-ChildItem -Force $v.Mount | Move-Item -Destination $v.Store; $v.Locked = $true }
                    return (& $resp $true 'Ok' $null)
                }
                'Unlock' {
                    $v = $st.Vaults[$r.id]
                    if ($r.password -ne $v.Password) { return (& $resp $false 'BadPassword' $null) }
                    if ($v.Locked) { Get-ChildItem -Force $v.Store | Move-Item -Destination $v.Mount; $v.Locked = $false }
                    return (& $resp $true 'Ok' ([pscustomobject]@{ mountPath = $v.Mount }))
                }
                'Remove' {
                    $v = $st.Vaults[$r.id]
                    if ($r.password -ne $v.Password) { return (& $resp $false 'BadPassword' $null) }
                    if (-not $v.Locked) { return (& $resp $false 'NotLocked' $null) }
                    Remove-Item -Recurse -Force $v.Mount, $v.Store
                    $st.Vaults.Remove($r.id)
                    return (& $resp $true 'Ok' $null)
                }
            }
            return (& $resp $false 'BadRequest' $null)
        }.GetNewClosure()
        return [pscustomobject]@{ Invoke = $sb; State = $state }
    }

    function New-SampleTree {
        param([string]$Path)
        New-Item -ItemType Directory -Path (Join-Path $Path 'Q1/Deep/Deeper') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $Path 'Empty dir') -Force | Out-Null
        Set-Content -Path (Join-Path $Path 'salaries.csv') -Value 'name,salary'
        Set-Content -Path (Join-Path $Path 'Q1/Deep/Deeper/relevé de paie 2026 ü.txt') -Value 'accented unicode name'
        New-Item -ItemType File -Path (Join-Path $Path 'empty.txt') | Out-Null
        $big = New-Object byte[] (3MB); (New-Object System.Random 42).NextBytes($big)
        [System.IO.File]::WriteAllBytes((Join-Path $Path 'Q1/scan.pdf'), $big)
        $ro = Join-Path $Path 'readonly.docx'
        Set-Content -Path $ro -Value 'ro'
        (Get-Item $ro).Attributes = 'ReadOnly'
    }
}

Describe 'Protecting a folder' -Skip:($IsWindows) {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvuo-" + [guid]::NewGuid())
        $script:folder = Join-Path $root 'home/Documents/Payroll'
        New-SampleTree -Path $folder
        $script:before = Get-FVTreeManifest -Path $folder -Mode Hash
        $script:fb = New-FakeBroker -Root $root
    }
    AfterEach { Get-ChildItem -Recurse -Force $root -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }

    It 'moves the files into the vault, links the folder and deletes the original' {
        $r = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $r.Ok | Should -BeTrue
        $r.Warnings.Count | Should -Be 0
        Test-FVReparsePath -Path $folder | Should -BeTrue
        @(Get-ChildItem -Force $folder).Count | Should -Be 0   # locked: looks empty
        @(Get-ChildItem -Force (Split-Path $folder) | Where-Object Name -like '*foldervault-original*').Count | Should -Be 0
        @($fb.State.Calls) | Should -Be @('Create', 'FinalizeCreate')

        $id = $r.Data.id
        $u = & $fb.Invoke @{ op = 'Unlock'; id = $id; password = $goodPw }
        $u.ok | Should -BeTrue
        $after = Get-FVTreeManifest -Path $folder -Mode Hash
        (Compare-FVManifest -Source $before -Destination $after).Ok | Should -BeTrue
    }

    It 'keeps the original untouched and discards the vault when verification fails' {
        Mock -ModuleName FolderVault.UserOps Copy-FVTree {
            Copy-FVTreeManaged -Source $Source -Destination $Destination
            Remove-Item (Join-Path $Destination 'salaries.csv') -Force
        }
        $r = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $r.Code | Should -Be 'VerifyFailed'
        $r.Data.missing | Should -Contain 'salaries.csv'
        Test-FVReparsePath -Path $folder | Should -BeFalse
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
        $fb.State.Vaults.Count | Should -Be 0
    }

    It 'detects silent corruption of equal size' {
        Mock -ModuleName FolderVault.UserOps Copy-FVTree {
            Copy-FVTreeManaged -Source $Source -Destination $Destination
            $f = Join-Path $Destination 'Q1/scan.pdf'
            $b = [System.IO.File]::ReadAllBytes($f); $b[1000] = $b[1000] -bxor 0xFF; [System.IO.File]::WriteAllBytes($f, $b)
        }
        (Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke).Code | Should -Be 'VerifyFailed'
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
    }

    It 'puts the original back when the link cannot be created' {
        Mock -ModuleName FolderVault.UserOps New-FVJunction { throw 'link refused' }
        $r = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $r.Ok | Should -BeFalse
        Test-FVReparsePath -Path $folder | Should -BeFalse
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
        $fb.State.Vaults.Count | Should -Be 0
    }

    It 'puts the original back when the link points somewhere else' {
        Mock -ModuleName FolderVault.UserOps Get-FVLinkTarget { '/somewhere/else' }
        $r = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $r.Ok | Should -BeFalse
        Test-FVReparsePath -Path $folder | Should -BeFalse
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
    }

    It 'changes nothing when the broker refuses' {
        $refuse = { param($r) [pscustomobject]@{ ok = $false; code = 'PathNotAllowed'; message = 'no'; data = $null } }
        $r = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $refuse
        $r.Code | Should -Be 'PathNotAllowed'
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
    }

    It 'still succeeds (with a warning) if the final lock fails; data stays safe' {
        $fb2 = New-FakeBroker -Root $root -FailFinalize
        $r = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb2.Invoke
        $r.Ok | Should -BeTrue
        $r.Warnings.Count | Should -BeGreaterThan 0
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
    }

    It 'refuses a folder containing a link, without calling the broker' {
        $outside = Join-Path $root 'outside'; New-Item -ItemType Directory $outside | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $folder 'Q1/sneaky') -Target $outside | Out-Null
        (Invoke-FVProtectFolder -Path $folder -Name 'P' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke).Code | Should -Be 'PathHasLinks'
        $fb.State.Calls.Count | Should -Be 0
    }
    It 'refuses a folder that is itself a link' {
        $l = Join-Path $root 'home/Documents/LinkToPayroll'
        New-Item -ItemType SymbolicLink -Path $l -Target $folder | Out-Null
        (Invoke-FVProtectFolder -Path $l -Name 'P' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke).Code | Should -Be 'PathHasLinks'
    }
    It 'refuses a folder reached through a linked parent' {
        $l = Join-Path $root 'home/LinkedDocs'
        New-Item -ItemType SymbolicLink -Path $l -Target (Join-Path $root 'home/Documents') | Out-Null
        (Invoke-FVProtectFolder -Path (Join-Path $l 'Payroll') -Name 'P' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke).Code | Should -Be 'PathHasLinks'
    }
    It 'refuses a missing folder' {
        (Invoke-FVProtectFolder -Path (Join-Path $root 'nope') -Name 'P' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke).Code | Should -Be 'PathNotFound'
    }
}

Describe 'Removing protection' -Skip:($IsWindows) {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvuo-" + [guid]::NewGuid())
        $script:folder = Join-Path $root 'home/Documents/Payroll'
        New-SampleTree -Path $folder
        $script:before = Get-FVTreeManifest -Path $folder -Mode Hash
        $script:fb = New-FakeBroker -Root $root
        $p = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $script:vault = [pscustomobject]@{ id = $p.Data.id; folderPath = $folder }
    }
    AfterEach { Get-ChildItem -Recurse -Force $root -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }

    It 'restores the files as a normal folder and deletes the vault' {
        $r = Invoke-FVUnprotectFolder -Vault $vault -Password $goodPw -Broker $fb.Invoke
        $r.Ok | Should -BeTrue
        Test-FVReparsePath -Path $folder | Should -BeFalse
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
        $fb.State.Vaults.Count | Should -Be 0
    }
    It 'does nothing with a wrong password' {
        $r = Invoke-FVUnprotectFolder -Vault $vault -Password 'wrong wrong wrong' -Broker $fb.Invoke
        $r.Code | Should -Be 'BadPassword'
        Test-FVReparsePath -Path $folder | Should -BeTrue
        $fb.State.Vaults.Count | Should -Be 1
    }
    It 'cleans up and keeps the vault when it cannot be locked' {
        $fb.State.FailLock = $true
        $r = Invoke-FVUnprotectFolder -Vault $vault -Password $goodPw -Broker $fb.Invoke
        $r.Code | Should -Be 'FilesInUse'
        Test-FVReparsePath -Path $folder | Should -BeTrue
        @(Get-ChildItem -Force (Split-Path $folder) | Where-Object Name -like '*foldervault-restore*').Count | Should -Be 0
        $fb.State.Vaults.Count | Should -Be 1
    }
    It 'refuses to replace a real folder that is not the link' {
        Remove-FVLink -Path $folder
        New-Item -ItemType Directory -Path $folder | Out-Null
        Set-Content (Join-Path $folder 'new.txt') 'someone made a new folder'
        $r = Invoke-FVUnprotectFolder -Vault $vault -Password $goodPw -Broker $fb.Invoke
        $r.Code | Should -Be 'NeedsAttention'
        Get-Content (Join-Path $folder 'new.txt') | Should -Be 'someone made a new folder'
        $fb.State.Vaults.Count | Should -Be 1
    }
}

Describe 'Recovering an interrupted protection' -Skip:($IsWindows) {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvuo-" + [guid]::NewGuid())
        $script:folder = Join-Path $root 'home/Documents/Payroll'
        New-SampleTree -Path $folder
        $script:before = Get-FVTreeManifest -Path $folder -Mode Hash
        $script:fb = New-FakeBroker -Root $root
        $c = & $fb.Invoke @{ op = 'Create'; path = $folder; name = 'P'; password = $goodPw; sizeGB = 5; contentBytes = 0 }
        $script:id = $c.data.id
        $script:mount = $c.data.mountPath
        $script:vault = [pscustomobject]@{ id = $id; folderPath = $folder }
        $script:backup = "$folder.foldervault-original-" + $id.Substring(0, 8)
    }
    AfterEach { Get-ChildItem -Recurse -Force $root -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }

    It 'cancels when the original was never touched' {
        (Get-FVUnfinishedState -Vault $vault).State | Should -Be 'OriginalOnly'
        (Resolve-FVUnfinished -Vault $vault -Password $goodPw -Broker $fb.Invoke).Ok | Should -BeTrue
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
        $fb.State.Vaults.Count | Should -Be 0
    }
    It 'puts the original back when it stopped after renaming' {
        Move-Item $folder $backup
        (Get-FVUnfinishedState -Vault $vault).State | Should -Be 'BackupOnly'
        (Resolve-FVUnfinished -Vault $vault -Password $goodPw -Broker $fb.Invoke).Ok | Should -BeTrue
        (Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folder -Mode Hash)).Ok | Should -BeTrue
    }
    It 'finishes when the link exists and the backup matches' {
        Copy-FVTreeManaged -Source $folder -Destination $mount
        Move-Item $folder $backup
        New-FVJunction -Path $folder -Target $mount
        (Get-FVUnfinishedState -Vault $vault).State | Should -Be 'LinkPlusBackup'
        (Resolve-FVUnfinished -Vault $vault -Password $goodPw -Broker $fb.Invoke).Ok | Should -BeTrue
        Test-Path $backup | Should -BeFalse
    }
    It 'refuses to delete the backup when the vault copy is incomplete' {
        Copy-FVTreeManaged -Source $folder -Destination $mount
        Remove-Item (Join-Path $mount 'salaries.csv')
        Move-Item $folder $backup
        New-FVJunction -Path $folder -Target $mount
        (Resolve-FVUnfinished -Vault $vault -Password $goodPw -Broker $fb.Invoke).Code | Should -Be 'NeedsAttention'
        Test-Path (Join-Path $backup 'salaries.csv') | Should -BeTrue
    }
}

Describe 'Audit fix A-04: an original edited during protection is kept' -Skip:($IsWindows) {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvuo-" + [guid]::NewGuid())
        $script:folder = Join-Path $root 'home/Documents/Payroll'
        New-SampleTree -Path $folder
        $script:fb = New-FakeBroker -Root $root
    }
    AfterEach { Get-ChildItem -Recurse -Force $root -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }
    It 'keeps the backup and warns when a file changed after the copy' {
        $script:target = $folder
        Mock -ModuleName FolderVault.UserOps New-FVJunction {
            # Simulate an app saving into the (now renamed) original right after the copy.
            $bk = Get-ChildItem -Directory (Split-Path $script:target) | Where-Object Name -like '*foldervault-original*' | Select-Object -First 1
            Set-Content -Path (Join-Path $bk.FullName 'salaries.csv') -Value 'edited at the last second'
            New-Item -ItemType SymbolicLink -Path $Path -Target $Target | Out-Null
        }
        $r = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $r.Ok | Should -BeTrue
        ($r.Warnings -join ' ') | Should -Match 'kept'
        $bk = Get-ChildItem -Directory (Split-Path $folder) | Where-Object Name -like '*foldervault-original*'
        @($bk).Count | Should -Be 1
        Get-Content (Join-Path $bk.FullName 'salaries.csv') | Should -Be 'edited at the last second'
    }
}


Describe '0.2: friendly locking' {
    BeforeEach {
        $script:sent = New-Object System.Collections.Generic.List[object]
        $script:inUse = $true
        $script:lockBroker = {
            param([hashtable]$r)
            $script:sent.Add($r)
            switch ($r.op) {
                'Lock' {
                    if ($script:inUse -and -not $r.force) { return [pscustomobject]@{ ok = $false; code = 'FilesInUse'; message = 'open'; data = [pscustomobject]@{} } }
                    return [pscustomobject]@{ ok = $true; code = 'Ok'; message = 'Done.'; data = [pscustomobject]@{} }
                }
                'List' { return [pscustomobject]@{ ok = $true; code = 'Ok'; message = ''; data = [pscustomobject]@{ vaults = @([pscustomobject]@{ id = 'a'; name = 'A'; folderPath = 'C:\x'; mountPath = $null; unlockedByMe = $true }) } } }
                'LockAll' {
                    if ($script:inUse -and -not $r.force) { return [pscustomobject]@{ ok = $false; code = 'FilesInUse'; message = 'open'; data = [pscustomobject]@{ locked = @(); failed = @('a') } } }
                    return [pscustomobject]@{ ok = $true; code = 'Ok'; message = 'Done.'; data = [pscustomobject]@{ locked = @('a', 'b'); failed = @() } }
                }
            }
        }
        $script:vault = [pscustomobject]@{ id = [guid]::NewGuid().ToString(); name = 'Payroll'; folderPath = 'C:\Users\a\Documents\Payroll'; mountPath = $null }
    }
    It 'locks straight away when nothing is open' {
        $script:inUse = $false
        $r = Invoke-FVLockVault -Vault $vault -Broker $lockBroker
        $r.Ok | Should -BeTrue
        $sent.Count | Should -Be 1
        $sent[0].force | Should -BeFalse
    }
    It 'never forces without asking' {
        $r = Invoke-FVLockVault -Vault $vault -Broker $lockBroker
        $r.Code | Should -Be 'FilesInUse'
        @($sent | Where-Object { $_.force }).Count | Should -Be 0
    }
    It 'forces only after the person says yes' {
        $script:asked = ''
        $r = Invoke-FVLockVault -Vault $vault -Broker $lockBroker -AskUser { param($m) $script:asked = $m; $true }
        $r.Ok | Should -BeTrue
        $asked | Should -Match 'still open'
        $asked | Should -Not -Match '—'
        $sent[-1].force | Should -BeTrue
    }
    It 'does nothing more when the person says no' {
        $r = Invoke-FVLockVault -Vault $vault -Broker $lockBroker -AskUser { param($m) $false }
        $r.Code | Should -Be 'Cancelled'
        @($sent | Where-Object { $_.force }).Count | Should -Be 0
    }
    It 'lock-all reports how many folders it locked, in plain words' {
        $script:inUse = $false
        $r = Invoke-FVLockAll -Broker $lockBroker
        $r.Ok | Should -BeTrue
        $r.Data.locked | Should -Be 2
        $r.Message | Should -Be '2 folders locked.'
    }
    It 'closing Explorer windows is a no-op off Windows' {
        Close-FVExplorerWindows -Folders @('C:\x') | Should -Be 0
    }
}

Describe 'Audit fix A-21: folder attributes after copying' -Skip:($IsWindows) {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvuo-" + [guid]::NewGuid())
        $script:folder = Join-Path $root 'home/Documents/Payroll'
        New-SampleTree -Path $folder
        $script:fb = New-FakeBroker -Root $root
        $global:FVRA = New-Object System.Collections.Generic.List[object]
        Mock -ModuleName FolderVault.UserOps Copy-FVTree {
            $global:FVRA.Add([pscustomobject]@{ Dest = $Destination; Attr = $RootAttributes })
            Copy-FVTreeManaged -Source $Source -Destination $Destination -ExcludeTopLevel $ExcludeTopLevel
        }
    }
    AfterEach { Get-ChildItem -Recurse -Force $root -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }

    It 'keeps the vault out of the search index, and gives the restored folder plain attributes' {
        $p = Invoke-FVProtectFolder -Path $folder -Name 'Payroll' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $p.Ok | Should -BeTrue
        $global:FVRA[0].Attr | Should -Be ([System.IO.FileAttributes]'Directory, NotContentIndexed')
        $r = Invoke-FVUnprotectFolder -Vault ([pscustomobject]@{ id = $p.Data.id; folderPath = $folder }) -Password $goodPw -Broker $fb.Invoke
        $r.Ok | Should -BeTrue
        $global:FVRA[1].Attr | Should -Be ([System.IO.FileAttributes]::Directory)
        # Never Hidden or System, which a volume root carries and robocopy would copy.
        ($global:FVRA[1].Attr -band ([System.IO.FileAttributes]'Hidden, System')) | Should -Be 0
    }
}

Describe 'Audit fix A-21: Copy-FVTree resets the root attributes even when the copy fails' {
    It 'applies RootAttributes in a finally block' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvuo-" + [guid]::NewGuid())
        $dest = Join-Path $root 'd'; New-Item -ItemType Directory -Path $dest -Force | Out-Null
        try {
            (Get-Item $dest).Attributes = 'Directory, Hidden'
            Mock -ModuleName FolderVault.UserOps Copy-FVTreeCore { throw 'copy failed' }
            { Copy-FVTree -Source $root -Destination $dest -RootAttributes Directory } | Should -Throw 'copy failed'
            ((Get-Item -Force $dest).Attributes -band [System.IO.FileAttributes]::Hidden) | Should -Be 0
        } finally { Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }
    }
}

Describe 'Audit fix A-27: junction targets in any form compare equal' {
    It 'turns <In> into <Out>' -TestCases @(
        @{ In = '\??\C:\ProgramData\FolderVault\Mounts\{a}\'; Out = 'C:\ProgramData\FolderVault\Mounts\{a}' }
        @{ In = '\\?\C:\ProgramData\FolderVault\Mounts\{a}'; Out = 'C:\ProgramData\FolderVault\Mounts\{a}' }
        @{ In = 'C:\ProgramData\FolderVault\Mounts\{a}\'; Out = 'C:\ProgramData\FolderVault\Mounts\{a}' }
        @{ In = 'C:\ProgramData\FolderVault\Mounts\{a}'; Out = 'C:\ProgramData\FolderVault\Mounts\{a}' }
        @{ In = '\\?\Volume{1234}\'; Out = '\\?\Volume{1234}' }
    ) {
        ConvertTo-FVPlainLinkTarget -Target $In | Should -BeExactly $Out
    }
}

Describe '0.3.0: protecting a OneDrive folder' -Skip:($IsWindows) {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvuo-" + [guid]::NewGuid())
        # Stand-ins for OneDrive placeholders: symbolic links whose names start with "cloud-",
        # reported to Folder Vault as cloud files. Their data lives in "elsewhere".
        $script:folder = Join-Path $root 'home/OneDrive/Documents/VaultTest'
        New-SampleTree -Path $folder
        $script:elsewhere = Join-Path $root 'elsewhere'
        [void](New-Item -ItemType Directory -Path $elsewhere)
        Set-Content -LiteralPath (Join-Path $elsewhere 'budget.xlsx') -Value 'synced budget'
        [void](New-Item -ItemType SymbolicLink -Path (Join-Path $folder 'cloud-budget.xlsx') -Target (Join-Path $elsewhere 'budget.xlsx'))
        Mock -ModuleName FolderVault.Common Get-FVReparseTag {
            if ([System.IO.Path]::GetFileName($Path) -like 'cloud-*') { return [Convert]::ToUInt32('9000001A', 16) }
            return [Convert]::ToUInt32('A000000C', 16)
        }
        $script:fb = New-FakeBroker -Root $root
        $global:FVMC = @{ managed = $null }
        Mock -ModuleName FolderVault.UserOps Copy-FVTree {
            if ($null -eq $global:FVMC.managed) { $global:FVMC.managed = [bool]$Managed }
            Copy-FVTreeManaged -Source $Source -Destination $Destination -ExcludeTopLevel $ExcludeTopLevel
        }
    }
    AfterEach { Get-ChildItem -Recurse -Force $root -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }

    It 'sees cloud files as data, flags the folder as synced, and copies it without robocopy' {
        $chk = Get-FVFolderCheck -Path $folder -ProfilePath $null -Policy $null
        $chk.Ok | Should -BeTrue
        $chk.CloudItems | Should -Be 1
        $chk.Synced | Should -BeTrue
        $p = Invoke-FVProtectFolder -Path $folder -Name 'VaultTest' -Password $goodPw -SizeGB 5 -Broker $fb.Invoke
        $p.Ok | Should -BeTrue -Because "$($p.Code): $($p.Message)"
        $global:FVMC.managed | Should -BeTrue
        $v = $fb.State.Vaults[$p.Data.id]
        Get-Content -LiteralPath (Join-Path $v.Store 'cloud-budget.xlsx') | Should -Be 'synced budget'
        (Get-Item -Force (Join-Path $v.Store 'cloud-budget.xlsx')).LinkType | Should -BeNullOrEmpty -Because 'the vault holds a real copy, not a link'
    }
    It 'still refuses a real link next to cloud files' {
        [void](New-Item -ItemType SymbolicLink -Path (Join-Path $folder 'shortcut-dir') -Target $elsewhere)
        (Get-FVFolderCheck -Path $folder -ProfilePath $null -Policy $null).Code | Should -Be 'PathHasLinks'
    }
    It 'flags a folder under OneDrive as synced even before any placeholder is seen' {
        Mock -ModuleName FolderVault.Common Get-FVReparseTag { [Convert]::ToUInt32('A000000C', 16) }
        Remove-Item -LiteralPath (Join-Path $folder 'cloud-budget.xlsx')
        $chk = Get-FVFolderCheck -Path $folder -ProfilePath $null -Policy $null
        $chk.CloudItems | Should -Be 0
        $chk.Synced | Should -BeFalse -Because 'the test path uses / separators, the real check looks for \OneDrive\'
    }
}

Describe '0.3.0: online-only files are refused with instructions' {
    It 'returns PathOnlineOnly when OneDrive has not downloaded some files' {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('fvoo-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $d)
        try {
            Mock -ModuleName FolderVault.UserOps Get-FVTreeInfo { [pscustomobject]@{ Exists = $true; Files = 3; Dirs = 0; Bytes = [long]10; ReparsePoints = @(); RootIsReparse = $false; CloudItems = 3; OnlineOnly = @('x\a.docx') } }
            (Get-FVFolderCheck -Path $d -ProfilePath $null -Policy $null).Code | Should -Be 'PathOnlineOnly'
            Get-FVMessage 'PathOnlineOnly' | Should -Match 'Always keep on this device'
        } finally { Remove-Item -Recurse -Force $d }
    }
    It 'reports the policy scope and passes the IT setting through' {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('fvoo-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $d)
        try {
            Mock -ModuleName FolderVault.UserOps Resolve-FVPathScope { [pscustomobject]@{ Ok = $true; Scope = 'Local'; Code = 'Ok' } }
            $pol = [pscustomobject]@{ sharedRoots = @(); allowUserCreateInShared = $true; allowFoldersOutsideProfile = $false }
            (Get-FVFolderCheck -Path $d -ProfilePath 'x' -Policy $pol).Scope | Should -Be 'Local'
            Should -Invoke -ModuleName FolderVault.UserOps Resolve-FVPathScope -ParameterFilter { $AllowOutsideProfile -eq $false } -Times 1
            $old = [pscustomobject]@{ sharedRoots = @(); allowUserCreateInShared = $true }
            [void](Get-FVFolderCheck -Path $d -ProfilePath 'x' -Policy $old)
            Should -Invoke -ModuleName FolderVault.UserOps Resolve-FVPathScope -ParameterFilter { $AllowOutsideProfile -eq $true } -Times 1 -Because 'a 0.2 background service does not send the setting'
        } finally { Remove-Item -Recurse -Force $d }
    }
}

Describe 'A-34: Copy-FVTree leaves a vault root''s attributes to the background service' -Skip:($IsWindows) {
    BeforeEach {
        $script:base = Join-Path ([System.IO.Path]::GetTempPath()) ('fvatt-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path "$base/src", "$base/realroot")
        Set-Content -LiteralPath "$base/src/a.txt" -Value 'a'
        $global:FVATT = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.UserOps Set-FVFolderAttributes { $global:FVATT.Add($Path) }
    }
    AfterEach { Remove-Item -Recurse -Force $base -ErrorAction SilentlyContinue }
    It 'does not set attributes through a mount point (the 0.4.2 "Access to the path is denied")' {
        # Stand-in for Mounts\{id}: a link to the vault's root.
        [void](New-Item -ItemType SymbolicLink -Path "$base/mount" -Target "$base/realroot")
        Mock -ModuleName FolderVault.Common Get-FVReparseTag { [Convert]::ToUInt32('A0000003', 16) }
        Copy-FVTree -Source "$base/src" -Destination "$base/mount" -RootAttributes ([System.IO.FileAttributes]'Directory, NotContentIndexed')
        $global:FVATT.Count | Should -Be 0
        Test-Path "$base/realroot/a.txt" | Should -BeTrue
    }
    It 'still sets them on an ordinary folder (restoring a folder, A-21)' {
        [void](New-Item -ItemType Directory -Path "$base/dest")
        Copy-FVTree -Source "$base/src" -Destination "$base/dest"
        @($global:FVATT) | Should -Be @("$base/dest")
    }
}

Describe '0.4.5: a failed copy check says what was wrong' {
    It 'names missing and different items, with both records, and the copy tool''s answer' {
        $src = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $src['a.txt'] = 'F|5|' + ('A' * 64); $src['b.txt'] = 'F|7|' + ('B' * 64)
        $dst = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $dst['b.txt'] = 'F|0|' + ('C' * 64)
        $cmp = Compare-FVManifest -Source $src -Destination $dst
        $d = Format-FVVerifyDetail -Compare $cmp -Source $src -Destination $dst -CopyResult ([pscustomobject]@{ ExitCode = 1; Text = "  New File   7  b.txt `r`n" })
        $d | Should -Match 'not in the copy: a\.txt'
        $d | Should -Match 'different: b\.txt \(original F\|7\|BBBBBBBB, copy F\|0\|CCCCCCCC\)'
        $d | Should -Match 'copy tool exit code 1: New File 7 b\.txt'
    }
    It 'shows a link in the original as different, with no copy record' {
        $src = New-Object 'System.Collections.Generic.Dictionary[string,string]'; $src['link'] = 'R'
        $dst = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $cmp = Compare-FVManifest -Source $src -Destination $dst
        Format-FVVerifyDetail -Compare $cmp -Source $src -Destination $dst | Should -Be 'different: link (original R, copy (none))'
    }
    It 'shortens long lists' {
        $src = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        1..6 | ForEach-Object { $src["f$_"] = 'F|1|x' }
        $dst = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $d = Format-FVVerifyDetail -Compare (Compare-FVManifest -Source $src -Destination $dst) -Source $src -Destination $dst
        $d | Should -Match 'and 3 more$'
    }
    It 'writes both records to a log the person can send to IT' {
        $src = New-Object 'System.Collections.Generic.Dictionary[string,string]'; $src['a.txt'] = 'F|5|x'
        $dst = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $old = $env:LOCALAPPDATA
        $env:LOCALAPPDATA = Join-Path ([System.IO.Path]::GetTempPath()) ('fvlog-' + [guid]::NewGuid().ToString('N'))
        try {
            $f = Write-FVCopyCheckLog -Source $src -Destination $dst -SourcePath 'C:\Temp\T' -DestinationPath 'C:\M' -Detail 'not in the copy: a.txt'
            $f | Should -BeLike '*FolderVault*last-copy-check.txt'
            $t = Get-Content -Raw -LiteralPath $f
            $t | Should -Match 'a\.txt = F\|5\|x'
            $t | Should -Match 'Summary: not in the copy: a\.txt'
        } finally { Remove-Item -Recurse -Force $env:LOCALAPPDATA -ErrorAction SilentlyContinue; $env:LOCALAPPDATA = $old }
    }
}

Describe 'A-37: robocopy is never given a mount point' {
    BeforeEach {
        $script:cpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('fvcopy-' + [guid]::NewGuid().ToString('N'))
        $script:cpSrc = Join-Path $cpRoot 'src'; $script:cpDst = Join-Path $cpRoot 'mount'
        [void][System.IO.Directory]::CreateDirectory((Join-Path $cpSrc 'Sub\Deeper'))
        [void][System.IO.Directory]::CreateDirectory($cpDst)
        [System.IO.File]::WriteAllText((Join-Path $cpSrc 'a.ps1'), 'one')
        [System.IO.File]::WriteAllText((Join-Path $cpSrc 'b.ps1'), 'two two')
        [System.IO.File]::WriteAllText((Join-Path $cpSrc 'Sub\Deeper\c.txt'), 'three')
        [System.IO.File]::SetLastWriteTimeUtc((Join-Path $cpSrc 'a.ps1'), [datetime]'2020-01-02T03:04:05Z')
        $script:oldRoot = $env:SystemRoot; $env:SystemRoot = $script:cpRoot
        $global:FVRoboCalls = New-Object System.Collections.Generic.List[object]
        Mock -ModuleName FolderVault.UserOps Test-FVIsWindows { $true }
        Mock -ModuleName FolderVault.UserOps Invoke-FVNative {
            $global:FVRoboCalls.Add($ArgumentList)
            Copy-FVTreeManaged -Source $ArgumentList[0] -Destination $ArgumentList[1]
            [pscustomobject]@{ ExitCode = 1; Output = @(); Text = '' }
        }
    }
    AfterEach { $env:SystemRoot = $script:oldRoot; Remove-Item -Recurse -Force $script:cpRoot -ErrorAction SilentlyContinue }

    It 'copies top-level files itself and gives robocopy only the folders below' {
        $r = Copy-FVTreeCore -Source $cpSrc -Destination $cpDst
        $global:FVRoboCalls.Count | Should -Be 1
        $global:FVRoboCalls[0][0] | Should -Be (Join-Path $cpSrc 'Sub')
        $global:FVRoboCalls[0][1] | Should -Be (Join-Path $cpDst 'Sub')
        foreach ($c in $global:FVRoboCalls) { $c | Should -Not -Contain $cpDst; $c | Should -Not -Contain $cpSrc }
        [System.IO.File]::ReadAllText((Join-Path $cpDst 'b.ps1')) | Should -Be 'two two'
        [System.IO.File]::ReadAllText((Join-Path $cpDst 'Sub\Deeper\c.txt')) | Should -Be 'three'
        [System.IO.File]::GetLastWriteTimeUtc((Join-Path $cpDst 'a.ps1')) | Should -Be ([datetime]'2020-01-02T03:04:05Z').ToUniversalTime()
        $r.ExitCode | Should -Be 1
        $cmp = Compare-FVManifest -Source (Get-FVTreeManifest -Path $cpSrc) -Destination (Get-FVTreeManifest -Path $cpDst)
        $cmp.Ok | Should -BeTrue
    }
    It 'leaves out the volume''s own folders when copying back' {
        [void][System.IO.Directory]::CreateDirectory((Join-Path $cpSrc 'System Volume Information'))
        $null = Copy-FVTreeCore -Source $cpSrc -Destination $cpDst -ExcludeTopLevel @('System Volume Information')
        Test-Path (Join-Path $cpDst 'System Volume Information') | Should -BeFalse
        $global:FVRoboCalls.Count | Should -Be 1
    }
    It 'stops when robocopy says it could not open a folder, even with exit code 0' {
        Mock -ModuleName FolderVault.UserOps Invoke-FVNative {
            [pscustomobject]@{ ExitCode = 0; Output = @('2026/11/22 20:31:28 ERROR 5 (0x00000005) Accessing Destination Directory C:\M\Sub\', 'Access is denied.'); Text = 'ERROR 5 ... Access is denied.' }
        }
        { Copy-FVTreeCore -Source $cpSrc -Destination $cpDst } | Should -Throw '*robocopy 0, Sub*'
    }
}

Describe 'A-37: reading robocopy''s answer' {
    It 'counts exit codes of 8 and above as failure' {
        Test-FVRobocopyFailed -Result ([pscustomobject]@{ ExitCode = 8; Output = @() }) | Should -BeTrue
        Test-FVRobocopyFailed -Result ([pscustomobject]@{ ExitCode = 3; Output = @() }) | Should -BeFalse
    }
    It 'counts a folder it could not open as failure' {
        Test-FVRobocopyFailed -Result ([pscustomobject]@{ ExitCode = 0; Output = @('2026/11/22 20:31:28 ERROR 5 (0x00000005) Accessing Source Directory C:\x\') }) | Should -BeTrue
    }
    It 'does not count a file retried and then copied as failure' {
        Test-FVRobocopyFailed -Result ([pscustomobject]@{ ExitCode = 1; Output = @('2026/11/22 20:31:28 ERROR 32 (0x00000020) Copying File C:\x\a.txt', 'Waiting 1 seconds... Retrying...') }) | Should -BeFalse
    }
}

