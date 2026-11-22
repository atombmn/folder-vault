<#
    Engine orchestration tests. Every Windows call is mocked; what is tested is
    ORDER and ROLLBACK, which is where data-loss and security bugs hide:
      * recovery key escrowed before encryption, never left un-escrowed
      * failures roll back the container
      * new password protector added before old ones are deleted
      * bad password leaves the vault detached
#>
BeforeAll {
    $src = Join-Path $PSScriptRoot '..\..\src'
    Import-Module (Join-Path $src 'FolderVault.Common.psm1') -Force
    Import-Module (Join-Path $src 'FolderVault.Engine.psm1') -Force
    $script:paths = Get-FVPaths -DataDir 'C:\ProgramData\FolderVault'
    $script:cfg = (ConvertTo-FVConfig $null).Config
    $script:owner = 'S-1-5-21-1-2-3-1001'
    # Storage cmdlets only exist on Windows; give Pester something to mock elsewhere.
    foreach ($n in @('Get-Disk', 'Initialize-Disk', 'New-Partition', 'Format-Volume', 'Get-DiskImage', 'Mount-DiskImage', 'Dismount-DiskImage', 'Set-Partition', 'Get-Partition', 'Remove-PartitionAccessPath')) {
        if (-not (Get-Command $n -ErrorAction SilentlyContinue)) { Set-Item -Path "function:global:$n" -Value { param([Parameter(ValueFromRemainingArguments)]$a) } }
    }
    # Stubs whose parameters the tests read must declare them (Pester 6 binds mocks to the real signature).
    if (-not (Get-Command Set-Partition -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
        function global:Set-Partition { param([int]$DiskNumber, [int]$PartitionNumber, [bool]$NoDefaultDriveLetter, $ErrorAction) }
        function global:Remove-PartitionAccessPath { param([int]$DiskNumber, [int]$PartitionNumber, [string]$AccessPath, $ErrorAction) }
    }

    function New-Rec { param([string]$Scope = 'Profile')
        $id = [guid]::NewGuid().ToString()
        New-FolderVaultRecord -Id $id -Name 'Fin' -FolderPath 'C:\Users\alice\Documents\Fin' -Scope $Scope -OwnerSid $script:owner -VhdxPath "x" -SizeGB 5
    }
    function Set-HappyMocks {
        $script:calls = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.Engine Test-FVEscrowCertificate { [pscustomobject]@{ Ok = $true; Reason = 'Ok' } }
        Mock -ModuleName FolderVault.Engine Test-Path { $false } -ParameterFilter { $LiteralPath -like '*.vhdx' }
        Mock -ModuleName FolderVault.Engine Invoke-FVDiskpartCreate { $script:calls.Add('diskpart') }
        Mock -ModuleName FolderVault.Engine Mount-FVVhd { $script:calls.Add('attach'); 7 }
        Mock -ModuleName FolderVault.Engine Initialize-FolderVaultDisk { $script:calls.Add('format'); '\\?\Volume{aaaa}\' }
        Mock -ModuleName FolderVault.Engine Add-FVPassphraseProtector { $script:calls.Add('pass'); '{P}' }
        Mock -ModuleName FolderVault.Engine Add-FVRecoveryProtector { $script:calls.Add('recovery'); [pscustomobject]@{ Id = '{R}'; Key = '111111-222222-333333-444444-555555-666666-777777-888888' } }
        Mock -ModuleName FolderVault.Engine Protect-FVRecoveryKey { $script:calls.Add('escrow') }
        Mock -ModuleName FolderVault.Engine Start-FVBdeEncryption { $script:calls.Add('encrypt') }
        Mock -ModuleName FolderVault.Engine New-FVPrivateDirectory { $script:calls.Add("mkdir:$Sddl") }
        Mock -ModuleName FolderVault.Engine Invoke-FVMountvol { $script:calls.Add("mountvol:$MountPath") }
        Mock -ModuleName FolderVault.Engine Set-FVSecurity { $script:calls.Add("mountacl:${Path}:${Sddl}") }
        Mock -ModuleName FolderVault.Engine Set-FVVolumeRootSecurity { $script:calls.Add("acl:$Sddl"); $script:calls.Add("aclpath:$VolumePath") }
        Mock -ModuleName FolderVault.Engine Set-FVNotIndexed { $script:calls.Add('noindex') }
        Mock -ModuleName FolderVault.Engine Remove-FolderVaultArtifacts { $script:calls.Add('rollback') }
    }
}

Describe 'Vault paths are derived only from a GUID' {
    It 'refuses ids that are not GUIDs: <Id>' -ForEach @(@{ Id = '..\..\Windows' }, @{ Id = 'C:\x' }, @{ Id = '' }, @{ Id = '00000000-0000-0000-0000-00000000000g' }) {
        { Get-FolderVaultFiles -Id $Id -Paths $paths } | Should -Throw
    }
    It 'keeps everything inside the data directory' {
        $f = Get-FolderVaultFiles -Id ([guid]::NewGuid().ToString()) -Paths $paths
        foreach ($p in @($f.Vhdx, $f.Escrow, $f.Mount)) { $p | Should -BeLike 'C:\ProgramData\FolderVault\*' }
    }
}

Describe 'Creating a container' {
    BeforeEach { Set-HappyMocks }
    It 'escrows the recovery key before encrypting and mounts only in the data directory' {
        $rec = New-Rec
        $r = New-FolderVaultContainer -Record $rec -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1'
        $r.Ok | Should -BeTrue
        $order = @($calls)
        [array]::IndexOf($order, 'escrow') | Should -BeLessThan ([array]::IndexOf($order, 'encrypt'))
        [array]::IndexOf($order, 'recovery') | Should -BeLessThan ([array]::IndexOf($order, 'escrow'))
        ($order | Where-Object { $_ -like 'mountvol:*' }) | Should -Be ("mountvol:C:\ProgramData\FolderVault\Mounts\" + $rec.Id.ToLowerInvariant())
        $order | Should -Not -Contain 'rollback'
    }
    It 'gives a profile vault root to the owner only' {
        $rec = New-Rec
        [void](New-FolderVaultContainer -Record $rec -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1')
        $acl = @($calls | Where-Object { $_ -like 'acl:*' })[0]
        $acl | Should -Match ([regex]::Escape($owner))
        $acl | Should -Not -Match ';;;BU\)'
        $acl | Should -Match '^acl:O:BAG:SYD:PAI'
    }
    It 'gives a shared vault root to Users (modify, not full control)' {
        $rec = New-Rec -Scope Shared
        [void](New-FolderVaultContainer -Record $rec -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1')
        $acl = @($calls | Where-Object { $_ -like 'acl:*' })[0]
        $acl | Should -Match '0x1301bf;;;BU'
    }
    It 'refuses to start without a valid escrow certificate' {
        Mock -ModuleName FolderVault.Engine Test-FVEscrowCertificate { [pscustomobject]@{ Ok = $false; Reason = 'Missing' } }
        $r = New-FolderVaultContainer -Record (New-Rec) -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1'
        $r.Code | Should -Be 'EscrowMissing'
        $calls | Should -Not -Contain 'diskpart'
    }
    It 'rolls back when <Step> fails' -ForEach @(
        @{ Step = 'Protect-FVRecoveryKey' }, @{ Step = 'Start-FVBdeEncryption' }, @{ Step = 'Invoke-FVMountvol' }, @{ Step = 'Initialize-FolderVaultDisk' }, @{ Step = 'Set-FVVolumeRootSecurity' }
    ) {
        Mock -ModuleName FolderVault.Engine $Step { throw 'boom' }
        $r = New-FolderVaultContainer -Record (New-Rec) -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1'
        $r.Ok | Should -BeFalse
        $calls | Should -Contain 'rollback'
    }
    It 'never encrypts if escrow failed' {
        Mock -ModuleName FolderVault.Engine Protect-FVRecoveryKey { throw 'disk full' }
        [void](New-FolderVaultContainer -Record (New-Rec) -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1')
        $calls | Should -Not -Contain 'encrypt'
        $calls | Should -Not -Contain ($calls | Where-Object { $_ -like 'mountvol:*' })
    }
    It 'does not overwrite an existing container' {
        Mock -ModuleName FolderVault.Engine Test-Path { $true } -ParameterFilter { $LiteralPath -like '*.vhdx' }
        $r = New-FolderVaultContainer -Record (New-Rec) -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1'
        $r.Ok | Should -BeFalse
        $calls | Should -Not -Contain 'diskpart'
        $calls | Should -Not -Contain 'rollback'
    }
}

Describe 'Opening a container' {
    BeforeEach {
        $script:calls = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.Engine Test-Path { $true } -ParameterFilter { $LiteralPath -like '*.vhdx' }
        Mock -ModuleName FolderVault.Engine Test-Path { $true } -ParameterFilter { $LiteralPath -like '*Mounts*' }
        Mock -ModuleName FolderVault.Engine Test-FVVhdAttached { $false }
        Mock -ModuleName FolderVault.Engine Mount-FVVhd { $script:calls.Add('attach'); 7 }
        Mock -ModuleName FolderVault.Engine Get-FVVolumePath { '\\?\Volume{aaaa}\' }
        Mock -ModuleName FolderVault.Engine Get-FVLockStatus { 'Locked' }
        Mock -ModuleName FolderVault.Engine Dismount-FVVhd { $script:calls.Add('detach') }
        Mock -ModuleName FolderVault.Engine Test-FVMounted { $false }
        Mock -ModuleName FolderVault.Engine Invoke-FVMountvol { $script:calls.Add('mountvol') }
        Mock -ModuleName FolderVault.Engine Remove-FVUnlockShortcut { $script:calls.Add('noshortcut') }
        Mock -ModuleName FolderVault.Engine Set-FVVolumeRootNotIndexed { $script:calls.Add("noindex:$VolumePath") }
    }
    It 'detaches again after a wrong password' {
        Mock -ModuleName FolderVault.Engine Unlock-FVBdeWithPassword { 'BadPassword' }
        $r = Open-FolderVaultContainer -Record (New-Rec) -Password 'nope' -Paths $paths
        $r.Code | Should -Be 'BadPassword'
        $calls | Should -Contain 'detach'
        $calls | Should -Not -Contain 'mountvol'
    }
    It 'mounts after a correct password' {
        Mock -ModuleName FolderVault.Engine Unlock-FVBdeWithPassword { 'Ok' }
        $r = Open-FolderVaultContainer -Record (New-Rec) -Password 'yes' -Paths $paths
        $r.Ok | Should -BeTrue
        $calls | Should -Contain 'mountvol'
        # A volume can only be mounted on an empty folder: the shortcut goes first.
        [array]::IndexOf(@($calls), 'noshortcut') | Should -BeLessThan ([array]::IndexOf(@($calls), 'mountvol'))
    }
}

Describe 'Locking a container' {
    BeforeEach {
        $script:calls = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.Engine Test-FVVhdAttached { $true }
        Mock -ModuleName FolderVault.Engine Mount-FVVhd { 7 }
        Mock -ModuleName FolderVault.Engine Get-FVVolumePath { '\\?\Volume{aaaa}\' }
        Mock -ModuleName FolderVault.Engine Test-FVMounted { $true }
        Mock -ModuleName FolderVault.Engine Invoke-FVMountvol { $script:calls.Add('unmount') }
        Mock -ModuleName FolderVault.Engine Dismount-FVVhd { $script:calls.Add('detach') }
        Mock -ModuleName FolderVault.Engine New-FVUnlockShortcut { $script:calls.Add('shortcut'); $true }
    }
    It 'changes nothing when files are in use and force is off' {
        Mock -ModuleName FolderVault.Engine Lock-FVBde { 'FilesInUse' }
        $r = Close-FolderVaultContainer -Record (New-Rec) -Paths $paths -Force $false
        $r.Code | Should -Be 'FilesInUse'
        $calls.Count | Should -Be 0
    }
    It 'locks BitLocker before unmounting and detaching' {
        Mock -ModuleName FolderVault.Engine Lock-FVBde { $script:calls.Add('bdelock'); 'Ok' }
        $r = Close-FolderVaultContainer -Record (New-Rec) -Paths $paths -Force $true
        $r.Ok | Should -BeTrue
        @($calls) | Should -Be @('bdelock', 'unmount', 'detach', 'shortcut')
    }
}

Describe 'Changing the password' {
    BeforeEach {
        $script:calls = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.Engine Confirm-FolderVaultPassword { [pscustomobject]@{ Ok = $true; Code = 'Ok'; Data = '\\?\Volume{aaaa}\' } }
        Mock -ModuleName FolderVault.Engine Get-FVProtectorIds { if ($Type -eq 8) { @('{OLD}') } else { @('{OLDREC}') } }
        Mock -ModuleName FolderVault.Engine Add-FVPassphraseProtector { $script:calls.Add('addpass'); '{NEW}' }
        Mock -ModuleName FolderVault.Engine Remove-FVProtector { $script:calls.Add("del:$ProtectorId") }
        Mock -ModuleName FolderVault.Engine Add-FVRecoveryProtector { $script:calls.Add('addrec'); [pscustomobject]@{ Id = '{NEWREC}'; Key = 'k' } }
        Mock -ModuleName FolderVault.Engine Protect-FVRecoveryKey { $script:calls.Add('escrow') }
        Mock -ModuleName FolderVault.Engine Lock-FVBde { $script:calls.Add('lock'); 'Ok' }
        Mock -ModuleName FolderVault.Engine Dismount-FVVhd { $script:calls.Add('detach') }
    }
    It 'adds the new password before deleting the old one' {
        $r = Set-FolderVaultPasswordCore -Record (New-Rec) -OldPassword 'a' -NewPassword 'b' -Paths $paths
        $r.Ok | Should -BeTrue
        @($calls) | Should -Be @('addpass', 'del:{OLD}', 'lock', 'detach')
    }
    It 'rotates the recovery key after a recovery-key reset, escrowing the new one first' {
        $r = Set-FolderVaultPasswordCore -Record (New-Rec) -RecoveryKey 'x' -NewPassword 'b' -Paths $paths
        $r.Ok | Should -BeTrue
        @($calls) | Should -Be @('addpass', 'del:{OLD}', 'addrec', 'escrow', 'del:{OLDREC}', 'lock', 'detach')
    }
    It 'keeps the old password if adding the new one fails' {
        Mock -ModuleName FolderVault.Engine Add-FVPassphraseProtector { throw 'nope' }
        $r = Set-FolderVaultPasswordCore -Record (New-Rec) -OldPassword 'a' -NewPassword 'b' -Paths $paths
        $r.Ok | Should -BeFalse
        $calls | Should -Not -Contain 'del:{OLD}'
        $calls | Should -Contain 'lock'
    }
    It 'stops if the old password is wrong' {
        Mock -ModuleName FolderVault.Engine Confirm-FolderVaultPassword { [pscustomobject]@{ Ok = $false; Code = 'BadPassword' } }
        (Set-FolderVaultPasswordCore -Record (New-Rec) -OldPassword 'a' -NewPassword 'b' -Paths $paths).Code | Should -Be 'BadPassword'
        $calls.Count | Should -Be 0
    }
}

Describe 'Proving the password' {
    It 'refuses while the vault is attached (cannot verify an unlocked vault)' {
        Mock -ModuleName FolderVault.Engine Test-Path { $true } -ParameterFilter { $LiteralPath -like '*.vhdx' }
        Mock -ModuleName FolderVault.Engine Test-FVVhdAttached { $true }
        (Confirm-FolderVaultPassword -Record (New-Rec) -Password 'x' -Paths $paths).Code | Should -Be 'NotLocked'
    }
    It 'removal deletes nothing on a wrong password' {
        Mock -ModuleName FolderVault.Engine Confirm-FolderVaultPassword { [pscustomobject]@{ Ok = $false; Code = 'BadPassword' } }
        Mock -ModuleName FolderVault.Engine Remove-FolderVaultArtifacts { throw 'must not delete' }
        (Remove-FolderVaultContainer -Record (New-Rec) -Password 'x' -Paths $paths).Code | Should -Be 'BadPassword'
    }
}

Describe 'Profile lookup' {
    It 'refuses non-user SIDs: <Sid>' -ForEach @(@{ Sid = 'S-1-5-18' }, @{ Sid = '..\..\x' }, @{ Sid = 'S-1-5-21-1-2-3' }) {
        Get-FVProfilePath -Sid $Sid | Should -BeNullOrEmpty
    }
}

Describe 'Audit fix A-03 / A-20: the engine only ever formats its own empty VHDX' {
    BeforeAll {
        $script:vp = 'C:\ProgramData\FolderVault\Vaults\a.vhdx'
        function New-Img { param([string]$Path = $script:vp, $Number = 3, [bool]$Attached = $true)
            [pscustomobject]@{ ImagePath = $Path; Attached = $Attached; Number = $Number } }
    }
    It 'refuses a physical disk even when an image is attached' {
        $d = [pscustomobject]@{ Number = 0; BusType = 'NVMe'; PartitionStyle = 'GPT' }
        { Assert-FolderVaultDisk -Disk $d -Image (New-Img -Number 0) -VhdxPath $script:vp } | Should -Throw '*bus type*'
    }
    It 'refuses a disk that belongs to a different image' {
        $d = [pscustomobject]@{ Number = 3; BusType = 'File Backed Virtual'; PartitionStyle = 'RAW' }
        { Assert-FolderVaultDisk -Disk $d -Image (New-Img -Path 'C:\Other\b.vhdx') -VhdxPath $script:vp } | Should -Throw '*image path*'
    }
    It 'refuses when the image is attached as another disk number' {
        $d = [pscustomobject]@{ Number = 1; BusType = 'File Backed Virtual'; PartitionStyle = 'RAW' }
        { Assert-FolderVaultDisk -Disk $d -Image (New-Img -Number 3) -VhdxPath $script:vp } | Should -Throw '*image is disk 3*'
    }
    It 'refuses a detached image' {
        $d = [pscustomobject]@{ Number = 3; BusType = 'File Backed Virtual'; PartitionStyle = 'RAW' }
        { Assert-FolderVaultDisk -Disk $d -Image (New-Img -Attached $false) -VhdxPath $script:vp } | Should -Throw '*not attached*'
    }
    It 'accepts its own VHDX with BusType as text, as a number, and with different letter case' {
        foreach ($bus in @('File Backed Virtual', 15, [uint16]15)) {
            $d = [pscustomobject]@{ Number = 3; BusType = $bus; PartitionStyle = 'RAW' }
            { Assert-FolderVaultDisk -Disk $d -Image (New-Img -Path 'c:\programdata\foldervault\vaults\A.VHDX') -VhdxPath $script:vp } | Should -Not -Throw
        }
    }
    It 'does not depend on Disk.Location, which Windows leaves empty for VHDX disks' {
        $d = [pscustomobject]@{ Number = 3; BusType = 15; PartitionStyle = 0; Location = $null }
        { Assert-FolderVaultDisk -Disk $d -Image (New-Img) -VhdxPath $script:vp } | Should -Not -Throw
    }
    It 'treats RAW, 0 and Unknown as blank, and GPT or MBR (text or number) as not blank' {
        foreach ($ps in @('RAW', 0, 'Unknown')) { Test-FVDiskIsBlank -Disk ([pscustomobject]@{ PartitionStyle = $ps }) | Should -BeTrue }
        foreach ($ps in @('GPT', 'MBR', 1, 2)) { Test-FVDiskIsBlank -Disk ([pscustomobject]@{ PartitionStyle = $ps }) | Should -BeFalse }
    }
    It 'refuses to initialise a disk that already has partitions' {
        Mock -ModuleName FolderVault.Engine Get-Disk { [pscustomobject]@{ Number = 3; BusType = 'File Backed Virtual'; PartitionStyle = 'GPT' } }
        Mock -ModuleName FolderVault.Engine Get-DiskImage { [pscustomobject]@{ ImagePath = 'C:\v\a.vhdx'; Attached = $true; Number = 3 } }
        Mock -ModuleName FolderVault.Engine Initialize-Disk { throw 'must not be called' }
        { Initialize-FolderVaultDisk -DiskNumber 3 -VhdxPath 'C:\v\a.vhdx' } | Should -Throw '*not empty*'
        Should -Invoke -ModuleName FolderVault.Engine Initialize-Disk -Times 0
    }
    It 'switches off automatic drive letters before formatting, and removes any letter given (A-23)' {
        $global:FVET = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.Engine Get-Disk { [pscustomobject]@{ Number = 3; BusType = 15; PartitionStyle = 0 } }
        Mock -ModuleName FolderVault.Engine Get-DiskImage { [pscustomobject]@{ ImagePath = 'C:\v\a.vhdx'; Attached = $true; Number = 3 } }
        Mock -ModuleName FolderVault.Engine Initialize-Disk { $global:FVET.Add('init') }
        Mock -ModuleName FolderVault.Engine New-Partition { $global:FVET.Add('part'); [pscustomobject]@{ PartitionNumber = 2 } }
        Mock -ModuleName FolderVault.Engine Set-Partition { $global:FVET.Add("nodefault:${PartitionNumber}:${NoDefaultDriveLetter}") }
        Mock -ModuleName FolderVault.Engine Get-Partition { [pscustomobject]@{ PartitionNumber = 2; DriveLetter = 'E' } }
        Mock -ModuleName FolderVault.Engine Remove-PartitionAccessPath { $global:FVET.Add("unletter:$AccessPath") }
        Mock -ModuleName FolderVault.Engine Format-Volume { $global:FVET.Add('format'); [pscustomobject]@{ Path = '\\?\Volume{bbbb}\' } }
        Initialize-FolderVaultDisk -DiskNumber 3 -VhdxPath 'C:\v\a.vhdx' | Should -Be '\\?\Volume{bbbb}\'
        $seq = $global:FVET -join ','
        $seq | Should -Match '^init,part,nodefault:2:True,unletter:E:\\,format,unletter:E:\\$'
    }
    It 'checks the disk after attaching, through the disk image' {
        Mock -ModuleName FolderVault.Engine Get-DiskImage { [pscustomobject]@{ ImagePath = 'C:\v\a.vhdx'; Attached = $true; Number = 4 } }
        Mock -ModuleName FolderVault.Engine Get-Disk { [pscustomobject]@{ Number = 4; BusType = 'NVMe' } }
        Mock -ModuleName FolderVault.Engine Start-Sleep { }
        { Mount-FVVhd -VhdxPath 'C:\v\a.vhdx' } | Should -Throw '*bus type*'
        Mock -ModuleName FolderVault.Engine Get-Disk { [pscustomobject]@{ Number = 4; BusType = 15 } }
        Mount-FVVhd -VhdxPath 'C:\v\a.vhdx' | Should -Be 4
    }
}

Describe 'Audit fixes A-24 / A-25: BitLocker method arguments and results' {
    BeforeEach { $global:FVEA = @{} }
    It 'passes the password as Passphrase, with the exact casing the WMI method declares' {
        Mock -ModuleName FolderVault.Engine Invoke-FVBde { $global:FVEA[$Method] = $Arguments; [pscustomobject]@{ ReturnValue = 0; VolumeKeyProtectorID = '{P}' } }
        Unlock-FVBdeWithPassword -VolumePath 'v' -Password 'pw' | Should -Be 'Ok'
        Add-FVPassphraseProtector -VolumePath 'v' -Password 'pw' | Should -Be '{P}'
        @($global:FVEA['UnlockWithPassphrase'].Keys) -ccontains 'Passphrase' | Should -BeTrue
        @($global:FVEA['ProtectKeyWithPassphrase'].Keys) -ccontains 'Passphrase' | Should -BeTrue
    }
    It 'asks GetConversionStatus with PrecisionFactor 0 as an unsigned number' {
        Mock -ModuleName FolderVault.Engine Invoke-FVBde { $global:FVEA[$Method] = $Arguments; [pscustomobject]@{ ReturnValue = 0; ConversionStatus = 1 } }
        Start-FVBdeEncryption -VolumePath 'v'
        $a = $global:FVEA['GetConversionStatus']
        @($a.Keys) -ccontains 'PrecisionFactor' | Should -BeTrue
        $a['PrecisionFactor'] | Should -BeOfType [uint32]
        $a['PrecisionFactor'] | Should -Be 0
        $global:FVEA['Encrypt']['EncryptionFlags'] | Should -Be 1
    }
    It 'reports FilesInUse only for "applications are using this volume" (0x80070005)' {
        Mock -ModuleName FolderVault.Engine Get-FVLockStatus { 'Unlocked' }
        Mock -ModuleName FolderVault.Engine Invoke-FVBde { [pscustomobject]@{ ReturnValue = [uint32]2147942405 } }
        Lock-FVBde -VolumePath 'v' | Should -Be 'FilesInUse'
        Lock-FVBde -VolumePath 'v' -Force $true | Should -Be 'Error'
        Mock -ModuleName FolderVault.Engine Invoke-FVBde { [pscustomobject]@{ ReturnValue = [uint32]2150694912 } }
        Lock-FVBde -VolumePath 'v' | Should -Be 'Error'
        Mock -ModuleName FolderVault.Engine Invoke-FVBde { [pscustomobject]@{ ReturnValue = 0 } }
        Lock-FVBde -VolumePath 'v' | Should -Be 'Ok'
    }
    It 'does not call Lock on a volume that is already locked' {
        Mock -ModuleName FolderVault.Engine Get-FVLockStatus { 'Locked' }
        Mock -ModuleName FolderVault.Engine Invoke-FVBde { throw 'must not be called' }
        Lock-FVBde -VolumePath 'v' | Should -Be 'Ok'
    }
}


Describe '0.2: unlock shortcut inside locked folders' {
    It 'lives inside the vault''s own mount folder' {
        $f = Get-FolderVaultFiles -Id ([guid]::NewGuid().ToString()) -Paths $paths
        $f.Shortcut | Should -BeLike ($f.Mount + '\*.lnk')
        $f.Shortcut | Should -Not -Match '—'
    }
    It 'is put back when an already-locked vault is locked again' {
        Mock -ModuleName FolderVault.Engine Test-FVVhdAttached { $false }
        Mock -ModuleName FolderVault.Engine Test-FVMounted { $false }
        Mock -ModuleName FolderVault.Engine New-FVUnlockShortcut { $true }
        (Close-FolderVaultContainer -Record (New-Rec) -Paths $paths).Code | Should -Be 'AlreadyLocked'
        Should -Invoke -ModuleName FolderVault.Engine New-FVUnlockShortcut -Times 1
    }
    It 'is removed before the empty mount folder is deleted' {
        $script:calls = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.Engine Test-FVMounted { $false }
        Mock -ModuleName FolderVault.Engine Dismount-FVVhd { }
        Mock -ModuleName FolderVault.Engine Test-Path { $false } -ParameterFilter { $LiteralPath -like '*.vhdx' -or $LiteralPath -like '*.cms' }
        Mock -ModuleName FolderVault.Engine Remove-FVUnlockShortcut { $script:calls.Add('noshortcut') }
        Mock -ModuleName FolderVault.Engine Test-Path { $script:calls.Add('checkmount'); $false } -ParameterFilter { $LiteralPath -like '*Mounts*' -and $LiteralPath -notlike '*.lnk' }
        Remove-FolderVaultArtifacts -Files (Get-FolderVaultFiles -Id ([guid]::NewGuid().ToString()) -Paths $paths)
        @($calls)[0] | Should -Be 'noshortcut'
    }
    It 'creation never throws (best effort) and reports $false off Windows' {
        New-FVUnlockShortcut -Record (New-Rec) -Paths $paths | Should -BeFalse
    }
}

Describe '0.2: cheaper session check' {
    BeforeAll {
        $script:map = @{ 'PC\alice' = 'S-1-5-21-1-2-3-1001'; 'PC\bob' = 'S-1-5-21-1-2-3-1002' }
        $script:resolve = { param($n) $script:map[$n] }
    }
    It 'counts sessions and locked sessions per user' {
        $ex = @(
            [pscustomobject]@{ UserName = 'PC\alice'; SessionId = 1 },
            [pscustomobject]@{ UserName = 'PC\bob'; SessionId = 2 },
            [pscustomobject]@{ UserName = 'PC\bob'; SessionId = 3 }
        )
        $r = ConvertTo-FVSessionStates -Explorers $ex -LockedSessionIds @(2) -ResolveSid $resolve
        $r['S-1-5-21-1-2-3-1001'].Sessions | Should -Be 1
        $r['S-1-5-21-1-2-3-1001'].LockedSessions | Should -Be 0
        $r['S-1-5-21-1-2-3-1002'].Sessions | Should -Be 2
        $r['S-1-5-21-1-2-3-1002'].LockedSessions | Should -Be 1
    }
    It 'ignores processes without an owner or an unknown user' {
        $ex = @([pscustomobject]@{ UserName = ''; SessionId = 1 }, [pscustomobject]@{ UserName = 'PC\ghost'; SessionId = 1 })
        (ConvertTo-FVSessionStates -Explorers $ex -LockedSessionIds @() -ResolveSid $resolve).Count | Should -Be 0
    }
    It 'treats nobody signed in as an empty map (so vaults lock as SignedOut)' {
        (ConvertTo-FVSessionStates -Explorers @() -LockedSessionIds @(1) -ResolveSid $resolve).Count | Should -Be 0
    }
}

Describe 'Audit fix A-33: the vault root''s permissions are set on the volume, not the mount point folder' {
    BeforeEach { Set-HappyMocks }
    It 'sets them through \\?\Volume{GUID}\ after mounting, and never through Mounts\{id}' {
        $rec = New-Rec
        [void](New-FolderVaultContainer -Record $rec -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1')
        @($calls | Where-Object { $_ -like 'aclpath:*' }) | Should -Be @('aclpath:\\?\Volume{aaaa}\')
        @($calls | Where-Object { $_ -like 'mountacl:*' }) | Should -BeNullOrEmpty -Because 'Windows applies a mount point folder''s permissions to the folder, not the volume (KB 237701)'
        $order = @($calls)
        $iAcl = [array]::FindIndex([string[]]$order, [Predicate[string]] { param($x) $x -like 'acl:*' })
        $iMount = [array]::FindIndex([string[]]$order, [Predicate[string]] { param($x) $x -like 'mountvol:*' })
        $iAcl | Should -BeGreaterThan $iMount -Because 'the volume must be mounted (and unlocked) first'
    }
    It 'fails the creation (and rolls back) when the permissions cannot be confirmed' {
        Mock -ModuleName FolderVault.Engine Set-FVVolumeRootSecurity { throw "The vault's root permissions did not apply" }
        $r = New-FolderVaultContainer -Record (New-Rec) -Password 'pw' -Config $cfg -Paths $paths -ComputerName 'PC1'
        $r.Ok | Should -BeFalse
        $r.Stage | Should -Be 'RootAcl'
        $calls | Should -Contain 'rollback'
    }
    It 'compares descriptors by their access entries, and insists on a protected list' {
        $want = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)'
        Test-FVSddlMatches -Actual 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;OICI;FA;;;SY)' -Expected $want | Should -BeTrue
        Test-FVSddlMatches -Actual 'O:BAG:SYD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)' -Expected $want | Should -BeFalse -Because 'not protected'
        Test-FVSddlMatches -Actual ($want + '(A;OICI;0x1200a9;;;BU)') -Expected $want | Should -BeFalse -Because 'Users can read (the Format default)'
        Test-FVSddlMatches -Actual 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' -Expected $want | Should -BeFalse -Because 'the owner is missing'
    }
    It 'has a native helper that compiles' {
        $src = & (Get-Module FolderVault.Engine) { $script:FVVolumeAclSource }
        Add-Type -TypeDefinition $src.Replace('namespace FolderVault', 'namespace FolderVaultCompileTest')
        @([FolderVaultCompileTest.VolumeAcl].GetMethods() | Where-Object IsStatic | ForEach-Object Name) | Should -Contain 'Set'
    }
}

Describe 'A-34: the vault root stays out of Windows Search after every unlock' {
    BeforeEach {
        $script:calls = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName FolderVault.Engine Test-Path { $true } -ParameterFilter { $LiteralPath -like '*.vhdx' }
        Mock -ModuleName FolderVault.Engine Test-Path { $true } -ParameterFilter { $LiteralPath -like '*Mounts*' }
        Mock -ModuleName FolderVault.Engine Test-FVVhdAttached { $false }
        Mock -ModuleName FolderVault.Engine Mount-FVVhd { 7 }
        Mock -ModuleName FolderVault.Engine Get-FVVolumePath { '\\?\Volume{aaaa}\' }
        Mock -ModuleName FolderVault.Engine Get-FVLockStatus { 'Locked' }
        Mock -ModuleName FolderVault.Engine Unlock-FVBdeWithPassword { 'Ok' }
        Mock -ModuleName FolderVault.Engine Test-FVMounted { $false }
        Mock -ModuleName FolderVault.Engine Invoke-FVMountvol { }
        Mock -ModuleName FolderVault.Engine Remove-FVUnlockShortcut { }
    }
    It 'marks the root through the volume path when unlocking' {
        Mock -ModuleName FolderVault.Engine Set-FVVolumeRootNotIndexed { $script:calls.Add("noindex:$VolumePath") }
        (Open-FolderVaultContainer -Record (New-Rec) -Password 'yes' -Paths $paths).Ok | Should -BeTrue
        $calls | Should -Contain 'noindex:\\?\Volume{aaaa}\'
    }
    It 'still unlocks if the mark cannot be set' {
        Mock -ModuleName FolderVault.Engine Set-FVVolumeRootNotIndexed { throw 'denied' }
        (Open-FolderVaultContainer -Record (New-Rec) -Password 'yes' -Paths $paths).Ok | Should -BeTrue
    }
}

