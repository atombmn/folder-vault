#Requires -Version 5.1
<#
    Folder Vault - broker request handling and policy (runs as SYSTEM).

    Pure decision logic: every privileged action goes through FolderVault.Engine,
    so this module can be tested with the engine mocked. The pipe server
    (FolderVault.Broker.ps1) authenticates the caller and passes a validated
    request plus a trusted caller object:
        @{ Sid; Name; IsElevatedAdmin; ProfilePath }
#>

Set-StrictMode -Version 3.0

$script:MaxVaultsPerUser = 50

function New-FVBrokerContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Paths,
        [AllowEmptyCollection()][object[]]$Vaults = @(),
        [bool]$RegistryOk = $true,
        [Parameter(Mandatory)][scriptblock]$SaveAction,
        [scriptblock]$NowFn = { [datetime]::UtcNow },
        [string]$ComputerName = 'PC'
    )
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Vaults) { $list.Add($v) }
    return [pscustomobject]@{
        Config = $Config; Paths = $Paths; Vaults = $list; RegistryOk = $RegistryOk
        Save = $SaveAction; Now = $NowFn; ComputerName = $ComputerName
    }
}

function Save-FVBrokerState {
    param($Context)
    & $Context.Save $Context.Vaults.ToArray()
}

function Get-FVNow { param($Context) return [datetime](& $Context.Now) }

function Find-FolderVault {
    param($Context, [string]$Id)
    foreach ($v in $Context.Vaults) { if ([string]::Equals($v.Id, $Id, [System.StringComparison]::OrdinalIgnoreCase)) { return $v } }
    return $null
}

function Test-FVCanSee {
    <# Profile vaults are visible only to their owner; shared vaults to every interactive user. #>
    param($Vault, $Caller)
    if ($Vault.Scope -eq 'Shared') { return $true }
    return ($Vault.OwnerSid -eq $Caller.Sid)
}

function Get-FVShortUser {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return '' }
    if ($Name.Contains('\')) { return $Name.Substring($Name.LastIndexOf('\') + 1) }
    return $Name
}

function ConvertTo-FolderVaultView {
    param($Context, $Vault, $Caller, [switch]$Admin)
    $now = Get-FVNow $Context
    $lock = ConvertTo-FVUtc $Vault.LockoutUntilUtc
    $lockSecs = 0
    if ($null -ne $lock -and $lock -gt $now) { $lockSecs = [int][math]::Ceiling(($lock - $now).TotalSeconds) }
    $mount = $null
    if ($Vault.State -eq 'Unlocked' -or $Vault.State -eq 'Creating') { $mount = (Get-FolderVaultFiles -Id $Vault.Id -Paths $Context.Paths).Mount }
    $view = [ordered]@{
        id = $Vault.Id; name = $Vault.Name; folderPath = $Vault.FolderPath; scope = $Vault.Scope; state = $Vault.State
        mine = ($Vault.OwnerSid -eq $Caller.Sid); unlockedByMe = ($Vault.UnlockedBySid -eq $Caller.Sid)
        mountPath = $mount; lockedOutSeconds = $lockSecs; sizeGB = $Vault.SizeGB
    }
    if ($Admin) { $view['ownerSid'] = $Vault.OwnerSid; $view['failedCount'] = $Vault.FailedCount; $view['lastError'] = $Vault.LastError }
    return $view
}

function Invoke-FVBrokerRequest {
    <#
        Dispatches one validated request. Never throws: any unexpected error
        becomes InternalError and is logged without request contents.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Caller, [Parameter(Mandatory)][hashtable]$Request)
    $op = $Request.op
    try {
        if (-not $Context.RegistryOk -and @('Ping', 'GetPolicy') -notcontains $op) {
            return (New-FVResponse -Ok $false -Code 'RegistryCorrupt')
        }
        switch ($op) {
            'Ping'           { return (New-FVResponse -Ok $true -Data @{ version = (Get-FVProductVersion); protocol = (Get-FVProtocolVersion) }) }
            'GetPolicy'      { return (Invoke-FVOpGetPolicy -Context $Context) }
            'List'           { return (Invoke-FVOpList -Context $Context -Caller $Caller) }
            'Create'         { return (Invoke-FVOpCreate -Context $Context -Caller $Caller -Request $Request) }
            'FinalizeCreate' { return (Invoke-FVOpFinalize -Context $Context -Caller $Caller -Request $Request) }
            'Unlock'         { return (Invoke-FVOpUnlock -Context $Context -Caller $Caller -Request $Request) }
            'Lock'           { return (Invoke-FVOpLock -Context $Context -Caller $Caller -Request $Request) }
            'LockAll'        { return (Invoke-FVOpLockAll -Context $Context -Caller $Caller -Request $Request) }
            'ChangePassword' { return (Invoke-FVOpChangePassword -Context $Context -Caller $Caller -Request $Request) }
            'Remove'         { return (Invoke-FVOpRemove -Context $Context -Caller $Caller -Request $Request) }
            'AdminList'      { return (Invoke-FVOpAdminList -Context $Context -Caller $Caller) }
            'AdminReset'     { return (Invoke-FVOpAdminReset -Context $Context -Caller $Caller -Request $Request) }
        }
        return (New-FVResponse -Ok $false -Code 'BadRequest')
    } catch {
        Write-FVLog -Level Error -EventId 1900 -Name 'InternalError' -Fields @{ op = $op; sid = $Caller.Sid; detail = $_.Exception.Message }
        return (New-FVResponse -Ok $false -Code 'InternalError')
    }
}

function Invoke-FVOpGetPolicy {
    param($Context)
    $c = $Context.Config
    return (New-FVResponse -Ok $true -Data @{
        minPasswordLength = $c.MinPasswordLength; maxUnlockMinutes = $c.MaxUnlockMinutes
        lockOnScreenLock = $c.LockOnScreenLock; forceDismountOnAutoLock = $c.ForceDismountOnAutoLock
        defaultVaultSizeGB = $c.DefaultVaultSizeGB; minVaultSizeGB = $c.MinVaultSizeGB; maxVaultSizeGB = $c.MaxVaultSizeGB
        sharedRoots = @($c.SharedRoots); allowUserCreateInShared = $c.AllowUserCreateInShared; verifyMode = $c.VerifyMode
        allowFoldersOutsideProfile = $c.AllowFoldersOutsideProfile
        localWeakWords = @($c.LocalWeakWords)
    })
}

function Invoke-FVOpList {
    param($Context, $Caller)
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Context.Vaults) {
        if (Test-FVCanSee -Vault $v -Caller $Caller) { $items.Add((ConvertTo-FolderVaultView -Context $Context -Vault $v -Caller $Caller)) }
    }
    return (New-FVResponse -Ok $true -Data @{ vaults = $items.ToArray() })
}

function Get-FVAuthorizedVault {
    <# Returns @{ Vault; Response } - Response is set when access must be refused. #>
    param($Context, $Caller, [string]$Id, [switch]$OwnerOnly)
    $v = Find-FolderVault -Context $Context -Id $Id
    if ($null -eq $v -or -not (Test-FVCanSee -Vault $v -Caller $Caller)) {
        # Same answer whether it does not exist or belongs to someone else.
        return [pscustomobject]@{ Vault = $null; Response = (New-FVResponse -Ok $false -Code 'NotFound') }
    }
    if ($OwnerOnly -and $v.OwnerSid -ne $Caller.Sid) {
        return [pscustomobject]@{ Vault = $null; Response = (New-FVResponse -Ok $false -Code 'NotAuthorized') }
    }
    return [pscustomobject]@{ Vault = $v; Response = $null }
}

function Test-FVThrottleFor {
    param($Context, $Vault)
    $t = Get-FVThrottle -FailedCount $Vault.FailedCount -LastFailureUtc $Vault.LastFailureUtc -LockoutUntilUtc $Vault.LockoutUntilUtc -NowUtc (Get-FVNow $Context) -Config $Context.Config
    if (-not $t.Allowed) {
        Write-FVLog -Level Warning -EventId 1012 -Name 'AttemptRefused' -Fields @{ vaultId = $Vault.Id; code = $t.Code; retryAfter = $t.RetryAfterSeconds }
        return (New-FVResponse -Ok $false -Code $t.Code -Data @{ retryAfterSeconds = $t.RetryAfterSeconds })
    }
    return $null
}

function Register-FVAttempt {
    param($Context, $Vault, [bool]$Success, $Caller, [string]$Op)
    $u = Get-FVFailureUpdate -FailedCount $Vault.FailedCount -Success $Success -NowUtc (Get-FVNow $Context) -Config $Context.Config
    $Vault.FailedCount = $u.FailedCount
    $Vault.LastFailureUtc = $u.LastFailureUtc
    $Vault.LockoutUntilUtc = $u.LockoutUntilUtc
    if (-not $Success) {
        Write-FVLog -Level Warning -EventId 1010 -Name 'WrongPassword' -Fields @{ op = $Op; vaultId = $Vault.Id; sid = $Caller.Sid; count = $u.FailedCount }
        if ($u.LockedOutNow) {
            Write-FVLog -Level Warning -EventId 1011 -Name 'VaultLockedOut' -Fields @{ vaultId = $Vault.Id; sid = $Caller.Sid; count = $u.FailedCount }
        }
    }
}

function Get-FVPolicyFailure {
    param($Context, [string]$Password, [string]$UserName)
    $p = Test-FVPassword -Password $Password -UserName $UserName -Config $Context.Config
    if ($p.Ok) { return $null }
    return (New-FVResponse -Ok $false -Code 'PasswordPolicy' -Data @{ problems = @($p.Problems) })
}

function Invoke-FVOpCreate {
    param($Context, $Caller, [hashtable]$Request)
    $cfg = $Context.Config

    if (-not (Test-FolderVaultName -Name $Request.name)) { return (New-FVResponse -Ok $false -Code 'NameInvalid') }
    $pf = Get-FVPolicyFailure -Context $Context -Password $Request.password -UserName (Get-FVShortUser $Caller.Name)
    if ($null -ne $pf) { return $pf }

    $n = ConvertTo-FVNormalizedPath -Path $Request.path
    if (-not $n.Ok) { return (New-FVResponse -Ok $false -Code 'PathInvalid') }
    $scope = Resolve-FVPathScope -Path $n.Path -ProfilePath $Caller.ProfilePath -SharedRoots @($cfg.SharedRoots) -AllowShared $cfg.AllowUserCreateInShared `
        -AllowOutsideProfile $cfg.AllowFoldersOutsideProfile -ExtraBlockedRoots @($Context.Paths.DataDir, $Context.Paths.InstallDir) -Layout (Get-FVMachineLayout)
    if (-not $scope.Ok) {
        Write-FVLog -Level Warning -EventId 1040 -Name 'CreateRefused' -Fields @{ sid = $Caller.Sid; code = $scope.Code; reason = 'scope' }
        return (New-FVResponse -Ok $false -Code $scope.Code)
    }
    $existing = @($Context.Vaults | ForEach-Object { $_.FolderPath })
    if (Test-FolderVaultOverlap -Path $n.Path -ExistingPaths $existing) { return (New-FVResponse -Ok $false -Code 'PathOverlaps') }

    $mine = @($Context.Vaults | Where-Object { $_.OwnerSid -eq $Caller.Sid }).Count
    if ($mine -ge $script:MaxVaultsPerUser) { return (New-FVResponse -Ok $false -Code 'NotAuthorized' -Message 'You have reached the maximum number of protected folders.') }

    $free = Get-FVFreeBytes -Path $Context.Paths.VaultDir
    $sz = Test-FVSizeRequest -SizeGB $Request.sizeGB -ContentBytes $Request.contentBytes -FreeBytes $free -Config $cfg
    if (-not $sz.Ok) { return (New-FVResponse -Ok $false -Code $sz.Code) }

    $id = [guid]::NewGuid().ToString()
    $f = Get-FolderVaultFiles -Id $id -Paths $Context.Paths
    $rec = New-FolderVaultRecord -Id $id -Name $Request.name -FolderPath $n.Path -Scope $scope.Scope -OwnerSid $Caller.Sid -VhdxPath $f.Vhdx -SizeGB $Request.sizeGB -State 'Creating'
    $rec.UnlockedBySid = $Caller.Sid
    $rec.UnlockedAtUtc = ConvertTo-FVIso (Get-FVNow $Context)
    # Record first, so a crash part-way leaves something IT can find.
    $Context.Vaults.Add($rec)
    Save-FVBrokerState $Context

    $r = New-FolderVaultContainer -Record $rec -Password $Request.password -Config $cfg -Paths $Context.Paths -ComputerName $Context.ComputerName
    if (-not $r.Ok) {
        [void]$Context.Vaults.Remove($rec)
        Save-FVBrokerState $Context
        Write-FVLog -Level Error -EventId 1041 -Name 'CreateFailed' -Fields @{ vaultId = $id; sid = $Caller.Sid; code = $r.Code; stage = $r.Stage; detail = $r.Detail }
        return (New-FVResponse -Ok $false -Code $r.Code)
    }
    Write-FVLog -EventId 1000 -Name 'VaultCreated' -Fields @{ vaultId = $id; sid = $Caller.Sid; scope = $scope.Scope }
    return (New-FVResponse -Ok $true -Data @{ id = $id; mountPath = $r.Data.MountPath; folderPath = $n.Path })
}

function Invoke-FVOpFinalize {
    param($Context, $Caller, [hashtable]$Request)
    $a = Get-FVAuthorizedVault -Context $Context -Caller $Caller -Id $Request.id -OwnerOnly
    if ($null -ne $a.Response) { return $a.Response }
    $v = $a.Vault
    if ($v.State -ne 'Creating') { return (New-FVResponse -Ok $false -Code 'BadRequest') }
    # The user's session has copied and verified the data; a forced lock is safe and
    # avoids failing because Explorer still has the folder open.
    $r = Close-FolderVaultContainer -Record $v -Paths $Context.Paths -Force $true
    if (-not $r.Ok) { return (New-FVResponse -Ok $false -Code $r.Code) }
    $v.State = 'Locked'; $v.UnlockedBySid = $null; $v.UnlockedAtUtc = $null
    Save-FVBrokerState $Context
    Write-FVLog -EventId 1002 -Name 'VaultLocked' -Fields @{ vaultId = $v.Id; sid = $Caller.Sid; reason = 'CreateFinished' }
    return (New-FVResponse -Ok $true)
}

function Test-FVUnlockAllowedBy {
    <# Profile vaults: owner only. Shared vaults: anyone who can see them. #>
    param($Vault, $Caller)
    if ($Vault.Scope -eq 'Shared') { return $true }
    return ($Vault.OwnerSid -eq $Caller.Sid)
}

function Invoke-FVOpUnlock {
    param($Context, $Caller, [hashtable]$Request)
    $a = Get-FVAuthorizedVault -Context $Context -Caller $Caller -Id $Request.id
    if ($null -ne $a.Response) { return $a.Response }
    $v = $a.Vault
    if (-not (Test-FVUnlockAllowedBy -Vault $v -Caller $Caller)) { return (New-FVResponse -Ok $false -Code 'NotAuthorized') }
    if ($v.State -eq 'NeedsAttention') { return (New-FVResponse -Ok $false -Code 'NeedsAttention') }
    # An unfinished protection may be re-opened by its owner so the UI can resume or cancel it.
    if ($v.State -eq 'Creating' -and $v.OwnerSid -ne $Caller.Sid) { return (New-FVResponse -Ok $false -Code 'Busy') }
    $f = Get-FolderVaultFiles -Id $v.Id -Paths $Context.Paths

    $rt = Get-FolderVaultRuntime -Record $v -Paths $Context.Paths
    if ($rt.Attached -and $rt.Unlocked -and $rt.Mounted) {
        return (New-FVResponse -Ok $true -Code 'AlreadyUnlocked' -Data @{ mountPath = $f.Mount })
    }
    if ($rt.Attached) {
        # Inconsistent state (e.g. after a crash): lock fully, then require the password.
        [void](Close-FolderVaultContainer -Record $v -Paths $Context.Paths -Force $true)
    }

    $t = Test-FVThrottleFor -Context $Context -Vault $v
    if ($null -ne $t) { return $t }

    $r = Open-FolderVaultContainer -Record $v -Password $Request.password -Paths $Context.Paths
    if ($r.Code -eq 'BadPassword') {
        Register-FVAttempt -Context $Context -Vault $v -Success $false -Caller $Caller -Op 'Unlock'
        Save-FVBrokerState $Context
        return (New-FVResponse -Ok $false -Code 'BadPassword')
    }
    if (-not $r.Ok) {
        Write-FVLog -Level Error -EventId 1901 -Name 'UnlockFailed' -Fields @{ vaultId = $v.Id; code = $r.Code; stage = $r.Stage; detail = $r.Detail }
        return (New-FVResponse -Ok $false -Code $r.Code)
    }
    Register-FVAttempt -Context $Context -Vault $v -Success $true -Caller $Caller -Op 'Unlock'
    if ($v.State -ne 'Creating') { $v.State = 'Unlocked' }
    $v.UnlockedBySid = $Caller.Sid; $v.UnlockedAtUtc = ConvertTo-FVIso (Get-FVNow $Context)
    Save-FVBrokerState $Context
    Write-FVLog -EventId 1001 -Name 'VaultUnlocked' -Fields @{ vaultId = $v.Id; sid = $Caller.Sid }
    return (New-FVResponse -Ok $true -Data @{ mountPath = $r.Data.MountPath })
}

function Close-FolderVaultAndRecord {
    param($Context, $Vault, [bool]$Force, [string]$Reason, [string]$Sid)
    $r = Close-FolderVaultContainer -Record $Vault -Paths $Context.Paths -Force $Force
    if ($r.Ok) {
        if ($Vault.State -ne 'Creating') { $Vault.State = 'Locked' }
        $Vault.UnlockedBySid = $null; $Vault.UnlockedAtUtc = $null
        Save-FVBrokerState $Context
        $eid = 1002
        if ($Reason -ne 'User') { $eid = 1003 }
        Write-FVLog -EventId $eid -Name 'VaultLocked' -Fields @{ vaultId = $Vault.Id; sid = $Sid; reason = $Reason }
    }
    return $r
}

function Invoke-FVOpLock {
    param($Context, $Caller, [hashtable]$Request)
    $a = Get-FVAuthorizedVault -Context $Context -Caller $Caller -Id $Request.id
    if ($null -ne $a.Response) { return $a.Response }
    # Anyone who can see a vault may lock it, but only the person who unlocked it
    # may force it (forcing discards that person's unsaved work).
    $force = [bool]$Request.force
    if ($force -and -not [string]::IsNullOrEmpty($a.Vault.UnlockedBySid) -and $a.Vault.UnlockedBySid -ne $Caller.Sid) { $force = $false }
    $r = Close-FolderVaultAndRecord -Context $Context -Vault $a.Vault -Force $force -Reason 'User' -Sid $Caller.Sid
    if (-not $r.Ok) { return (New-FVResponse -Ok $false -Code $r.Code) }
    return (New-FVResponse -Ok $true -Code 'Ok')
}

function Invoke-FVOpLockAll {
    param($Context, $Caller, [hashtable]$Request)
    $locked = New-Object System.Collections.Generic.List[string]
    $failed = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Context.Vaults.ToArray()) {
        if ($v.UnlockedBySid -ne $Caller.Sid) { continue }
        if ($v.State -ne 'Unlocked' -and $v.State -ne 'Creating') { continue }
        $r = Close-FolderVaultAndRecord -Context $Context -Vault $v -Force $Request.force -Reason 'User' -Sid $Caller.Sid
        if ($r.Ok) { $locked.Add($v.Id) } else { $failed.Add(@{ id = $v.Id; code = $r.Code }) }
    }
    $ok = ($failed.Count -eq 0)
    $code = 'Ok'
    if (-not $ok) { $code = 'FilesInUse' }
    return (New-FVResponse -Ok $ok -Code $code -Data @{ locked = $locked.ToArray(); failed = $failed.ToArray() })
}

function Invoke-FVOpChangePassword {
    param($Context, $Caller, [hashtable]$Request)
    $a = Get-FVAuthorizedVault -Context $Context -Caller $Caller -Id $Request.id
    if ($null -ne $a.Response) { return $a.Response }
    $v = $a.Vault
    if (-not (Test-FVUnlockAllowedBy -Vault $v -Caller $Caller)) { return (New-FVResponse -Ok $false -Code 'NotAuthorized') }
    if ($v.State -ne 'Locked') { return (New-FVResponse -Ok $false -Code 'NotLocked') }
    $t = Test-FVThrottleFor -Context $Context -Vault $v
    if ($null -ne $t) { return $t }
    $pf = Get-FVPolicyFailure -Context $Context -Password $Request.newPassword -UserName (Get-FVShortUser $Caller.Name)
    if ($null -ne $pf) { return $pf }
    $r = Set-FolderVaultPasswordCore -Record $v -OldPassword $Request.password -NewPassword $Request.newPassword -Paths $Context.Paths -ComputerName $Context.ComputerName
    if ($r.Code -eq 'BadPassword') {
        Register-FVAttempt -Context $Context -Vault $v -Success $false -Caller $Caller -Op 'ChangePassword'
        Save-FVBrokerState $Context
        return (New-FVResponse -Ok $false -Code 'BadPassword')
    }
    if (-not $r.Ok) {
        Write-FVLog -Level Error -EventId 1902 -Name 'ChangePasswordFailed' -Fields @{ vaultId = $v.Id; code = $r.Code; stage = $r.Stage; detail = $r.Detail }
        return (New-FVResponse -Ok $false -Code $r.Code)
    }
    Register-FVAttempt -Context $Context -Vault $v -Success $true -Caller $Caller -Op 'ChangePassword'
    Save-FVBrokerState $Context
    Write-FVLog -EventId 1020 -Name 'PasswordChanged' -Fields @{ vaultId = $v.Id; sid = $Caller.Sid }
    return (New-FVResponse -Ok $true)
}

function Invoke-FVOpRemove {
    param($Context, $Caller, [hashtable]$Request)
    $a = Get-FVAuthorizedVault -Context $Context -Caller $Caller -Id $Request.id
    if ($null -ne $a.Response) { return $a.Response }
    $v = $a.Vault
    if (-not (Test-FVUnlockAllowedBy -Vault $v -Caller $Caller)) { return (New-FVResponse -Ok $false -Code 'NotAuthorized') }
    if ($v.State -ne 'Locked' -and $v.State -ne 'Creating') { return (New-FVResponse -Ok $false -Code 'NotLocked') }
    $rt = Get-FolderVaultRuntime -Record $v -Paths $Context.Paths
    if ($rt.Attached) { return (New-FVResponse -Ok $false -Code 'NotLocked') }
    $t = Test-FVThrottleFor -Context $Context -Vault $v
    if ($null -ne $t) { return $t }
    $r = Remove-FolderVaultContainer -Record $v -Password $Request.password -Paths $Context.Paths
    if ($r.Code -eq 'BadPassword') {
        Register-FVAttempt -Context $Context -Vault $v -Success $false -Caller $Caller -Op 'Remove'
        Save-FVBrokerState $Context
        return (New-FVResponse -Ok $false -Code 'BadPassword')
    }
    if (-not $r.Ok) {
        Write-FVLog -Level Error -EventId 1903 -Name 'RemoveFailed' -Fields @{ vaultId = $v.Id; code = $r.Code; stage = $r.Stage; detail = $r.Detail }
        return (New-FVResponse -Ok $false -Code $r.Code)
    }
    [void]$Context.Vaults.Remove($v)
    Save-FVBrokerState $Context
    Write-FVLog -EventId 1030 -Name 'VaultRemoved' -Fields @{ vaultId = $v.Id; sid = $Caller.Sid }
    return (New-FVResponse -Ok $true)
}

function Invoke-FVOpAdminList {
    param($Context, $Caller)
    if (-not $Caller.IsElevatedAdmin) { return (New-FVResponse -Ok $false -Code 'NotAuthorized') }
    $items = @($Context.Vaults | ForEach-Object { ConvertTo-FolderVaultView -Context $Context -Vault $_ -Caller $Caller -Admin })
    return (New-FVResponse -Ok $true -Data @{ vaults = $items })
}

function Invoke-FVOpAdminReset {
    param($Context, $Caller, [hashtable]$Request)
    if (-not $Caller.IsElevatedAdmin) {
        Write-FVLog -Level Warning -EventId 1050 -Name 'AdminRefused' -Fields @{ op = 'AdminReset'; sid = $Caller.Sid }
        return (New-FVResponse -Ok $false -Code 'NotAuthorized')
    }
    $v = Find-FolderVault -Context $Context -Id $Request.id
    if ($null -eq $v) { return (New-FVResponse -Ok $false -Code 'NotFound') }
    if (-not (Test-FVRecoveryKeyFormat -Value $Request.recoveryKey)) { return (New-FVResponse -Ok $false -Code 'BadRecoveryKey') }
    $rt = Get-FolderVaultRuntime -Record $v -Paths $Context.Paths
    if ($rt.Attached) { return (New-FVResponse -Ok $false -Code 'NotLocked') }
    $t = Test-FVThrottleFor -Context $Context -Vault $v
    if ($null -ne $t) { return $t }
    $pf = Get-FVPolicyFailure -Context $Context -Password $Request.newPassword -UserName ''
    if ($null -ne $pf) { return $pf }
    $r = Set-FolderVaultPasswordCore -Record $v -RecoveryKey $Request.recoveryKey -NewPassword $Request.newPassword -Paths $Context.Paths -ComputerName $Context.ComputerName
    if ($r.Code -eq 'BadRecoveryKey') {
        Register-FVAttempt -Context $Context -Vault $v -Success $false -Caller $Caller -Op 'AdminReset'
        Save-FVBrokerState $Context
        return (New-FVResponse -Ok $false -Code 'BadRecoveryKey')
    }
    if (-not $r.Ok) {
        Write-FVLog -Level Error -EventId 1904 -Name 'AdminResetFailed' -Fields @{ vaultId = $v.Id; code = $r.Code; stage = $r.Stage; detail = $r.Detail }
        return (New-FVResponse -Ok $false -Code $r.Code)
    }
    Register-FVAttempt -Context $Context -Vault $v -Success $true -Caller $Caller -Op 'AdminReset'
    if ($v.State -eq 'NeedsAttention') { $v.State = 'Locked' }
    $v.LastError = $null
    Save-FVBrokerState $Context
    Write-FVLog -Level Warning -EventId 1051 -Name 'AdminPasswordReset' -Fields @{ vaultId = $v.Id; sid = $Caller.Sid }
    return (New-FVResponse -Ok $true)
}

function Test-FVAnyUnlocked {
    <# True while any vault is unlocked or part-way through being protected. The broker sleeps when this is false. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    if (-not $Context.RegistryOk) { return $false }
    foreach ($v in $Context.Vaults) { if ($v.State -eq 'Unlocked' -or $v.State -eq 'Creating') { return $true } }
    return $false
}

function Invoke-FVBrokerWatchdog {
    <#
        Auto-locks vaults when: the unlocking user signed out, every session of
        that user is at the lock screen, or the maximum unlock time passed.
        $SessionStates = $null means "unknown" (query failed): only the timeout
        rule is applied, and the failure is logged.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [AllowNull()]$SessionStates)
    if (-not (Test-FVAnyUnlocked -Context $Context)) { return }
    $cfg = $Context.Config
    $now = Get-FVNow $Context
    foreach ($v in $Context.Vaults.ToArray()) {
        if ($v.State -ne 'Unlocked' -and $v.State -ne 'Creating') { continue }
        $reason = $null
        $at = ConvertTo-FVUtc $v.UnlockedAtUtc
        if ($null -ne $at -and $at.AddMinutes($cfg.MaxUnlockMinutes) -lt $now) { $reason = 'Timeout' }
        elseif ($null -ne $SessionStates -and -not [string]::IsNullOrEmpty($v.UnlockedBySid)) {
            if (-not $SessionStates.ContainsKey($v.UnlockedBySid)) { $reason = 'SignedOut' }
            elseif ($cfg.LockOnScreenLock) {
                $s = $SessionStates[$v.UnlockedBySid]
                if ($s.Sessions -gt 0 -and $s.LockedSessions -ge $s.Sessions) { $reason = 'ScreenLocked' }
            }
        }
        if ($null -eq $reason) { continue }
        $r = Close-FolderVaultAndRecord -Context $Context -Vault $v -Force $cfg.ForceDismountOnAutoLock -Reason $reason -Sid $v.UnlockedBySid
        if (-not $r.Ok) {
            Write-FVLog -Level Warning -EventId 1004 -Name 'AutoLockFailed' -Fields @{ vaultId = $v.Id; reason = $reason; code = $r.Code }
        }
    }
}

function Initialize-FVBrokerState {
    <# At broker start: everything is locked and the registry is reconciled with reality. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    if (-not $Context.RegistryOk) { return }
    $changed = $false
    foreach ($v in $Context.Vaults.ToArray()) {
        $rt = Get-FolderVaultRuntime -Record $v -Paths $Context.Paths
        if (-not $rt.Exists) {
            if ($v.State -ne 'NeedsAttention') { $v.State = 'NeedsAttention'; $v.LastError = 'Container file missing'; $changed = $true }
            continue
        }
        if ($rt.Attached -or $rt.Mounted) {
            [void](Close-FolderVaultContainer -Record $v -Paths $Context.Paths -Force $true)
        }
        if ($v.State -eq 'Unlocked') { $v.State = 'Locked'; $changed = $true }
        if ($null -ne $v.UnlockedBySid -and $v.State -ne 'Creating') { $v.UnlockedBySid = $null; $v.UnlockedAtUtc = $null; $changed = $true }
        # Vaults created by 0.1.0 have no unlock shortcut yet.
        [void](New-FVUnlockShortcut -Record $v -Paths $Context.Paths)
    }
    if ($changed) { Save-FVBrokerState $Context }
}

Export-ModuleMember -Function @(
    'New-FVBrokerContext', 'Invoke-FVBrokerRequest', 'Invoke-FVBrokerWatchdog', 'Initialize-FVBrokerState', 'Find-FolderVault', 'Test-FVAnyUnlocked'
)
