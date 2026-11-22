#Requires -Version 5.1
<#
    Folder Vault - file operations that run in the SIGNED-IN USER'S context.

    All reading, copying and deleting of the user's own files happens here, with
    the user's own permissions. The SYSTEM broker never touches user folders, so
    tricks such as swapping a folder for a junction cannot make SYSTEM read or
    write somewhere the user could not reach anyway.

    Data-safety rule: the original files are deleted only after the copy inside
    the vault has been verified file-by-file (SHA-256 by default) AND the folder
    link has been created and checked. Every earlier failure rolls back.
#>

Set-StrictMode -Version 3.0

function New-FVStep {
    param([string]$Code, [string]$Message, $Data = $null, [string[]]$Warnings = @())
    return [pscustomobject]@{ Ok = ($Code -eq 'Ok'); Code = $Code; Message = $Message; Data = $Data; Warnings = @($Warnings) }
}

function Invoke-FVProgress {
    param([scriptblock]$Progress, [string]$Text, [int]$Percent)
    if ($null -ne $Progress) { try { & $Progress $Text $Percent } catch { Write-Verbose 'progress callback failed' } }
}

function Get-FVShortId { param([string]$Id) return $Id.Substring(0, 8) }

# ---------------------------------------------------------------------------
# Filesystem primitives (wrapped so tests can mock the Windows-only ones)
# ---------------------------------------------------------------------------
function Test-FVIsWindows {
    [OutputType([bool])]
    param()
    return ($env:OS -eq 'Windows_NT')
}

function Test-FVReparsePath {
    <# True when $Path itself is a link (junction, symlink, mount point). OneDrive's own placeholders are not links. #>
    [OutputType([bool])]
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $i = Get-Item -LiteralPath $Path -Force
    return (Test-FVIsReparse $i)
}

function Test-FVAncestorsClean {
    <# True when no existing ancestor of $Path (up to the drive root) is a reparse point. #>
    [OutputType([bool])]
    param([string]$Path)
    $p = [System.IO.Path]::GetDirectoryName($Path)
    while (-not [string]::IsNullOrEmpty($p)) {
        if (Test-FVReparsePath -Path $p) { return $false }
        $parent = [System.IO.Path]::GetDirectoryName($p)
        if ($parent -eq $p) { break }
        $p = $parent
    }
    return $true
}

function New-FVJunction {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Target)
    if (-not $PSCmdlet.ShouldProcess($Path, "Create link to $Target")) { return }
    if (Test-FVIsWindows) { New-Item -ItemType Junction -Path $Path -Target $Target -ErrorAction Stop | Out-Null }
    else { New-Item -ItemType SymbolicLink -Path $Path -Target $Target -ErrorAction Stop | Out-Null }
}

function Get-FVLinkTarget {
    [OutputType([string])]
    param([string]$Path)
    if (-not (Test-FVReparsePath -Path $Path)) { return $null }
    $i = Get-Item -LiteralPath $Path -Force
    $t = $null
    if ($null -ne $i.PSObject.Properties['Target']) { $t = @($i.Target)[0] }
    if ($null -eq $t -and $null -ne $i.PSObject.Properties['LinkTarget']) { $t = $i.LinkTarget }
    if ($null -eq $t) { return $null }
    return (ConvertTo-FVPlainLinkTarget -Target ([string]$t))
}

function ConvertTo-FVPlainLinkTarget {
    <#
        Some Windows APIs report a junction's target in the NT form "\??\C:\..."
        rather than "C:\...". Return the ordinary form, without a trailing
        backslash, so it can be compared with the expected path whichever form
        Windows PowerShell 5.1 returns. (Not yet observed on a real PC.)
    #>
    [OutputType([string])]
    param([string]$Target)
    $t = $Target
    if ($t.StartsWith('\??\')) { $t = $t.Substring(4) }
    if ($t.StartsWith('\\?\') -and $t -notlike '\\?\Volume{*') { $t = $t.Substring(4) }
    return $t.TrimEnd('\', '/')
}

function Remove-FVLink {
    <# Removes a junction/symlink itself; never its target. Refuses on a real directory. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-FVReparsePath -Path $Path)) { throw [System.InvalidOperationException]::new('Not a link') }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Remove link')) { return }
    try { [System.IO.Directory]::Delete($Path, $false) } catch { [System.IO.File]::Delete($Path) }
}

function Set-FVFolderAttributes {
    <# Sets a folder's attributes (a separate function so tests can see it called). #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][System.IO.FileAttributes]$Attributes)
    if ($PSCmdlet.ShouldProcess($Path, 'Set attributes')) { (New-Object System.IO.DirectoryInfo($Path)).Attributes = $Attributes }
}

function Copy-FVTree {
    <# Copies the contents of $Source into $Destination as the current user. Links are never followed. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [string[]]$ExcludeTopLevel = @(),
        # Attributes to give the destination folder itself afterwards. Robocopy
        # copies the source folder's attributes onto it, and a volume root is
        # Hidden + System, so a folder restored from a vault would vanish from
        # view (Microsoft documents this robocopy behaviour). Found in the
        # 13 Nov 2026 audit.
        [System.IO.FileAttributes]$RootAttributes = [System.IO.FileAttributes]::Directory,
        # Copy with .NET instead of robocopy. Used for OneDrive folders: every
        # file and folder there is a cloud placeholder (a reparse point), and
        # robocopy's /XJ switch is not documented to tell those apart from
        # junctions, so Folder Vault does not rely on it.
        [switch]$Managed
    )
    try {
        if ($Managed) { Copy-FVTreeManaged -Source $Source -Destination $Destination -ExcludeTopLevel $ExcludeTopLevel }
        else { Copy-FVTreeCore -Source $Source -Destination $Destination -ExcludeTopLevel $ExcludeTopLevel }
    }
    finally {
        if (Test-Path -LiteralPath $Destination) {
            $d = New-Object System.IO.DirectoryInfo($Destination)
            # A vault is reached through a mount point. Attributes set through a mount
            # point land on the mount point folder, which only the background service
            # may change, not on the vault's root (seen on the first PC, 0.4.2). The
            # service keeps the vault root's own attributes (A-34).
            if (-not (Test-FVIsReparse $d)) { Set-FVFolderAttributes -Path $Destination -Attributes $RootAttributes }
        }
    }
}

function Copy-FVTreeCore {
    param([string]$Source, [string]$Destination, [string[]]$ExcludeTopLevel = @())
    if (Test-FVIsWindows) {
        $robo = Join-Path $env:SystemRoot 'System32\robocopy.exe'
        $roboArgs = @($Source, $Destination, '/E', '/COPY:DAT', '/DCOPY:DAT', '/XJ', '/R:2', '/W:1', '/NP', '/NFL', '/NDL', '/NJH', '/NJS')
        if ($ExcludeTopLevel.Count -gt 0) {
            $roboArgs += '/XD'
            foreach ($x in $ExcludeTopLevel) { $roboArgs += (Join-Path $Source $x) }
        }
        $r = Invoke-FVNative -FilePath $robo -ArgumentList $roboArgs
        # robocopy: 0-7 mean success (files copied, extras found); 8 and above mean failure.
        if ($r.ExitCode -ge 8) { throw [System.IO.IOException]::new("Copy failed (robocopy $($r.ExitCode)): " + $r.Text) }
        return
    }
    Copy-FVTreeManaged -Source $Source -Destination $Destination -ExcludeTopLevel $ExcludeTopLevel
}

function Copy-FVTreeManaged {
    <# Pure .NET copy used off-Windows (tests) and as a fallback. #>
    param([string]$Source, [string]$Destination, [string[]]$ExcludeTopLevel = @())
    $src = New-Object System.IO.DirectoryInfo($Source)
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($src, $Destination, $true))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $dir = $item[0]; $dest = $item[1]; $isRoot = $item[2]
        if (-not (Test-Path -LiteralPath $dest)) { [void][System.IO.Directory]::CreateDirectory($dest) }
        foreach ($e in $dir.EnumerateFileSystemInfos()) {
            if ($isRoot -and ($ExcludeTopLevel -contains $e.Name)) { continue }
            if (Test-FVIsReparse $e) { continue }   # links are never followed or copied (the check refuses them anyway)
            $target = Join-Path $dest $e.Name
            if ($e -is [System.IO.DirectoryInfo]) { $stack.Push(@($e, $target, $false)) }
            else {
                [System.IO.File]::Copy($e.FullName, $target, $true)
                [System.IO.File]::SetLastWriteTimeUtc($target, $e.LastWriteTimeUtc)
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
function Get-FVFolderCheck {
    <#
        Client-side checks before protecting a folder (the broker re-checks the
        policy parts). Returns Ok/Code plus Path, Bytes and Files.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [AllowNull()][AllowEmptyString()][string]$ProfilePath, $Policy)
    $fail = { param($c) [pscustomobject]@{ Ok = $false; Code = $c; Path = $null; Bytes = [long]0; Files = 0 } }
    if (Test-FVIsWindows) {
        $n = ConvertTo-FVNormalizedPath -Path $Path
        if (-not $n.Ok) { return (& $fail 'PathInvalid') }
        $p = $n.Path
    } else {
        # Only reached by the cross-platform unit tests; production is Windows-only.
        $p = [System.IO.Path]::GetFullPath($Path).TrimEnd('/')
    }
    $scopeName = 'Profile'
    if ($null -ne $Policy) {
        $outside = $true
        if ($null -ne $Policy.PSObject.Properties['allowFoldersOutsideProfile']) { $outside = [bool]$Policy.allowFoldersOutsideProfile }
        $scope = Resolve-FVPathScope -Path $p -ProfilePath $ProfilePath -SharedRoots @($Policy.sharedRoots) -AllowShared ([bool]$Policy.allowUserCreateInShared) -AllowOutsideProfile $outside
        if (-not $scope.Ok) { return (& $fail $scope.Code) }
        $scopeName = $scope.Scope
    }
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { return (& $fail 'PathNotFound') }
    if (Test-FVReparsePath -Path $p) { return (& $fail 'PathHasLinks') }
    if (-not (Test-FVAncestorsClean -Path $p)) { return (& $fail 'PathHasLinks') }
    $info = Get-FVTreeInfo -Path $p
    if ($info.RootIsReparse -or @($info.ReparsePoints).Count -gt 0) { return (& $fail 'PathHasLinks') }
    if (@($info.OnlineOnly).Count -gt 0) { return (& $fail 'PathOnlineOnly') }
    # A folder synced by OneDrive (or a similar app) holds cloud placeholders, or sits under a folder named OneDrive*.
    $synced = ($info.CloudItems -gt 0) -or ($p -match '\\OneDrive( - [^\\]+)?\\')
    return [pscustomobject]@{ Ok = $true; Code = 'Ok'; Path = $p; Bytes = $info.Bytes; Files = $info.Files; Scope = $scopeName; Synced = $synced; CloudItems = [int]$info.CloudItems }
}

function Test-FVCanRename {
    <# Quick check that nothing holds the folder open: rename it away and straight back. #>
    [OutputType([bool])]
    param([string]$Path)
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    $probe = Join-Path $parent ('.foldervault-probe-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try { [System.IO.Directory]::Move($Path, $probe) } catch { return $false }
    try { [System.IO.Directory]::Move($probe, $Path) } catch {
        throw [System.InvalidOperationException]::new("Folder was renamed to '$probe' and could not be renamed back. Rename it back manually.")
    }
    return $true
}

# ---------------------------------------------------------------------------
# Protect a folder
# ---------------------------------------------------------------------------
function Invoke-FVProtectFolder {
    <#
        1. Check the folder.
        2. Broker creates the encrypted vault and mounts it (unlocked) in its own area.
        3. Copy the files into the vault and verify every one.
        4. Rename the original aside, create a link at the original path to the vault, check it.
        5. Broker locks the vault.
        6. Delete the renamed original.
        Steps 1-4 roll back completely on failure. After step 5 the vault holds
        the data; a failure in step 6 only leaves an extra copy to delete by hand.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][int]$SizeGB,
        [AllowNull()][AllowEmptyString()][string]$ProfilePath,
        $Policy,
        [Parameter(Mandatory)][scriptblock]$Broker,
        [scriptblock]$Progress,
        [string]$VerifyMode = 'Hash'
    )
    Invoke-FVProgress $Progress 'Checking the folder...' 2
    $chk = Get-FVFolderCheck -Path $Path -ProfilePath $ProfilePath -Policy $Policy
    if (-not $chk.Ok) { return (New-FVStep $chk.Code (Get-FVMessage $chk.Code)) }
    $folder = $chk.Path
    if (-not (Test-FVCanRename -Path $folder)) { return (New-FVStep 'FilesInUse' (Get-FVMessage 'FilesInUse')) }

    Invoke-FVProgress $Progress 'Creating the encrypted vault...' 10
    $resp = & $Broker @{ op = 'Create'; path = $folder; name = $Name; password = $Password; sizeGB = $SizeGB; contentBytes = [long]$chk.Bytes }
    if (-not $resp.ok) {
        $data = $null
        if ($null -ne $resp.PSObject.Properties['data']) { $data = $resp.data }
        return (New-FVStep $resp.code $resp.message $data)
    }
    $id = [string]$resp.data.id
    $mount = [string]$resp.data.mountPath

    $discard = {
        # Throw away the new vault; the original folder is untouched at this point.
        $l = & $Broker @{ op = 'Lock'; id = $id; force = $true }
        $r = & $Broker @{ op = 'Remove'; id = $id; password = $Password }
        return ($l.ok -and $r.ok)
    }

    try {
        Invoke-FVProgress $Progress 'Copying files into the vault...' 25
        Copy-FVTree -Source $folder -Destination $mount -RootAttributes ([System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::NotContentIndexed) -Managed:($chk.CloudItems -gt 0)
        Invoke-FVProgress $Progress 'Checking every file was copied correctly...' 60
        $srcMan = Get-FVTreeManifest -Path $folder -Mode $VerifyMode
        $dstMan = Get-FVTreeManifest -Path $mount -Mode $VerifyMode -ExcludeTopLevel (Get-FVVolumeSystemNames)
        $cmp = Compare-FVManifest -Source $srcMan -Destination $dstMan
        if (-not $cmp.Ok) {
            [void](& $discard)
            return (New-FVStep 'VerifyFailed' (Get-FVMessage 'VerifyFailed') @{ missing = @($cmp.Missing | Select-Object -First 5); mismatched = @($cmp.Mismatched | Select-Object -First 5) })
        }
    } catch {
        [void](& $discard)
        return (New-FVStep 'VerifyFailed' ("$(Get-FVMessage 'VerifyFailed') ($($_.Exception.Message))"))
    }

    Invoke-FVProgress $Progress 'Linking the folder to the vault...' 75
    $leaf = [System.IO.Path]::GetFileName($folder)
    $parent = [System.IO.Path]::GetDirectoryName($folder)
    $backup = Join-Path $parent ("$leaf.foldervault-original-" + (Get-FVShortId $id))
    try {
        [System.IO.Directory]::Move($folder, $backup)
    } catch {
        [void](& $discard)
        return (New-FVStep 'FilesInUse' (Get-FVMessage 'FilesInUse'))
    }
    try {
        New-FVJunction -Path $folder -Target $mount
        $t = Get-FVLinkTarget -Path $folder
        if ($null -eq $t -or -not [string]::Equals($t, $mount.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.InvalidOperationException]::new('Link check failed')
        }
        $check = Get-FVTreeManifest -Path $folder -Mode 'Size' -ExcludeTopLevel (Get-FVVolumeSystemNames)
        if ($check.Count -lt $srcMan.Count) { throw [System.InvalidOperationException]::new('Linked folder does not show the files') }   # count-safe: manifests are Dictionary objects
    } catch {
        $msg = $_.Exception.Message
        try { if (Test-FVReparsePath -Path $folder) { Remove-FVLink -Path $folder } } catch { Write-Verbose 'link cleanup failed' }
        try { [System.IO.Directory]::Move($backup, $folder) } catch {
            return (New-FVStep 'NeedsAttention' "Your files are safe in '$backup'. Rename it back to '$leaf' and contact IT. ($msg)")
        }
        [void](& $discard)
        return (New-FVStep 'InternalError' "$(Get-FVMessage 'InternalError') ($msg)")
    }

    Invoke-FVProgress $Progress 'Locking the vault...' 85
    $fin = & $Broker @{ op = 'FinalizeCreate'; id = $id }
    $warnings = New-Object System.Collections.Generic.List[string]
    if (-not $fin.ok) { $warnings.Add('The vault was created but could not be locked automatically. Lock it from the Folder Vault window.') }

    Invoke-FVProgress $Progress 'Removing the unprotected copy...' 92
    # A program may have kept a file open and saved to it after the copy was made.
    # If the original changed since it was copied, keep it rather than lose that edit.
    $changed = $true
    try { $changed = -not (Compare-FVManifest -Source (Get-FVTreeManifest -Path $backup -Mode $VerifyMode) -Destination $srcMan).Ok } catch { $changed = $true }
    if ($changed) {
        $warnings.Add("Some files in the original changed while it was being protected, so the original was kept at '$backup'. Copy any newer files into the protected folder, then delete '$backup'.")
    } else {
        try {
            Remove-FVTreeContents -Path $backup
            [System.IO.Directory]::Delete($backup, $false)
        } catch {
            $warnings.Add("Some original files could not be deleted from '$backup' (they may be open). Your files are safe in the vault; delete that folder when you can.")
        }
    }
    Invoke-FVProgress $Progress 'Done.' 100
    return (New-FVStep 'Ok' 'The folder is now protected and locked.' @{ id = $id; folder = $folder } $warnings.ToArray())
}

# ---------------------------------------------------------------------------
# Remove protection
# ---------------------------------------------------------------------------
function Invoke-FVUnprotectFolder {
    <#
        1. Unlock (or use the already unlocked vault).
        2. Copy everything out to a new folder beside the link and verify it.
        3. Lock the vault.
        4. Swap the link for the restored folder.
        5. Broker deletes the vault after re-checking the password.
        The vault is deleted last, so a failure at any step loses nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Vault,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][scriptblock]$Broker,
        [scriptblock]$Progress,
        [string]$VerifyMode = 'Hash'
    )
    $id = [string]$Vault.id
    $folder = [string]$Vault.folderPath
    Invoke-FVProgress $Progress 'Unlocking...' 5
    $u = & $Broker @{ op = 'Unlock'; id = $id; password = $Password }
    if (-not $u.ok) { return (New-FVStep $u.code $u.message) }
    $mount = [string]$u.data.mountPath

    $leaf = [System.IO.Path]::GetFileName($folder)
    $parent = [System.IO.Path]::GetDirectoryName($folder)
    $restore = Join-Path $parent ("$leaf.foldervault-restore-" + (Get-FVShortId $id))
    try {
        if (Test-Path -LiteralPath $restore) { return (New-FVStep 'InternalError' "A folder named '$restore' already exists. Remove it and try again.") }
        Invoke-FVProgress $Progress 'Copying files out of the vault...' 20
        [void][System.IO.Directory]::CreateDirectory($restore)
        Copy-FVTree -Source $mount -Destination $restore -ExcludeTopLevel (Get-FVVolumeSystemNames) -RootAttributes ([System.IO.FileAttributes]::Directory)
        Invoke-FVProgress $Progress 'Checking every file was copied correctly...' 60
        $srcMan = Get-FVTreeManifest -Path $mount -Mode $VerifyMode -ExcludeTopLevel (Get-FVVolumeSystemNames)
        $dstMan = Get-FVTreeManifest -Path $restore -Mode $VerifyMode
        $cmp = Compare-FVManifest -Source $srcMan -Destination $dstMan
        if (-not $cmp.Ok) { throw [System.IO.IOException]::new('verification mismatch') }
    } catch {
        try { if (Test-Path -LiteralPath $restore) { Remove-FVTreeContents -Path $restore; [System.IO.Directory]::Delete($restore, $false) } } catch { Write-Verbose 'restore cleanup failed' }
        return (New-FVStep 'VerifyFailed' "$(Get-FVMessage 'VerifyFailed') ($($_.Exception.Message))")
    }

    Invoke-FVProgress $Progress 'Locking the vault...' 75
    $l = Invoke-FVLockVault -Vault ([pscustomobject]@{ id = $id; name = [System.IO.Path]::GetFileName($folder); folderPath = $folder; mountPath = $mount }) -Broker $Broker
    if (-not $l.Ok) {
        try { Remove-FVTreeContents -Path $restore; [System.IO.Directory]::Delete($restore, $false) } catch { Write-Verbose 'restore cleanup failed' }
        return (New-FVStep $l.Code $l.Message)
    }

    Invoke-FVProgress $Progress 'Putting your files back in place...' 85
    try {
        if (Test-Path -LiteralPath $folder) {
            if (-not (Test-FVReparsePath -Path $folder)) { throw [System.InvalidOperationException]::new("'$folder' is not the Folder Vault link") }
            Remove-FVLink -Path $folder
        }
        [System.IO.Directory]::Move($restore, $folder)
    } catch {
        return (New-FVStep 'NeedsAttention' "Your files are safe in '$restore' and still in the vault. Contact IT. ($($_.Exception.Message))")
    }

    Invoke-FVProgress $Progress 'Deleting the vault...' 95
    $r = & $Broker @{ op = 'Remove'; id = $id; password = $Password }
    if (-not $r.ok) {
        return (New-FVStep 'Ok' 'Protection removed. Your files are back in the folder.' $null @("The old vault could not be deleted ($($r.message)). Ask IT to remove it."))
    }
    Invoke-FVProgress $Progress 'Done.' 100
    return (New-FVStep 'Ok' 'Protection removed. Your files are back in the folder (no longer password protected).')
}

# ---------------------------------------------------------------------------
# Unfinished protection (UI or PC stopped part-way through)
# ---------------------------------------------------------------------------
function Get-FVUnfinishedState {
    <#
        Works out where an interrupted protection stopped, from what is on disk:
          'LinkPlusBackup' - link exists and the original is still beside it  -> finish
          'LinkOnly'       - link exists, original already gone               -> finish
          'BackupOnly'     - original renamed aside, no link                  -> put back, then cancel
          'OriginalOnly'   - original untouched                               -> cancel
          'Unknown'        - anything else                                    -> IT
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Vault)
    $folder = [string]$Vault.folderPath
    $leaf = [System.IO.Path]::GetFileName($folder)
    $parent = [System.IO.Path]::GetDirectoryName($folder)
    $backup = Join-Path $parent ("$leaf.foldervault-original-" + (Get-FVShortId ([string]$Vault.id)))
    $hasFolder = Test-Path -LiteralPath $folder
    $isLink = $hasFolder -and (Test-FVReparsePath -Path $folder)
    $hasBackup = Test-Path -LiteralPath $backup
    $state = 'Unknown'
    if ($isLink -and $hasBackup) { $state = 'LinkPlusBackup' }
    elseif ($isLink) { $state = 'LinkOnly' }
    elseif (-not $hasFolder -and $hasBackup) { $state = 'BackupOnly' }
    elseif ($hasFolder -and -not $hasBackup) { $state = 'OriginalOnly' }
    return [pscustomobject]@{ State = $state; Folder = $folder; Backup = $backup }
}

function Resolve-FVUnfinished {
    <# Finishes or cancels an interrupted protection, choosing whatever cannot lose data. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Vault,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][scriptblock]$Broker,
        [string]$VerifyMode = 'Hash'
    )
    $id = [string]$Vault.id
    $s = Get-FVUnfinishedState -Vault $Vault
    switch ($s.State) {
        'LinkPlusBackup' {
            $u = & $Broker @{ op = 'Unlock'; id = $id; password = $Password }
            if (-not $u.ok) { return (New-FVStep $u.code $u.message) }
            $srcMan = Get-FVTreeManifest -Path $s.Backup -Mode $VerifyMode
            $dstMan = Get-FVTreeManifest -Path ([string]$u.data.mountPath) -Mode $VerifyMode -ExcludeTopLevel (Get-FVVolumeSystemNames)
            $cmp = Compare-FVManifest -Source $srcMan -Destination $dstMan
            if (-not $cmp.Ok) { return (New-FVStep 'NeedsAttention' "The vault copy does not match '$($s.Backup)'. Nothing was deleted. Contact IT.") }
            $fin = & $Broker @{ op = 'FinalizeCreate'; id = $id }
            if (-not $fin.ok) { return (New-FVStep $fin.code $fin.message) }
            $w = @()
            try { Remove-FVTreeContents -Path $s.Backup; [System.IO.Directory]::Delete($s.Backup, $false) } catch { $w = @("Delete '$($s.Backup)' when you can.") }
            return (New-FVStep 'Ok' 'Protection finished.' $null $w)
        }
        'LinkOnly' {
            $fin = & $Broker @{ op = 'FinalizeCreate'; id = $id }
            if (-not $fin.ok) { return (New-FVStep $fin.code $fin.message) }
            return (New-FVStep 'Ok' 'Protection finished.')
        }
        'BackupOnly' {
            [System.IO.Directory]::Move($s.Backup, $s.Folder)
            $null = & $Broker @{ op = 'Lock'; id = $id; force = $true }
            $r = & $Broker @{ op = 'Remove'; id = $id; password = $Password }
            if (-not $r.ok) { return (New-FVStep $r.code $r.message) }
            return (New-FVStep 'Ok' 'The unfinished protection was cancelled. Your folder is back as it was.')
        }
        'OriginalOnly' {
            $null = & $Broker @{ op = 'Lock'; id = $id; force = $true }
            $r = & $Broker @{ op = 'Remove'; id = $id; password = $Password }
            if (-not $r.ok) { return (New-FVStep $r.code $r.message) }
            return (New-FVStep 'Ok' 'The unfinished protection was cancelled. Your folder was not changed.')
        }
    }
    return (New-FVStep 'NeedsAttention' (Get-FVMessage 'NeedsAttention'))
}

# ---------------------------------------------------------------------------
# Locking (shared by the tray, the window, the Explorer menu and the hotkey)
# ---------------------------------------------------------------------------
function Get-FVProp {
    <# Reads a property that may be missing (broker replies vary), without tripping StrictMode. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Close-FVExplorerWindows {
    <#
        Closes File Explorer windows showing a protected folder (or anything
        inside it). An open Explorer window is the most common reason a folder
        "cannot be locked": it holds the folder open but has no unsaved work.
        Returns how many windows were closed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param([string[]]$Folders = @())
    $roots = @($Folders | Where-Object { -not [string]::IsNullOrEmpty($_) } | ForEach-Object { $_.TrimEnd('\') })
    if (-not (Test-FVIsWindows) -or $roots.Count -eq 0) { return 0 }
    try { $shell = New-Object -ComObject Shell.Application } catch { return 0 }
    $closed = 0
    foreach ($w in @($shell.Windows())) {
        $p = $null
        try { $p = [string]$w.Document.Folder.Self.Path } catch { continue }
        if ([string]::IsNullOrEmpty($p)) { continue }
        foreach ($r in $roots) {
            if ($p.Equals($r, [System.StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($r + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($PSCmdlet.ShouldProcess($p, 'Close Explorer window')) { try { $w.Quit(); $closed++ } catch { Write-Verbose 'window did not close' } }
                break
            }
        }
    }
    if ($closed -gt 0) { Start-Sleep -Milliseconds 800 }
    return $closed
}

function Get-FolderVaultFolders {
    param($Vault)
    $f = @([string](Get-FVProp $Vault 'folderPath'))
    $m = [string](Get-FVProp $Vault 'mountPath')
    if (-not [string]::IsNullOrEmpty($m)) { $f += $m }
    return $f
}

function Invoke-FVLockVault {
    <#
        Locks one vault the friendly way:
          1. try a normal lock;
          2. if something holds it open, close Explorer windows showing it and try again;
          3. only then ask the user (through $AskUser) whether to lock anyway.
        $AskUser receives a message and returns $true to force. Without it, nothing is forced.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Vault, [Parameter(Mandatory)][scriptblock]$Broker, [scriptblock]$AskUser)
    $id = [string]$Vault.id
    $folders = Get-FolderVaultFolders $Vault
    $r = & $Broker @{ op = 'Lock'; id = $id; force = $false }
    if (-not $r.ok -and $r.code -eq 'FilesInUse' -and (Close-FVExplorerWindows -Folders $folders) -gt 0) {
        $r = & $Broker @{ op = 'Lock'; id = $id; force = $false }
    }
    if (-not $r.ok -and $r.code -eq 'FilesInUse' -and $null -ne $AskUser) {
        $msg = "A file from '$($Vault.name)' is still open in another program.`r`n`r`nSave it and close it, then try again (click No).`r`nOr click Yes to lock now. Anything not saved in that file will be lost."
        if ([bool](& $AskUser $msg)) { $r = & $Broker @{ op = 'Lock'; id = $id; force = $true } }
        else { return (New-FVStep 'Cancelled' 'The folder was not locked.') }
    }
    if ($r.ok) {
        [void](Clear-FVRecentItems -Folders $folders)
        return (New-FVStep 'Ok' "'$($Vault.name)' is locked.")
    }
    return (New-FVStep ([string]$r.code) ([string]$r.message))
}

function Invoke-FVLockAll {
    <# Locks every vault the current user unlocked, with the same friendly steps as Invoke-FVLockVault. Data.locked = how many were locked. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Broker, [scriptblock]$AskUser, [bool]$Force = $false)
    $l = & $Broker @{ op = 'List' }
    $mine = @()
    if ($l.ok) { $mine = @(Get-FVProp $l.data 'vaults' | Where-Object { $null -ne $_ -and (Get-FVProp $_ 'unlockedByMe') }) }
    $folders = @($mine | ForEach-Object { Get-FolderVaultFolders $_ })
    $r = & $Broker @{ op = 'LockAll'; force = $Force }
    if (-not $r.ok -and (Close-FVExplorerWindows -Folders $folders) -gt 0) { $r = & $Broker @{ op = 'LockAll'; force = $Force } }
    if (-not $r.ok -and $null -ne $AskUser) {
        $msg = "A file from one of your protected folders is still open in another program.`r`n`r`nSave it and close it, then try again (click No).`r`nOr click Yes to lock now. Anything not saved will be lost."
        if ([bool](& $AskUser $msg)) { $r = & $Broker @{ op = 'LockAll'; force = $true } }
    }
    [void](Clear-FVRecentItems -Folders $folders)
    $count = @(Get-FVProp $r.data 'locked' | Where-Object { $null -ne $_ }).Count
    if ($r.ok) {
        $text = 'Nothing was unlocked.'
        if ($count -eq 1) { $text = '1 folder locked.' } elseif ($count -gt 1) { $text = "$count folders locked." }
        return (New-FVStep 'Ok' $text @{ locked = $count })
    }
    return (New-FVStep ([string]$r.code) ([string]$r.message) @{ locked = $count })
}

# ---------------------------------------------------------------------------
# Privacy clean-up on lock (user context)
# ---------------------------------------------------------------------------
function Clear-FVRecentItems {
    <# Deletes Windows "Recent items" shortcuts that point inside the given folders. Returns the count removed. #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param([string[]]$Folders = @())
    if (-not (Test-FVIsWindows) -or $Folders.Count -eq 0) { return 0 }
    $recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
    if (-not (Test-Path -LiteralPath $recent)) { return 0 }
    $shell = New-Object -ComObject WScript.Shell
    $removed = 0
    foreach ($lnk in @(Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -File -ErrorAction SilentlyContinue)) {
        try { $target = $shell.CreateShortcut($lnk.FullName).TargetPath } catch { continue }
        if ([string]::IsNullOrEmpty($target)) { continue }
        foreach ($f in $Folders) {
            if ([string]::IsNullOrEmpty($f)) { continue }
            $root = $f.TrimEnd('\')
            if ($target.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or $target.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($PSCmdlet.ShouldProcess($lnk.FullName, 'Delete recent item')) {
                    Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction SilentlyContinue
                    $removed++
                }
                break
            }
        }
    }
    return $removed
}

Export-ModuleMember -Function @(
    'Test-FVIsWindows', 'Test-FVReparsePath', 'Test-FVAncestorsClean', 'New-FVJunction', 'Get-FVLinkTarget', 'Remove-FVLink',
    'Copy-FVTree', 'Copy-FVTreeManaged', 'Get-FVFolderCheck', 'Test-FVCanRename',
    'Invoke-FVProtectFolder', 'Invoke-FVUnprotectFolder', 'Get-FVUnfinishedState', 'Resolve-FVUnfinished', 'Clear-FVRecentItems',
    'Get-FVProp', 'Close-FVExplorerWindows', 'Invoke-FVLockVault', 'Invoke-FVLockAll', 'ConvertTo-FVPlainLinkTarget'
)
