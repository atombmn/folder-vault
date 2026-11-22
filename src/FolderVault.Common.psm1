#Requires -Version 5.1
<#
    Folder Vault - shared logic (no privileged operations).

    Everything in this module is deliberately free of Windows-only calls so it can
    be unit-tested anywhere. It is used by the SYSTEM broker, the user UI and the
    admin tools. It must stay compatible with Windows PowerShell 5.1:
    no ternary (?:), no null-coalescing (??), no pipeline chains (&& ||).
#>

Set-StrictMode -Version 3.0

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$script:FVProtocolVersion = 1
$script:FVMaxFrameBytes   = 65536
$script:FVPipeName        = 'FolderVaultBroker'
$script:FVProductVersion  = '0.5.0'

# Names the broker places on the root of every vault volume that must never be
# treated as user data.
$script:FVVolumeSystemNames = @('System Volume Information', '$RECYCLE.BIN')

# Profile sub-folders that may not be protected as a whole (only their
# sub-folders may be). AppData is blocked at any depth.
$script:FVKnownProfileFolders = @(
    'Desktop', 'Documents', 'Downloads', 'Pictures', 'Music', 'Videos',
    'Favorites', 'Links', 'Contacts', 'Searches', 'Saved Games', '3D Objects'
)

$script:FVReservedDeviceNames = @(
    'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
)

# Small embedded list of passwords/words that are always rejected when they make
# up most of the password. Not a substitute for length. Add local words (towns,
# the organisation's name, products) with the LocalWeakWords setting.
$script:FVCommonWords = @(
    'password', 'passw0rd', 'p@ssword', 'p@ssw0rd', 'qwerty', 'qwertyuiop',
    'asdfgh', 'zxcvbn', 'letmein', 'welcome', 'admin', 'administrator',
    'iloveyou', 'monkey', 'dragon', 'football', 'baseball', 'sunshine',
    'princess', 'master', 'shadow', 'superman', 'trustno1', 'changeme',
    'office', 'company', 'secret', 'computer', 'windows', 'microsoft',
    'abc123', 'abcdef', '123456', '1234567890', '0987654321', 'vault', 'foldervault', 'folder'
)

# ---------------------------------------------------------------------------
# Messages shown to users (one place, so the UI and broker agree)
# ---------------------------------------------------------------------------
$script:FVMessages = @{
    'Ok'                  = 'Done.'
    'BadRequest'          = 'The request was not understood.'
    'UnsupportedVersion'  = 'This version of Folder Vault does not match the background service. Ask IT to update it.'
    'NotAuthorized'       = 'You are not allowed to do that.'
    'NotFound'            = 'That protected folder no longer exists.'
    'BadPassword'         = 'That password is not correct.'
    'Throttled'           = 'Too many attempts. Please wait a moment and try again.'
    'LockedOut'           = 'Too many wrong passwords. This folder is temporarily blocked. Try again later or contact IT.'
    'PasswordPolicy'      = 'The new password does not meet the rules.'
    'PathInvalid'         = 'That folder path is not valid.'
    'PathNotAllowed'      = 'That folder cannot be protected. Windows and program folders, AppData, whole drives and other people''s folders are never protected. Choose one of your own folders.'
    'PathWholeFolder'     = 'Folder Vault protects folders inside Documents, Desktop, Downloads or OneDrive, not the whole of one of them. Make a folder inside it, move the files there, and protect that.'
    'PathOtherUser'       = 'That folder belongs to another person''s Windows account, so you cannot protect it.'
    'PathNotLocalDisk'    = 'Folder Vault can only protect folders on this computer''s own drives, not on USB sticks, memory cards, DVDs or network drives.'
    'PathOutsideProfile'  = 'On this computer, Folder Vault only protects folders inside your own user folder (Documents, Desktop, OneDrive and so on). Ask IT if you need another folder protected.'
    'PathOnlineOnly'      = 'Some files in that folder are only in OneDrive online, not on this computer. In File Explorer, right-click the folder, choose "Always keep on this device", wait until every file shows a green tick, then try again.'
    'PathNotFound'        = 'That folder does not exist.'
    'PathHasLinks'        = 'That folder is, or contains, a link to another folder (a junction or symbolic link), so it cannot be protected safely.'
    'PathOverlaps'        = 'That folder is already protected, or is inside or contains a protected folder.'
    'NameInvalid'         = 'The name may only use letters, numbers, spaces, dashes, dots and brackets (up to 40 characters).'
    'SizeInvalid'         = 'The vault size is not valid.'
    'InsufficientSpace'   = 'There is not enough free disk space to protect this folder.'
    'FilesInUse'          = 'Some files in this folder are still open. Close them and try again.'
    'Busy'                = 'Folder Vault is busy with this folder. Please wait.'
    'NotLocked'           = 'Lock the folder first.'
    'AlreadyUnlocked'     = 'This folder is already unlocked.'
    'AlreadyLocked'       = 'This folder is already locked.'
    'EscrowMissing'       = 'Folder Vault is not fully set up (no recovery certificate). Contact IT.'
    'RegistryCorrupt'     = 'Folder Vault''s list of protected folders is damaged. Contact IT; no files have been changed.'
    'VerifyFailed'        = 'The copy could not be verified, so nothing was changed. Contact IT if this keeps happening.'
    'NeedsAttention'      = 'This protected folder needs attention from IT.'
    'BrokerUnavailable'   = 'The Folder Vault background service is not running. Restart the computer or contact IT.'
    'BrokerUntrusted'     = 'Folder Vault could not confirm it is talking to the genuine background service, so your password was not sent. Contact IT immediately.'
    'BadRecoveryKey'      = 'That recovery key is not correct.'
    'InternalError'       = 'Something went wrong. Nothing was deleted. Contact IT if this keeps happening.'
    'UnsupportedEdition'  = 'This edition of Windows does not support Folder Vault (Windows Pro or higher is required).'
}

function Get-FVMessage {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Code)
    if ($script:FVMessages.ContainsKey($Code)) { return $script:FVMessages[$Code] }
    return $script:FVMessages['InternalError']
}

function Get-FVPipeName { [OutputType([string])] param() return $script:FVPipeName }
function Get-FVProtocolVersion { [OutputType([int])] param() return $script:FVProtocolVersion }
function Get-FVProductVersion { [OutputType([string])] param() return $script:FVProductVersion }
function Get-FVMaxFrameBytes { [OutputType([int])] param() return $script:FVMaxFrameBytes }

# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------
function Join-FVPath {
    <# Joins Windows paths without touching the file system (Join-Path validates drives). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Parent, [Parameter(Mandatory)][string]$Child)
    return ($Parent.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Get-FVPaths {
    [CmdletBinding()]
    param(
        [string]$DataDir = 'C:\ProgramData\FolderVault',
        [string]$InstallDir = 'C:\Program Files\FolderVault'
    )
    return [pscustomobject]@{
        InstallDir   = $InstallDir
        DataDir      = $DataDir
        VaultDir     = (Join-FVPath $DataDir 'Vaults')
        EscrowDir    = (Join-FVPath $DataDir 'Escrow')
        MountDir     = (Join-FVPath $DataDir 'Mounts')
        LogDir       = (Join-FVPath $DataDir 'Logs')
        ConfigFile   = (Join-FVPath $DataDir 'config.json')
        RegistryFile = (Join-FVPath $DataDir 'vaults.json')
        EscrowCert   = (Join-FVPath $DataDir 'escrow.cer')
    }
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
function Get-FVDefaultConfig {
    [CmdletBinding()]
    param()
    return [ordered]@{
        MinPasswordLength        = 12
        MaxUnlockMinutes         = 240
        LockOnScreenLock         = $true
        ForceDismountOnAutoLock  = $true
        MaxFailedAttempts        = 10
        BackoffStartAfter        = 3
        LockoutMinutes           = 15
        SharedRoots              = @()
        LocalWeakWords           = @()      # place names, company and product names staff might use in a password
        AllowUserCreateInShared  = $true
        AllowFoldersOutsideProfile = $true   # folders on any fixed local drive, e.g. D:\Accounts
        DefaultVaultSizeGB       = 5
        MinVaultSizeGB           = 1
        MaxVaultSizeGB           = 500
        EncryptionMethod         = 7      # 7 = XTS-AES-256
        VerifyMode               = 'Hash' # Hash | Size
        WatchdogIntervalSeconds  = 5
    }
}

# Top-level folders on ANY drive that are Windows' own (as well as any starting with '$').
$script:FVSystemTopFolders = @('System Volume Information', 'Recovery', 'Windows.old', 'PerfLogs', 'Config.Msi', 'OneDriveTemp', 'Boot', 'EFI')
$script:FVSystemPathRoots = @('C:\Windows', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData', 'C:\Recovery', 'C:\$Recycle.Bin', 'C:\System Volume Information')

function ConvertTo-FVConfig {
    <#
        Merges a user/admin supplied config object over the defaults and validates
        every value. Unknown keys are ignored; invalid values fall back to the
        default and are reported in .Warnings. Never throws.
    #>
    [CmdletBinding()]
    param([AllowNull()]$InputObject)

    $cfg = Get-FVDefaultConfig
    $warnings = New-Object System.Collections.Generic.List[string]
    if ($null -eq $InputObject) {
        return [pscustomobject]@{ Config = [pscustomobject]$cfg; Warnings = $warnings.ToArray() }
    }

    $intRanges = @{
        MinPasswordLength       = @(8, 128)
        MaxUnlockMinutes        = @(1, 1440)
        MaxFailedAttempts       = @(3, 100)
        BackoffStartAfter       = @(1, 20)
        LockoutMinutes          = @(1, 1440)
        DefaultVaultSizeGB      = @(1, 2000)
        MinVaultSizeGB          = @(1, 2000)
        MaxVaultSizeGB          = @(1, 64000)
        EncryptionMethod        = @(6, 7)
        WatchdogIntervalSeconds = @(2, 60)
    }
    $boolKeys = @('LockOnScreenLock', 'ForceDismountOnAutoLock', 'AllowUserCreateInShared', 'AllowFoldersOutsideProfile')

    foreach ($prop in $InputObject.PSObject.Properties) {
        $name = $prop.Name
        $val = $prop.Value
        if ($intRanges.ContainsKey($name)) {
            $isInt = ($val -is [int] -or $val -is [long] -or ($val -is [double] -and [math]::Floor($val) -eq $val))
            if ($isInt -and [long]$val -ge $intRanges[$name][0] -and [long]$val -le $intRanges[$name][1]) {
                $cfg[$name] = [int]$val
            } else {
                $warnings.Add("Config '$name' invalid; using default.")
            }
        } elseif ($boolKeys -contains $name) {
            if ($val -is [bool]) { $cfg[$name] = $val } else { $warnings.Add("Config '$name' invalid; using default.") }
        } elseif ($name -eq 'VerifyMode') {
            if ($val -is [string] -and @('Hash', 'Size') -contains $val) { $cfg[$name] = $val } else { $warnings.Add("Config 'VerifyMode' invalid; using default.") }
        } elseif ($name -eq 'LocalWeakWords') {
            # Extra words refused when they make up most of a password, like the built-in list.
            # Letters and digits only, 3 to 40 characters, at most 200 words; stored in lower case.
            $words = New-Object System.Collections.Generic.List[string]
            foreach ($w in @($val)) {
                $t = ([string]$w).Trim().ToLowerInvariant()
                if ($t -match '^[a-z0-9]{3,40}$') { if (-not $words.Contains($t) -and $words.Count -lt 200) { $words.Add($t) } }
                else { $warnings.Add("Weak word '$w' ignored: use 3 to 40 letters or digits.") }
            }
            $cfg[$name] = $words.ToArray()
        } elseif ($name -eq 'SharedRoots') {
            $roots = New-Object System.Collections.Generic.List[string]
            foreach ($r in @($val)) {
                if ($null -eq $r) { continue }
                $check = Test-FVSharedRoot -Path ([string]$r)
                if ($check.Ok) { $roots.Add($check.Path) } else { $warnings.Add("Shared root '$r' rejected: $($check.Code)") }
            }
            $cfg[$name] = $roots.ToArray()
        }
    }

    if ($cfg.MinVaultSizeGB -gt $cfg.MaxVaultSizeGB) {
        $warnings.Add('MinVaultSizeGB > MaxVaultSizeGB; using defaults.')
        $d = Get-FVDefaultConfig
        $cfg.MinVaultSizeGB = $d.MinVaultSizeGB
        $cfg.MaxVaultSizeGB = $d.MaxVaultSizeGB
    }
    if ($cfg.BackoffStartAfter -ge $cfg.MaxFailedAttempts) {
        $warnings.Add('BackoffStartAfter must be lower than MaxFailedAttempts; using defaults.')
        $d = Get-FVDefaultConfig
        $cfg.BackoffStartAfter = $d.BackoffStartAfter
        $cfg.MaxFailedAttempts = $d.MaxFailedAttempts
    }
    return [pscustomobject]@{ Config = [pscustomobject]$cfg; Warnings = $warnings.ToArray() }
}

# ---------------------------------------------------------------------------
# Path handling (Windows semantics, implemented by hand so it is deterministic
# and testable on any OS). Fails closed: anything unusual is rejected rather
# than "resolved".
# ---------------------------------------------------------------------------
function ConvertTo-FVNormalizedPath {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path)

    $fail = { param($c) [pscustomobject]@{ Ok = $false; Path = $null; Code = $c } }

    if ([string]::IsNullOrEmpty($Path)) { return (& $fail 'Empty') }
    if ($Path.Length -gt 240) { return (& $fail 'TooLong') }
    if ($Path -ne $Path.Trim()) { return (& $fail 'Whitespace') }
    foreach ($ch in $Path.ToCharArray()) {
        if ([int]$ch -lt 32) { return (& $fail 'ControlChar') }
    }
    if ($Path -notmatch '^[A-Za-z]:[\\/]') { return (& $fail 'NotLocalDrivePath') }

    $drive = $Path.Substring(0, 1).ToUpperInvariant()
    $rest = $Path.Substring(3).Replace('/', '\')
    if ($rest.EndsWith('\')) { $rest = $rest.Substring(0, $rest.Length - 1) }
    if ($rest.Length -eq 0) { return (& $fail 'DriveRoot') }

    $segments = $rest.Split('\')
    foreach ($seg in $segments) {
        if ($seg.Length -eq 0) { return (& $fail 'EmptySegment') }
        if ($seg -eq '.' -or $seg -eq '..') { return (& $fail 'RelativeSegment') }
        if ($seg.Length -gt 255) { return (& $fail 'SegmentTooLong') }
        if ($seg.IndexOfAny([char[]]'<>:"|?*') -ge 0) { return (& $fail 'InvalidChar') }
        if ($seg.EndsWith('.') -or $seg.EndsWith(' ')) { return (& $fail 'TrailingDotOrSpace') }
        if ($seg -match '~\d') { return (& $fail 'ShortName') }
        $base = $seg.Split('.')[0].ToUpperInvariant()
        if ($script:FVReservedDeviceNames -contains $base) { return (& $fail 'ReservedName') }
    }
    return [pscustomobject]@{ Ok = $true; Path = ($drive + ':\' + ($segments -join '\')); Code = 'Ok' }
}

function Test-FVPathUnder {
    <# True when $Path is strictly inside $Root (both already normalized). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $r = $Root.TrimEnd('\') + '\'
    return $Path.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase) -and $Path.Length -gt $r.Length
}

function Test-FVPathEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$A, [Parameter(Mandatory)][string]$B)
    return [string]::Equals($A.TrimEnd('\'), $B.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-FVSharedRoot {
    <# Validates an admin-configured shared root such as C:\Shared or D:\Data\Teams. #>
    [CmdletBinding()]
    param([string]$Path)
    $n = ConvertTo-FVNormalizedPath -Path $Path
    if (-not $n.Ok) { return [pscustomobject]@{ Ok = $false; Path = $null; Code = $n.Code } }
    $p = $n.Path
    foreach ($sys in ($script:FVSystemPathRoots + @('C:\Users'))) {
        if ((Test-FVPathEqual $p $sys) -or (Test-FVPathUnder -Path $p -Root $sys) -or (Test-FVPathUnder -Path $sys -Root $p)) {
            return [pscustomobject]@{ Ok = $false; Path = $null; Code = 'SystemLocation' }
        }
    }
    return [pscustomobject]@{ Ok = $true; Path = $p; Code = 'Ok' }
}

function Get-FVPathScope {
    <#
        Decides whether a caller may protect $Path ($Path must be normalized).
        Returns Ok, Scope and Code. Scopes:
          Profile  inside the caller's own profile, including OneDrive (owner only)
          Local    anywhere else on a fixed local drive (owner only), from 0.3.0
          Shared   inside an admin-defined shared root (anyone on the PC with the password)
        $ProfilePath is the caller's profile root, resolved server-side from the
        caller's SID, never taken from the client. $ProfilesDirectory (usually
        C:\Users) and $OtherProfiles keep people out of each other's folders.
        $FixedDrives lists the letters of this PC's fixed drives; $null skips
        that check (unit tests).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][AllowEmptyString()][string]$ProfilePath,
        [string[]]$SharedRoots = @(),
        [bool]$AllowShared = $true,
        [string[]]$ExtraBlockedRoots = @(),
        [bool]$AllowOutsideProfile = $true,
        [string]$ProfilesDirectory = 'C:\Users',
        [AllowEmptyCollection()][string[]]$OtherProfiles = @(),
        [AllowNull()][string[]]$FixedDrives = $null
    )
    $deny = { param($c) [pscustomobject]@{ Ok = $false; Scope = $null; Code = $c } }
    $ok = { param($sc) [pscustomobject]@{ Ok = $true; Scope = $sc; Code = 'Ok' } }

    # 1. Never: Windows, programs, Folder Vault's own folders, system folders on any drive.
    foreach ($sys in ($script:FVSystemPathRoots + $ExtraBlockedRoots)) {
        if ([string]::IsNullOrEmpty($sys)) { continue }
        if ((Test-FVPathEqual $Path $sys) -or (Test-FVPathUnder -Path $Path -Root $sys)) { return (& $deny 'PathNotAllowed') }
    }
    $segsAll = $Path.Substring(3).Split('\')
    $top = $segsAll[0]
    if ($top.StartsWith('$') -or ($script:FVSystemTopFolders -contains $top)) { return (& $deny 'PathNotAllowed') }
    foreach ($s in $segsAll) { if ($s -ieq 'AppData') { return (& $deny 'PathNotAllowed') } }

    # 2. Only this PC's own fixed drives.
    if ($null -ne $FixedDrives) {
        $letter = $Path.Substring(0, 1)
        if (@($FixedDrives | Where-Object { $_ -ieq $letter }).Count -eq 0) { return (& $deny 'PathNotLocalDisk') }
    }

    # 3. Shared areas set up by IT.
    foreach ($root in $SharedRoots) {
        if ([string]::IsNullOrEmpty($root)) { continue }
        if (Test-FVPathEqual $Path $root) { return (& $deny 'PathWholeFolder') }
        if (Test-FVPathUnder -Path $Path -Root $root) {
            if (-not $AllowShared) { return (& $deny 'PathNotAllowed') }
            return (& $ok 'Shared')
        }
    }

    # 4. The caller's own profile.
    $own = $null
    if (-not [string]::IsNullOrEmpty($ProfilePath)) {
        $pn = ConvertTo-FVNormalizedPath -Path $ProfilePath
        if ($pn.Ok) { $own = $pn.Path }
    }
    if ($null -ne $own -and (Test-FVPathEqual $Path $own)) { return (& $deny 'PathWholeFolder') }
    if ($null -ne $own -and (Test-FVPathUnder -Path $Path -Root $own)) {
        $segs = $Path.Substring($own.Length + 1).Split('\')
        $first = $segs[0]
        if ($segs.Count -eq 1) {   # count-safe: String.Split always returns an array
            if ($first.StartsWith('.')) { return (& $deny 'PathNotAllowed') }
            if ($first -like 'OneDrive*') { return (& $deny 'PathWholeFolder') }
            foreach ($k in $script:FVKnownProfileFolders) { if ($first -ieq $k) { return (& $deny 'PathWholeFolder') } }
        }
        if ($segs.Count -eq 2 -and $first -like 'OneDrive*') {   # count-safe: String.Split always returns an array
            # OneDrive\Documents, OneDrive\Desktop... (folders Windows backs up to OneDrive)
            foreach ($k in $script:FVKnownProfileFolders) { if ($segs[1] -ieq $k) { return (& $deny 'PathWholeFolder') } }
        }
        return (& $ok 'Profile')
    }

    # 5. Other people's profiles, and the folder that holds everyone's profiles.
    foreach ($o in @($OtherProfiles) + @($ProfilesDirectory)) {
        if ([string]::IsNullOrEmpty($o)) { continue }
        $on = ConvertTo-FVNormalizedPath -Path $o
        if (-not $on.Ok) { continue }
        if ((Test-FVPathEqual $Path $on.Path) -or (Test-FVPathUnder -Path $Path -Root $on.Path)) { return (& $deny 'PathOtherUser') }
    }
    if ($null -eq $own) { return (& $deny 'PathNotAllowed') }

    # 6. Anywhere else on a fixed local drive, if IT allows it.
    if (-not $AllowOutsideProfile) { return (& $deny 'PathOutsideProfile') }
    return (& $ok 'Local')
}

function Get-FVMachineLayout {
    <#
        What the folder rules need to know about this PC: where profiles live,
        every profile folder (so nobody protects someone else's), and the
        letters of the fixed local drives (no USB sticks, DVDs or network drives).
        Read fresh each time, so new accounts and drives are seen at once.
    #>
    [CmdletBinding()]
    param()
    if (-not (Test-FVOnWindows)) { return [pscustomobject]@{ ProfilesDirectory = 'C:\Users'; Profiles = @(); FixedDrives = $null } }
    $list = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $dir = 'C:\Users'
    $profiles = New-Object System.Collections.Generic.List[string]
    try {
        $d = (Get-ItemProperty -LiteralPath $list -Name ProfilesDirectory -ErrorAction Stop).ProfilesDirectory
        if (-not [string]::IsNullOrEmpty([string]$d)) { $dir = [System.Environment]::ExpandEnvironmentVariables([string]$d) }
    } catch { Write-Verbose 'ProfilesDirectory not readable; using C:\Users' }
    foreach ($k in @(Get-ChildItem -LiteralPath $list -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -notmatch '^S-1-5-21-') { continue }
        $p = $k.GetValue('ProfileImagePath')
        if (-not [string]::IsNullOrEmpty([string]$p)) { $profiles.Add([System.Environment]::ExpandEnvironmentVariables([string]$p)) }
    }
    $fixed = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed } | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    return [pscustomobject]@{ ProfilesDirectory = $dir; Profiles = $profiles.ToArray(); FixedDrives = $fixed }
}

function Get-FVProtectWarnings {
    <#
        Plain-English warnings the person must accept before a folder is
        protected, from the result of Get-FVFolderCheck. Empty when none apply.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Check)
    $w = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Check.PSObject.Properties['Synced'] -and [bool]$Check.Synced) {
        $w.Add('This folder is in OneDrive. Once it is protected, OneDrive stops syncing it: the folder is removed from OneDrive online and from your other devices, and OneDrive keeps the old copies in its recycle bin for up to 30 days (93 days for work or school accounts). The protected copy is kept only on this computer, so make sure it is backed up another way.')
    }
    if ($null -ne $Check.PSObject.Properties['Scope'] -and [string]$Check.Scope -eq 'Local') {
        $w.Add('This folder is outside your own user folder. Once it is protected, only you can open it with the password. If other people use this folder, choose No and ask IT to set it up as a shared folder instead.')
    }
    return $w.ToArray()
}

function Resolve-FVPathScope {
    <# Get-FVPathScope with this PC's profiles and fixed drives filled in. Used by the broker and the window alike. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][AllowEmptyString()][string]$ProfilePath,
        [string[]]$SharedRoots = @(),
        [bool]$AllowShared = $true,
        [bool]$AllowOutsideProfile = $true,
        [string[]]$ExtraBlockedRoots = @(),
        $Layout
    )
    if ($null -eq $Layout) { $Layout = Get-FVMachineLayout }
    $mine = ''
    if (-not [string]::IsNullOrEmpty($ProfilePath)) { $mine = $ProfilePath.TrimEnd('\') }
    $others = @(@($Layout.Profiles) | Where-Object { -not [string]::IsNullOrEmpty($_) -and ($_.TrimEnd('\') -ine $mine) })
    $fixed = $null
    if ($null -ne $Layout.FixedDrives) { $fixed = [string[]]@($Layout.FixedDrives) }
    return (Get-FVPathScope -Path $Path -ProfilePath $ProfilePath -SharedRoots $SharedRoots -AllowShared $AllowShared -ExtraBlockedRoots $ExtraBlockedRoots `
            -AllowOutsideProfile $AllowOutsideProfile -ProfilesDirectory ([string]$Layout.ProfilesDirectory) -OtherProfiles ([string[]]$others) -FixedDrives $fixed)
}

function Test-FolderVaultOverlap {
    <# True when $Path equals, is inside, or contains any existing vault path. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path, [string[]]$ExistingPaths = @())
    foreach ($e in $ExistingPaths) {
        if ([string]::IsNullOrEmpty($e)) { continue }
        if ((Test-FVPathEqual $Path $e) -or (Test-FVPathUnder -Path $Path -Root $e) -or (Test-FVPathUnder -Path $e -Root $Path)) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Names, sizes, ids
# ---------------------------------------------------------------------------
function Test-FolderVaultName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    if ($Name.Length -gt 40) { return $false }
    if ($Name -ne $Name.Trim()) { return $false }
    return ($Name -match "^[\p{L}\p{N} _\-\.\(\)']+$")
}

function Test-FVGuid {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    return ($Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Test-FVRecoveryKeyFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    return ($Value -match '^\d{6}(-\d{6}){7}$')
}

function Get-FVSuggestedSizeGB {
    <# Suggests a vault size: 3x current content, at least the configured minimum, rounded up to whole GB. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][long]$ContentBytes, [Parameter(Mandatory)]$Config)
    $gb = [math]::Ceiling(($ContentBytes * 3.0) / 1GB)
    if ($gb -lt $Config.DefaultVaultSizeGB) { $gb = $Config.DefaultVaultSizeGB }
    if ($gb -lt $Config.MinVaultSizeGB) { $gb = $Config.MinVaultSizeGB }
    if ($gb -gt $Config.MaxVaultSizeGB) { $gb = $Config.MaxVaultSizeGB }
    return [int]$gb
}

function Test-FVSizeRequest {
    <#
        Validates a requested vault size against policy, the content to be moved,
        and free space on the drive that holds the VHDX (expandable VHDX only
        consumes what is used, but the content must fit now with headroom).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][long]$SizeGB,
        [Parameter(Mandatory)][long]$ContentBytes,
        [Parameter(Mandatory)][long]$FreeBytes,
        [Parameter(Mandatory)]$Config
    )
    if ($SizeGB -lt $Config.MinVaultSizeGB -or $SizeGB -gt $Config.MaxVaultSizeGB) {
        return [pscustomobject]@{ Ok = $false; Code = 'SizeInvalid' }
    }
    # NTFS + BitLocker metadata overhead: keep 15% + 256 MB inside the volume.
    $usable = ($SizeGB * 1GB * 0.85) - 256MB
    if ($ContentBytes -gt $usable) { return [pscustomobject]@{ Ok = $false; Code = 'SizeInvalid' } }
    # Copy needs the content again on the same disk, plus 1 GB headroom.
    $need = [long]($ContentBytes * 1.1) + 1GB
    if ($FreeBytes -lt $need) { return [pscustomobject]@{ Ok = $false; Code = 'InsufficientSpace' } }
    return [pscustomobject]@{ Ok = $true; Code = 'Ok' }
}

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
function Test-FVPassword {
    <#
        Server-side password policy. Returns Ok and a list of problem codes.
        The UI calls the same function for instant feedback, but only the
        broker's verdict counts.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Password,
        [AllowNull()][AllowEmptyString()][string]$UserName,
        [Parameter(Mandatory)]$Config
    )
    $problems = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrEmpty($Password)) {
        $problems.Add('Empty')
        return [pscustomobject]@{ Ok = $false; Problems = $problems.ToArray() }
    }
    if ($Password.Length -lt $Config.MinPasswordLength) { $problems.Add('TooShort') }
    if ($Password.Length -gt 256) { $problems.Add('TooLong') }
    foreach ($ch in $Password.ToCharArray()) {
        $c = [int]$ch
        if ($c -lt 0x20 -or $c -gt 0x7E) { $problems.Add('InvalidCharacters'); break }
    }
    if ($Password -ne $Password.Trim()) { $problems.Add('EdgeWhitespace') }

    $distinct = @($Password.ToLowerInvariant().ToCharArray() | Select-Object -Unique).Count
    if ($distinct -lt 5) { $problems.Add('TooRepetitive') }

    if (Test-FVSequential -Value $Password) { $problems.Add('Sequential') }

    $lower = $Password.ToLowerInvariant()
    if (-not [string]::IsNullOrEmpty($UserName)) {
        $u = $UserName
        if ($u.Contains('\')) { $u = $u.Substring($u.LastIndexOf('\') + 1) }
        $u = $u.ToLowerInvariant()
        if ($u.Length -ge 3 -and $lower.Contains($u)) { $problems.Add('ContainsUserName') }
    }
    $local = @()
    if ($null -ne $Config.PSObject.Properties['LocalWeakWords']) { $local = @($Config.LocalWeakWords | Where-Object { -not [string]::IsNullOrEmpty($_) }) }
    foreach ($w in (@($script:FVCommonWords) + $local)) {
        if ($lower.Contains($w)) {
            $remainder = $lower.Replace($w, '')
            if ($remainder.Length -lt 8) { $problems.Add('Common'); break }
        }
    }
    return [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = $problems.ToArray() }
}

function Test-FVSequential {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Value)
    if ($Value.Length -lt 4) { return $false }
    $up = $true; $down = $true
    for ($i = 1; $i -lt $Value.Length; $i++) {
        $d = [int]$Value[$i] - [int]$Value[$i - 1]
        if ($d -ne 1) { $up = $false }
        if ($d -ne -1) { $down = $false }
    }
    return ($up -or $down)
}

function Get-FVPasswordProblemText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Code, [int]$MinLength = 12)
    switch ($Code) {
        'Empty'             { return 'Enter a password.' }
        'TooShort'          { return "Use at least $MinLength characters. A short sentence works well, e.g. 'Mangoes ripen in March 2027'." }
        'TooLong'           { return 'Use at most 256 characters.' }
        'InvalidCharacters' { return 'Use only English letters, numbers, spaces and normal keyboard symbols.' }
        'EdgeWhitespace'    { return 'Do not start or end the password with a space.' }
        'TooRepetitive'     { return 'Use more different characters.' }
        'Sequential'        { return 'Do not use simple sequences like 123456 or abcdef.' }
        'ContainsUserName'  { return 'Do not include your Windows user name.' }
        'Common'            { return 'That password is too common or easy to guess.' }
        'Mismatch'          { return 'The two passwords do not match.' }
        default             { return 'The password does not meet the rules.' }
    }
}

function Get-FVPasswordScore {
    <# 0 (very weak) .. 4 (strong), for the strength meter only. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowNull()][AllowEmptyString()][string]$Password)
    if ([string]::IsNullOrEmpty($Password)) { return 0 }
    $pool = 0
    if ($Password -cmatch '[a-z]') { $pool += 26 }
    if ($Password -cmatch '[A-Z]') { $pool += 26 }
    if ($Password -match '[0-9]') { $pool += 10 }
    if ($Password -match '[^a-zA-Z0-9]') { $pool += 33 }
    if ($pool -eq 0) { return 0 }
    $distinct = @($Password.ToCharArray() | Select-Object -Unique).Count
    $effectiveLen = [math]::Min($Password.Length, $distinct * 2)
    $bits = $effectiveLen * [math]::Log($pool, 2)
    if ($bits -lt 40) { return 1 }
    if ($bits -lt 60) { return 2 }
    if ($bits -lt 80) { return 3 }
    return 4
}

# ---------------------------------------------------------------------------
# Failed-attempt throttling (state is persisted in the vault record)
# ---------------------------------------------------------------------------
function ConvertTo-FVUtc {
    <# Accepts DateTime or ISO-8601 string (PS 7 auto-converts JSON dates, PS 5.1 does not). #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = [string]$Value
    if ([string]::IsNullOrEmpty($s)) { return $null }
    $dt = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt }
    return $null
}

function ConvertTo-FVIso {
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    return ([datetime]$Value).ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-FVThrottle {
    [CmdletBinding()]
    param(
        [int]$FailedCount = 0,
        [AllowNull()]$LastFailureUtc,
        [AllowNull()]$LockoutUntilUtc,
        [Parameter(Mandatory)][datetime]$NowUtc,
        [Parameter(Mandatory)]$Config
    )
    $lockout = ConvertTo-FVUtc $LockoutUntilUtc
    if ($null -ne $lockout -and $lockout -gt $NowUtc) {
        return [pscustomobject]@{ Allowed = $false; Code = 'LockedOut'; RetryAfterSeconds = [int][math]::Ceiling(($lockout - $NowUtc).TotalSeconds) }
    }
    if ($FailedCount -ge $Config.BackoffStartAfter) {
        $exp = [math]::Min(6, $FailedCount - $Config.BackoffStartAfter)
        $delay = [math]::Min(60, [math]::Pow(2, $exp))
        $last = ConvertTo-FVUtc $LastFailureUtc
        if ($null -ne $last) {
            $elapsed = ($NowUtc - $last).TotalSeconds
            if ($elapsed -lt $delay) {
                return [pscustomobject]@{ Allowed = $false; Code = 'Throttled'; RetryAfterSeconds = [int][math]::Ceiling($delay - $elapsed) }
            }
        }
    }
    return [pscustomobject]@{ Allowed = $true; Code = 'Ok'; RetryAfterSeconds = 0 }
}

function Get-FVFailureUpdate {
    <# Returns the new throttle state after an attempt. #>
    [CmdletBinding()]
    param(
        [int]$FailedCount = 0,
        [Parameter(Mandatory)][bool]$Success,
        [Parameter(Mandatory)][datetime]$NowUtc,
        [Parameter(Mandatory)]$Config
    )
    if ($Success) {
        return [pscustomobject]@{ FailedCount = 0; LastFailureUtc = $null; LockoutUntilUtc = $null; LockedOutNow = $false }
    }
    $n = $FailedCount + 1
    $lock = $null
    $now = $false
    if ($n -ge $Config.MaxFailedAttempts) {
        $lock = ConvertTo-FVIso ($NowUtc.AddMinutes($Config.LockoutMinutes))
        $now = $true
    }
    return [pscustomobject]@{ FailedCount = $n; LastFailureUtc = (ConvertTo-FVIso $NowUtc); LockoutUntilUtc = $lock; LockedOutNow = $now }
}

# ---------------------------------------------------------------------------
# Protocol: framing, requests, responses
# ---------------------------------------------------------------------------
function Read-FVExact {
    param([System.IO.Stream]$Stream, [int]$Count, [int]$TimeoutMs)
    $buf = New-Object byte[] $Count
    $off = 0
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ($off -lt $Count) {
        $remaining = [int]($deadline - [datetime]::UtcNow).TotalMilliseconds
        if ($remaining -le 0) { throw [System.TimeoutException]::new('Read timed out') }
        $ar = $Stream.BeginRead($buf, $off, $Count - $off, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($remaining)) {
            throw [System.TimeoutException]::new('Read timed out')
        }
        $n = $Stream.EndRead($ar)
        if ($n -le 0) { throw [System.IO.EndOfStreamException]::new('Connection closed') }
        $off += $n
    }
    return , $buf
}

function Write-FVFrame {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [Parameter(Mandatory)]$Object)
    $json = ConvertTo-Json -InputObject $Object -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt $script:FVMaxFrameBytes) { throw [System.InvalidOperationException]::new('Frame too large') }
    $len = [System.BitConverter]::GetBytes([int]$bytes.Length)
    if (-not [System.BitConverter]::IsLittleEndian) { [array]::Reverse($len) }
    $Stream.Write($len, 0, 4)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Read-FVFrame {
    <# Reads one frame. Throws on timeout, oversize, truncation or invalid JSON. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [int]$TimeoutMs = 10000)
    $lenBytes = Read-FVExact -Stream $Stream -Count 4 -TimeoutMs $TimeoutMs
    if (-not [System.BitConverter]::IsLittleEndian) { [array]::Reverse($lenBytes) }
    $len = [System.BitConverter]::ToInt32($lenBytes, 0)
    if ($len -le 0 -or $len -gt $script:FVMaxFrameBytes) { throw [System.IO.InvalidDataException]::new('Bad frame length') }
    $body = Read-FVExact -Stream $Stream -Count $len -TimeoutMs $TimeoutMs
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)   # throw on invalid bytes
    $json = $utf8.GetString($body)
    return (ConvertFrom-Json -InputObject $json)
}

# Allowed fields per operation, with type and max length.
$script:FVRequestSchema = @{
    'Ping'           = @{}
    'GetPolicy'      = @{}
    'List'           = @{}
    'Create'         = @{ path = 'path'; name = 'name'; password = 'password'; sizeGB = 'int'; contentBytes = 'long' }
    'FinalizeCreate' = @{ id = 'guid' }
    'Unlock'         = @{ id = 'guid'; password = 'password' }
    'Lock'           = @{ id = 'guid'; force = 'bool' }
    'LockAll'        = @{ force = 'bool' }
    'ChangePassword' = @{ id = 'guid'; password = 'password'; newPassword = 'password' }
    'Remove'         = @{ id = 'guid'; password = 'password' }
    'AdminList'      = @{}
    'AdminReset'     = @{ id = 'guid'; recoveryKey = 'recovery'; newPassword = 'password' }
}

function Get-FVOperations { return @($script:FVRequestSchema.Keys) }

function Test-FVRequest {
    <#
        Strict schema validation. Unknown fields, wrong types, missing fields and
        oversized strings are all rejected. Returns a clean hashtable.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Request)
    $bad = { param($c) [pscustomobject]@{ Ok = $false; Code = $c; Request = $null } }
    if ($null -eq $Request -or -not ($Request -is [pscustomobject])) { return (& $bad 'BadRequest') }

    $props = @{}
    foreach ($p in $Request.PSObject.Properties) { $props[$p.Name] = $p.Value }

    if (-not $props.ContainsKey('v') -or -not ($props['v'] -is [int] -or $props['v'] -is [long])) { return (& $bad 'BadRequest') }
    if ([int]$props['v'] -ne $script:FVProtocolVersion) { return (& $bad 'UnsupportedVersion') }
    if (-not $props.ContainsKey('op') -or -not ($props['op'] -is [string])) { return (& $bad 'BadRequest') }
    $op = [string]$props['op']
    if (-not $script:FVRequestSchema.ContainsKey($op)) { return (& $bad 'BadRequest') }
    # Case-sensitive op match (hashtable lookup above is case-insensitive).
    $canonical = @($script:FVRequestSchema.Keys | Where-Object { $_ -ceq $op })
    if ($canonical.Count -ne 1) { return (& $bad 'BadRequest') }

    $schema = $script:FVRequestSchema[$op]
    $clean = @{ v = [int]$props['v']; op = $op }
    foreach ($k in $props.Keys) {
        if ($k -ceq 'v' -or $k -ceq 'op') { continue }
        if (-not ($schema.Keys -ccontains $k)) { return (& $bad 'BadRequest') }
    }
    foreach ($field in $schema.Keys) {
        if (-not $props.ContainsKey($field)) { return (& $bad 'BadRequest') }
        $val = $props[$field]
        switch ($schema[$field]) {
            'path'     { if (-not ($val -is [string]) -or $val.Length -gt 260) { return (& $bad 'BadRequest') } }
            'name'     { if (-not ($val -is [string]) -or $val.Length -gt 64) { return (& $bad 'BadRequest') } }
            'password' { if (-not ($val -is [string]) -or $val.Length -gt 512) { return (& $bad 'BadRequest') } }
            'guid'     { if (-not ($val -is [string]) -or -not (Test-FVGuid $val)) { return (& $bad 'BadRequest') } }
            'recovery' { if (-not ($val -is [string]) -or $val.Length -gt 64) { return (& $bad 'BadRequest') } }
            'bool'     { if (-not ($val -is [bool])) { return (& $bad 'BadRequest') } }
            'int'      {
                if (-not ($val -is [int] -or $val -is [long])) { return (& $bad 'BadRequest') }
                if ([long]$val -lt 0 -or [long]$val -gt 1000000) { return (& $bad 'BadRequest') }
                $val = [int]$val
            }
            'long'     {
                if (-not ($val -is [int] -or $val -is [long])) { return (& $bad 'BadRequest') }
                if ([long]$val -lt 0 -or [long]$val -gt 70368744177664) { return (& $bad 'BadRequest') }
                $val = [long]$val
            }
        }
        $clean[$field] = $val
    }
    return [pscustomobject]@{ Ok = $true; Code = 'Ok'; Request = $clean }
}

function New-FVResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$Ok,
        [string]$Code = 'Ok',
        [AllowNull()]$Data = $null,
        [string]$Message
    )
    if ([string]::IsNullOrEmpty($Message)) { $Message = Get-FVMessage -Code $Code }
    if ($null -eq $Data) { $Data = @{} }
    return [ordered]@{ ok = $Ok; code = $Code; message = $Message; data = $Data }
}

# ---------------------------------------------------------------------------
# Logging with a field allowlist (secrets cannot be logged by construction)
# ---------------------------------------------------------------------------
$script:FVLogFieldAllowList = @('op', 'vaultId', 'jobId', 'code', 'user', 'sid', 'reason', 'stage', 'count', 'scope', 'retryAfter', 'detail')
$script:FVLogSink = $null
$script:FVRedactions = @()

function Set-FVLogRedaction {
    <#
        Secrets of the request being handled. Any occurrence in a log line
        (for example inside an exception message) is replaced with ***.
        Defence in depth on top of the field allow-list.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Secrets = @())
    $script:FVRedactions = @($Secrets | Where-Object { -not [string]::IsNullOrEmpty($_) -and $_.Length -ge 4 })
}

function Set-FVLogSink {
    <# $Sink is a scriptblock receiving (level, eventId, message). #>
    [CmdletBinding()]
    param([AllowNull()][scriptblock]$Sink)
    $script:FVLogSink = $Sink
}

function Format-FVLogValue {
    param($Value)
    $s = [string]$Value
    $s = $s -replace '[\r\n\t]', ' '
    if ($s.Length -gt 300) { $s = $s.Substring(0, 300) + '...' }
    return $s
}

function Write-FVLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Information', 'Warning', 'Error')][string]$Level = 'Information',
        [int]$EventId = 1,
        [Parameter(Mandatory)][string]$Name,
        [hashtable]$Fields = @{}
    )
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add("event=$Name")
    foreach ($k in ($Fields.Keys | Sort-Object)) {
        if ($script:FVLogFieldAllowList -ccontains $k) {
            $parts.Add("$k=" + (Format-FVLogValue $Fields[$k]))
        }
    }
    $msg = $parts -join ' '
    foreach ($secret in $script:FVRedactions) { $msg = $msg.Replace($secret, '***') }
    if ($null -ne $script:FVLogSink) {
        try { & $script:FVLogSink $Level $EventId $msg } catch { Write-Verbose "log sink failed: $($_.Exception.Message)" }
    } else {
        Write-Verbose "[$Level][$EventId] $msg"
    }
}

# ---------------------------------------------------------------------------
# Vault registry (JSON file, written atomically)
# ---------------------------------------------------------------------------
$script:FolderVaultFields = @(
    'Id', 'Name', 'FolderPath', 'Scope', 'OwnerSid', 'VhdxPath', 'State', 'CreatedUtc', 'SizeGB',
    'FailedCount', 'LastFailureUtc', 'LockoutUntilUtc', 'UnlockedBySid', 'UnlockedAtUtc', 'LastError'
)

function New-FolderVaultRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$FolderPath,
        [Parameter(Mandatory)][ValidateSet('Profile', 'Local', 'Shared')][string]$Scope,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][string]$VhdxPath,
        [Parameter(Mandatory)][int]$SizeGB,
        [string]$State = 'Creating'
    )
    return [pscustomobject][ordered]@{
        Id = $Id; Name = $Name; FolderPath = $FolderPath; Scope = $Scope; OwnerSid = $OwnerSid
        VhdxPath = $VhdxPath; State = $State; CreatedUtc = (ConvertTo-FVIso ([datetime]::UtcNow)); SizeGB = $SizeGB
        FailedCount = 0; LastFailureUtc = $null; LockoutUntilUtc = $null
        UnlockedBySid = $null; UnlockedAtUtc = $null; LastError = $null
    }
}

function ConvertTo-FolderVaultRecord {
    param($Obj)
    $rec = [ordered]@{}
    foreach ($f in $script:FolderVaultFields) {
        $v = $null
        $p = $Obj.PSObject.Properties[$f]
        if ($null -ne $p) { $v = $p.Value }
        if ($f -like '*Utc' -and $null -ne $v) { $v = ConvertTo-FVIso (ConvertTo-FVUtc $v) }
        $rec[$f] = $v
    }
    if ($null -eq $rec.FailedCount) { $rec.FailedCount = 0 }
    $rec.FailedCount = [int]$rec.FailedCount
    if ($null -ne $rec.SizeGB) { $rec.SizeGB = [int]$rec.SizeGB }
    return [pscustomobject]$rec
}

function Read-FVRegistry {
    <# Missing file = empty registry. Corrupt file = Ok $false (caller must fail closed, never overwrite). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Ok = $true; Code = 'Ok'; Vaults = @() }
    }
    try {
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        $obj = ConvertFrom-Json -InputObject $text
        if ($null -eq $obj -or $null -eq $obj.PSObject.Properties['vaults']) { throw 'missing vaults' }
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($v in @($obj.vaults)) {
            if ($null -eq $v) { continue }
            $r = ConvertTo-FolderVaultRecord $v
            if (-not (Test-FVGuid $r.Id)) { throw 'bad id' }
            $list.Add($r)
        }
        return [pscustomobject]@{ Ok = $true; Code = 'Ok'; Vaults = $list.ToArray() }
    } catch {
        return [pscustomobject]@{ Ok = $false; Code = 'RegistryCorrupt'; Vaults = @() }
    }
}

function Save-FVRegistry {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path, [AllowEmptyCollection()][object[]]$Vaults = @())
    if (-not $PSCmdlet.ShouldProcess($Path, 'Save vault registry')) { return }
    $doc = [ordered]@{ version = 1; vaults = @($Vaults | ForEach-Object { ConvertTo-FolderVaultRecord $_ }) }
    $json = ConvertTo-Json -InputObject $doc -Depth 6
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) {
        [System.IO.File]::Replace($tmp, $Path, "$Path.bak")
    } else {
        [System.IO.File]::Move($tmp, $Path)
    }
}

# ---------------------------------------------------------------------------
# File tree helpers. These never follow reparse points (junctions, symlinks,
# mount points, cloud placeholders).
# ---------------------------------------------------------------------------
# Cloud files (OneDrive, SharePoint and other sync apps using the Windows Cloud
# Files API) are reparse points too, but they hold the file's own data, so
# they are not links. Windows shows them to PowerShell as reparse points
# ("exposed placeholders"). IO_REPARSE_TAG_CLOUD is 0x9000001A, and its
# variants differ only in bits 12 to 15 (IO_REPARSE_TAG_CLOUD_MASK 0x0000F000).
$script:FVReparseTagReader = $null
$script:FVNativeReparseSource = @"
using System;
using System.Runtime.InteropServices;
namespace FolderVault {
  public static class ReparseTag {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WIN32_FIND_DATAW {
      // FILETIME is two 32-bit halves. Declaring it as a long would add 4 bytes of padding
      // after dwFileAttributes and shift every later field, including dwReserved0.
      public uint dwFileAttributes;
      public uint ftCreationLow; public uint ftCreationHigh; public uint ftLastAccessLow; public uint ftLastAccessHigh;
      public uint ftLastWriteLow; public uint ftLastWriteHigh;
      public uint nFileSizeHigh; public uint nFileSizeLow; public uint dwReserved0; public uint dwReserved1;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstFileW(string lpFileName, out WIN32_FIND_DATAW lpFindFileData);
    [DllImport("kernel32.dll")]
    static extern bool FindClose(IntPtr hFindFile);
    // Returns the reparse tag, 0 when the item is not a reparse point, or 0xFFFFFFFF on error.
    public static uint Get(string path) {
      WIN32_FIND_DATAW d;
      IntPtr h = FindFirstFileW(path, out d);
      if (h == new IntPtr(-1)) { return 0xFFFFFFFF; }
      FindClose(h);
      if ((d.dwFileAttributes & 0x400) == 0) { return 0; }
      return d.dwReserved0;
    }
  }
}
"@

function Get-FVReparseTag {
    <#
        The reparse tag of a file or folder (0 if none). On first use this
        compiles a small helper with the C# compiler that is part of .NET
        Framework. If that is not possible, it returns 0xFFFFFFFF ("unknown"),
        and every reparse point is then treated as a link and refused.
    #>
    [CmdletBinding()]
    [OutputType([uint32])]
    param([Parameter(Mandatory)][string]$Path)
    if ($null -eq $script:FVReparseTagReader) {
        $script:FVReparseTagReader = 'unavailable'
        if (Test-FVOnWindows) {
            try {
                if (-not ('FolderVault.ReparseTag' -as [type])) { Add-Type -TypeDefinition $script:FVNativeReparseSource -ErrorAction Stop }
                $script:FVReparseTagReader = 'ok'
            } catch { Write-Verbose "Reparse tag helper unavailable: $($_.Exception.Message)" }
        }
    }
    if ($script:FVReparseTagReader -ne 'ok') { return [uint32]4294967295 }   # 0xFFFFFFFF; PowerShell reads 0xFFFFFFFF as -1
    return [uint32](('FolderVault.ReparseTag' -as [type])::Get($Path))
}

function Test-FVOnWindows {
    [OutputType([bool])]
    param()
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Test-FVCloudTag {
    <# True for IO_REPARSE_TAG_CLOUD and its variants (0x9000x01A). #>
    [OutputType([bool])]
    param([uint32]$Tag)
    # 0xFFFF0FFF and 0x9000001A, written in decimal: PowerShell reads these hex literals as negative Int32.
    return ((([long]$Tag) -band 4294905855) -eq 2415919130)
}

function Test-FVIsCloudFile {
    <# True when $Item is a cloud sync placeholder (OneDrive and similar): a reparse point that holds data, not a link. #>
    param([System.IO.FileSystemInfo]$Item)
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { return $false }
    return (Test-FVCloudTag -Tag (Get-FVReparseTag -Path $Item.FullName))
}

function Test-FVIsReparse {
    <#
        True when $Item is a link of any kind (junction, symbolic link, mount
        point, or any reparse point Folder Vault does not recognise). Cloud sync
        placeholders are NOT links: they are ordinary files and folders kept
        in sync by OneDrive.
    #>
    param([System.IO.FileSystemInfo]$Item)
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { return $false }
    return (-not (Test-FVIsCloudFile $Item))
}

# File attributes that mean "the data is not on this computer" (online-only).
# FILE_ATTRIBUTE_OFFLINE 0x1000, RECALL_ON_OPEN 0x40000, RECALL_ON_DATA_ACCESS 0x400000.
$script:FVOnlineOnlyMask = 0x00441000

function Test-FVIsOnlineOnly {
    <# True for a FILE whose contents are only in the cloud. Folders are not counted: listing them fetches their contents. #>
    param([System.IO.FileSystemInfo]$Item)
    if ($Item -is [System.IO.DirectoryInfo]) { return $false }
    return ((([long]$Item.Attributes) -band $script:FVOnlineOnlyMask) -ne 0)
}

function Get-FVTreeInfo {
    <#
        Walks a tree without following reparse points. Returns counts, total
        bytes and the first few reparse points found (any reparse point means
        the folder is refused for protection).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string[]]$ExcludeTopLevel = @(), [int]$MaxReparseReport = 5)
    $root = New-Object System.IO.DirectoryInfo($Path)
    if (-not $root.Exists) { return [pscustomobject]@{ Exists = $false; Files = 0; Dirs = 0; Bytes = [long]0; ReparsePoints = @(); RootIsReparse = $false; CloudItems = 0; OnlineOnly = @() } }
    $reparse = New-Object System.Collections.Generic.List[string]
    $online = New-Object System.Collections.Generic.List[string]
    $files = 0; $dirs = 0; [long]$bytes = 0; $cloud = 0
    if (Test-FVIsCloudFile $root) { $cloud++ }
    $rootIsReparse = Test-FVIsReparse $root
    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    if (-not $rootIsReparse) { $stack.Push($root) }
    $isRoot = $true
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($item in $dir.EnumerateFileSystemInfos()) {
            if ($isRoot -and ($ExcludeTopLevel -contains $item.Name)) { continue }
            if (Test-FVIsReparse $item) {
                if ($reparse.Count -lt $MaxReparseReport) { $reparse.Add($item.FullName) } else { $reparse.Add('...') ; break }
                continue
            }
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $cloud++ }
            if (Test-FVIsOnlineOnly $item) { if ($online.Count -lt $MaxReparseReport) { $online.Add($item.FullName) } }
            if ($item -is [System.IO.DirectoryInfo]) { $dirs++; $stack.Push($item) }
            else { $files++; $bytes += ([System.IO.FileInfo]$item).Length }
        }
        $isRoot = $false
        if ($reparse.Count -gt $MaxReparseReport) { break }
    }
    return [pscustomobject]@{ Exists = $true; Files = $files; Dirs = $dirs; Bytes = $bytes; ReparsePoints = $reparse.ToArray(); RootIsReparse = $rootIsReparse; CloudItems = $cloud; OnlineOnly = $online.ToArray() }
}

function Remove-FVTreeContents {
    <#
        Deletes everything inside $Path but not $Path itself.
        Reparse points are removed as links only; their targets are never touched.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    $root = New-Object System.IO.DirectoryInfo($Path)
    if (-not $root.Exists) { return }
    if (Test-FVIsReparse $root) { throw [System.InvalidOperationException]::new('Refusing to empty a reparse point') }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Delete contents')) { return }
    foreach ($item in @($root.EnumerateFileSystemInfos())) { Remove-FVItemSafe -Item $item }
}

function Remove-FVItemSafe {
    param([System.IO.FileSystemInfo]$Item)
    if (Test-FVIsReparse $Item) {
        # Remove the link itself, never its target.
        if ($Item -is [System.IO.DirectoryInfo]) {
            try { [System.IO.Directory]::Delete($Item.FullName, $false) } catch { [System.IO.File]::Delete($Item.FullName) }
        } else {
            [System.IO.File]::Delete($Item.FullName)
        }
        return
    }
    if ($Item -is [System.IO.DirectoryInfo]) {
        foreach ($child in @($Item.EnumerateFileSystemInfos())) { Remove-FVItemSafe -Item $child }
        $Item.Attributes = [System.IO.FileAttributes]::Directory
        [System.IO.Directory]::Delete($Item.FullName, $false)
    } else {
        $Item.Attributes = [System.IO.FileAttributes]::Normal
        [System.IO.File]::Delete($Item.FullName)
    }
}

function Get-FVFileHash {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try { return [System.BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '') }
        finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
}

function Get-FVTreeManifest {
    <# relative path -> 'D' for directories, or 'F|<length>|<sha256 or ->' for files. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [ValidateSet('Hash', 'Size')][string]$Mode = 'Hash', [string[]]$ExcludeTopLevel = @())
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $root = New-Object System.IO.DirectoryInfo($Path)
    $rootFull = $root.FullName.TrimEnd([char[]]@('\', '/'))
    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $stack.Push($root)
    $isRoot = $true
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($item in $dir.EnumerateFileSystemInfos()) {
            if ($isRoot -and ($ExcludeTopLevel -contains $item.Name)) { continue }
            $rel = $item.FullName.Substring($rootFull.Length + 1).Replace('/', '\')
            if (Test-FVIsReparse $item) { $map[$rel] = 'R'; continue }
            if ($item -is [System.IO.DirectoryInfo]) { $map[$rel] = 'D'; $stack.Push($item) }
            else {
                $len = ([System.IO.FileInfo]$item).Length
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    # A cloud file (it got past Test-FVIsReparse): take the size of its data, as read.
                    $fs = [System.IO.File]::OpenRead($item.FullName)
                    try { $len = $fs.Length } finally { $fs.Dispose() }
                }
                $h = '-'
                if ($Mode -eq 'Hash') { $h = Get-FVFileHash -Path $item.FullName }
                $map[$rel] = "F|$len|$h"
            }
        }
        $isRoot = $false
    }
    return $map
}

function Compare-FVManifest {
    <# Every entry in $Source must exist identically in $Destination. Extra entries in Destination are allowed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Source, [Parameter(Mandatory)]$Destination)
    $missing = New-Object System.Collections.Generic.List[string]
    $mismatch = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Source.Keys) {
        if ($Source[$k] -eq 'R') { $mismatch.Add($k); continue }
        if (-not $Destination.ContainsKey($k)) { $missing.Add($k); continue }
        if ($Destination[$k] -ne $Source[$k]) { $mismatch.Add($k) }
    }
    return [pscustomobject]@{ Ok = ($missing.Count -eq 0 -and $mismatch.Count -eq 0); Missing = $missing.ToArray(); Mismatched = $mismatch.ToArray() }
}

# Rights that let someone change a file or folder. Read rights are left out on
# purpose: "Modify" and "Full control" also contain the read bits, so testing
# against those named groups wrongly flags read-only access (bug in 0.2.2).
# Used by the health check and by the installer's package check.
$script:WriteMask = [long](
    0x00000002 -bor   # WriteData / CreateFiles
    0x00000004 -bor   # AppendData / CreateDirectories
    0x00000010 -bor   # WriteExtendedAttributes
    0x00000040 -bor   # DeleteSubdirectoriesAndFiles
    0x00000100 -bor   # WriteAttributes
    0x00010000 -bor   # Delete
    0x00040000 -bor   # ChangePermissions (WRITE_DAC)
    0x00080000 -bor   # TakeOwnership (WRITE_OWNER)
    0x10000000 -bor   # GENERIC_ALL
    0x40000000)       # GENERIC_WRITE

function Test-FVGrantsWrite {
    <# True when a FileSystemRights value includes any right that allows changing things. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][long]$Rights)
    return (($Rights -band $script:WriteMask) -ne 0)
}

function Invoke-FVNative {
    <#
        Runs a Windows program and returns its exit code and output.
        Windows PowerShell 5.1 turns anything a program writes to its error
        output into an error record, and into a STOPPING error when the
        caller's ErrorActionPreference is Stop. Every call to diskpart,
        mountvol, robocopy and reg goes through here, so a warning from one of
        them can never abort an operation half-way (audit fix A-28).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    $out = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    return [pscustomobject]@{ ExitCode = [int]$LASTEXITCODE; Output = $out; Text = (($out -join "`r`n").Trim()) }
}

function Get-FVVolumeSystemNames { return $script:FVVolumeSystemNames }

Export-ModuleMember -Function @(
    'Test-FVGrantsWrite', 'Invoke-FVNative',
    'Join-FVPath', 'Get-FVMessage', 'Get-FVPipeName', 'Get-FVProtocolVersion', 'Get-FVProductVersion', 'Get-FVMaxFrameBytes',
    'Get-FVPaths', 'Get-FVDefaultConfig', 'ConvertTo-FVConfig',
    'Get-FVMachineLayout', 'Get-FVReparseTag', 'Test-FVCloudTag', 'Test-FVIsCloudFile', 'Test-FVIsOnlineOnly', 'Test-FVOnWindows',
    'ConvertTo-FVNormalizedPath', 'Test-FVPathUnder', 'Test-FVPathEqual', 'Test-FVSharedRoot', 'Get-FVPathScope', 'Resolve-FVPathScope', 'Get-FVProtectWarnings', 'Test-FolderVaultOverlap',
    'Test-FolderVaultName', 'Test-FVGuid', 'Test-FVRecoveryKeyFormat', 'Get-FVSuggestedSizeGB', 'Test-FVSizeRequest',
    'Test-FVPassword', 'Test-FVSequential', 'Get-FVPasswordProblemText', 'Get-FVPasswordScore',
    'ConvertTo-FVUtc', 'ConvertTo-FVIso', 'Get-FVThrottle', 'Get-FVFailureUpdate',
    'Write-FVFrame', 'Read-FVFrame', 'Get-FVOperations', 'Test-FVRequest', 'New-FVResponse',
    'Set-FVLogSink', 'Set-FVLogRedaction', 'Write-FVLog',
    'New-FolderVaultRecord', 'ConvertTo-FolderVaultRecord', 'Read-FVRegistry', 'Save-FVRegistry',
    'Test-FVIsReparse', 'Get-FVTreeInfo', 'Remove-FVTreeContents', 'Get-FVFileHash', 'Get-FVTreeManifest', 'Compare-FVManifest', 'Get-FVVolumeSystemNames'
)
