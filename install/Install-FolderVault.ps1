#Requires -Version 5.1
<#
.SYNOPSIS
    Installs or updates Folder Vault on one Windows 10/11 Pro, Enterprise or Education PC.

.DESCRIPTION
    The easy way: put the client's recovery certificate (.cer) in the Folder Vault
    folder and double-click Install.cmd. Windows asks for administrator
    permission, the installer checks the PC, asks at most two questions and
    finishes in about a minute.

    Scripted use (for example from an RMM tool), from an elevated Windows PowerShell 5.1:
        .\install\Install-FolderVault.ps1 -EscrowCertificate .\escrow.cer [-SharedRoot C:\Shared] [-NoTrayIcon]

    What it does:
      1. Checks the PC (edition, BitLocker, drive C: encryption, free space).
      2. Stops an older Folder Vault if one is running (protected folders lock).
      3. Copies Folder Vault to C:\Program Files\FolderVault (only administrators can change it).
      4. Creates C:\ProgramData\FolderVault (only SYSTEM and administrators can open it)
         and installs the recovery certificate (public key only).
      5. Registers the "Folder Vault Broker" background task (runs as SYSTEM, low priority).
      6. Adds the Explorer right-click items, Start menu shortcuts, the tray icon
         and an entry in Settings > Apps so Folder Vault can be removed like any program.
      7. Confirms the background service answers, and records file fingerprints
         for later integrity checks.

.PARAMETER EscrowCertificate
    The client's recovery certificate (.cer). If left out, the installer looks
    for exactly one .cer file next to Install.cmd.

.PARAMETER SharedRoot
    Folders (for example C:\Shared) where staff may create shared protected folders.

.PARAMETER FolderRule
    Which folders staff may protect. 'AnyFolder' (the default from 0.3.0):
    any of their own folders on this PC's fixed drives, including OneDrive
    and folders such as D:\Accounts. 'UserFoldersOnly': only folders inside
    their own user folder. Left out, an update keeps the current setting.

.PARAMETER NoTrayIcon
    Do not start the tray icon at sign-in. Folders still lock automatically;
    people use the right-click menu and the Start menu instead. Lightest option.

.PARAMETER InactivityLockMinutes
    Optional. Lock the screen after this many idle minutes (protected folders
    lock with it). Default 0: Windows' own screen lock settings are used, and
    a screen lock time set by an earlier Folder Vault installer is removed.

.PARAMETER AllowUnencryptedSystemDrive
    Install even though drive C: is not BitLocker-encrypted. Not recommended.

.PARAMETER AllowWritablePackageFolder
    Install even though people other than administrators could have changed
    the Folder Vault folder this is run from. Not recommended: unzip the release zip file
    afresh instead (see SETUP-GUIDE).

.PARAMETER Interactive
    Used by Install.cmd: asks questions and waits for Enter at the end.
#>
[CmdletBinding()]
param(
    [string]$EscrowCertificate,
    [string[]]$SharedRoot = @(),
    [ValidateSet('AnyFolder', 'UserFoldersOnly')][string]$FolderRule,
    [switch]$NoTrayIcon,
    [switch]$AllowUnencryptedSystemDrive,
    [switch]$AllowWritablePackageFolder,
    [ValidateRange(0, 60)][int]$InactivityLockMinutes = 0,
    [switch]$Interactive,
    [string]$InstallDir = 'C:\Program Files\FolderVault',
    [string]$DataDir = 'C:\ProgramData\FolderVault'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$source = Join-Path $packageRoot 'src'
Import-Module (Join-Path $PSScriptRoot 'FolderVault.Setup.psm1') -Force

# --------------------------------------------------------------- elevation
if (-not (Test-FVElevated)) {
    if (-not $Interactive) { Write-Host 'Run this from an administrator PowerShell window, or double-click Install.cmd.' -ForegroundColor Red; exit 1 }
    if (Start-FVElevated -ScriptPath $PSCommandPath -Arguments @('-Interactive')) { exit 0 }
    Wait-FVKey; exit 1
}

$stage = $null
function Stop-Install {
    param([string]$Text, [string]$Fix)
    Remove-FVAdminOnlyFolder -Path $stage
    Write-Host ''
    Write-FVProblem "Folder Vault was not installed. $Text" $Fix
    Write-Host '    Nothing on this PC has been changed by this attempt, apart from the steps marked [OK] above.' -ForegroundColor Gray
    if ($Interactive) { Wait-FVKey }
    exit 1
}

$total = 7
$programFiles = @('FolderVault.Common.psm1', 'FolderVault.Engine.psm1', 'FolderVault.BrokerCore.psm1', 'FolderVault.Broker.ps1',
    'FolderVault.Client.psm1', 'FolderVault.UserOps.psm1', 'FolderVault.UI.ps1', 'FolderVault.Tray.ps1')
$setupFiles = @('FolderVault.Setup.psm1', 'Uninstall-FolderVault.ps1')

Write-FVTitle "Installing Folder Vault on $env:COMPUTERNAME"

# --------------------------------------------------------------- 1. checks
Write-FVStep 1 $total 'Checking this PC'
if ($PSVersionTable.PSVersion.Major -ne 5) { Stop-Install 'It was started with PowerShell 7.' 'Double-click Install.cmd instead (it uses the Windows PowerShell built into Windows).' }
foreach ($f in $programFiles) { if (-not (Test-Path -LiteralPath (Join-Path $source $f))) { Stop-Install "The Folder Vault folder is incomplete ($f is missing)." 'Unzip the Folder Vault package again and run Install.cmd from the unzipped folder.' } }
foreach ($f in $setupFiles) { if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $f))) { Stop-Install "The Folder Vault folder is incomplete ($f is missing)." 'Unzip the Folder Vault package again.' } }
Import-Module (Join-Path $source 'FolderVault.Common.psm1') -Force

# Is this the released package? (audit fix A-22)
$sumsFile = Join-Path $packageRoot 'SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $sumsFile)) { Stop-Install 'The Folder Vault folder is incomplete (SHA256SUMS.txt is missing).' 'Unzip the Folder Vault package again.' }
$expected = Read-FVChecksumFile -Path $sumsFile
$integrity = Test-FVPackageIntegrity -Root $packageRoot -Expected $expected
if (-not $integrity.Ok) {
    $what = @($integrity.Missing | ForEach-Object { "$_ (missing)" }) + @($integrity.Modified | ForEach-Object { "$_ (changed)" }) + @($integrity.Unlisted | ForEach-Object { "$_ (not part of Folder Vault)" })
    Stop-Install "The Folder Vault folder is not the released package: $($what -join ', ')." 'Delete this folder, unzip a fresh copy of the release zip file and run Install.cmd from it.'
}
Write-FVOk "Package files match the published fingerprints ($($integrity.Checked) files)."
Write-FVNote "Package fingerprint: $(Get-FVPackageFingerprint -ChecksumFile $sumsFile). It should match the one in the release notes."
$writers = @()
$pkgDrive = New-Object System.IO.DriveInfo(([System.IO.Path]::GetPathRoot($packageRoot)))
if ($pkgDrive.DriveType -eq [System.IO.DriveType]::Removable) {
    # USB sticks usually have no permissions to check. The stick is in the technician's hands.
    Write-FVNote 'Running from a removable drive. Keep the IT team''s USB stick with you while installing.'
} else {
    $writers = @(Get-FVPackageWriters -PackageRoot $packageRoot)
}
if ($writers.Count -gt 0) {
    Write-FVWarn "People other than administrators could have changed this Folder Vault folder: $($writers -join ', ')." 'Safest: unzip the release zip file into a folder only administrators can change, or run it from the IT team''s USB stick, and check the fingerprint above.'
    if ($Interactive) {
        if (-not (Read-FVYes 'Install from this folder anyway? Only if you unzipped it yourself just now')) { Stop-Install 'You chose to use a safer copy.' 'Unzip the release zip file into a folder only administrators can change, then run Install.cmd from there.' }
    } elseif (-not $AllowWritablePackageFolder) {
        Stop-Install 'The Folder Vault folder could have been changed by people other than administrators.' 'Unzip the release zip file into a folder only administrators can change, or add -AllowWritablePackageFolder.'
    }
}
# Work from a private copy from here on, so nothing can be swapped while installing.
$stage = New-FVAdminOnlyFolder -Prefix 'FolderVault-setup-'
foreach ($sub in @('src', 'install')) { Copy-Item -LiteralPath (Join-Path $packageRoot $sub) -Destination (Join-Path $stage $sub) -Recurse -Force }
Copy-Item -LiteralPath (Join-Path $packageRoot 'Uninstall.cmd') -Destination (Join-Path $stage 'Uninstall.cmd') -Force
$staged = Test-FVPackageIntegrity -Root $stage -Expected $expected -TopFiles @('Uninstall.cmd')
if (-not $staged.Ok) { Stop-Install 'The Folder Vault files changed while they were being copied.' 'Unzip a fresh copy of the release zip file and run Install.cmd again.' }
$source = Join-Path $stage 'src'
$setupSource = Join-Path $stage 'install'
Import-Module (Join-Path $source 'FolderVault.Common.psm1') -Force
Import-Module (Join-Path $source 'FolderVault.Engine.psm1') -Force

$checks = @(Get-FVReadiness)
Write-FVReadiness -Checks $checks
if (@($checks | Where-Object Status -eq 'PROBLEM').Count -gt 0) { Stop-Install 'This PC is not ready (see PROBLEM above).' 'Fix the items marked PROBLEM, then run Install.cmd again.' }

$sysProtected = @($checks | Where-Object { $_.Name -eq 'Drive C:' -and $_.Status -eq 'OK' }).Count -eq 1
if (-not $sysProtected -and -not $AllowUnencryptedSystemDrive) {
    if ($Interactive) {
        Write-Host ''
        Write-Host '  Drive C: is not encrypted. Folder Vault will still encrypt the protected folders,' -ForegroundColor Yellow
        Write-Host '  but someone who takes the disk out could recover the original copies.' -ForegroundColor Yellow
        if (-not (Read-FVYes 'Install anyway? (recommended: N, turn on BitLocker first)')) { Stop-Install 'You chose to turn on BitLocker first.' 'Turn on BitLocker for drive C:, then run Install.cmd again.' }
    } else {
        Stop-Install 'Drive C: is not BitLocker-encrypted.' 'Turn on BitLocker for C:, or add -AllowUnencryptedSystemDrive.'
    }
}

if ([string]::IsNullOrEmpty($EscrowCertificate)) {
    $found = @(Find-FVEscrowCertificate -PackageRoot $packageRoot)
    if ($found.Count -eq 0) { Stop-Install 'The recovery certificate is missing.' 'Put the client''s recovery certificate (a .cer file from the IT team) in the same folder as Install.cmd.' }
    if ($found.Count -gt 1) { Stop-Install "There is more than one recovery certificate ($($found.Name -join ', '))." 'Leave only the one for this client next to Install.cmd.' }
    $EscrowCertificate = $found[0].FullName
}
$cert = Test-FVEscrowCertificate -CertPath (Resolve-Path -LiteralPath $EscrowCertificate).Path
if (-not $cert.Ok) {
    $why = @{ Missing = 'cannot be found'; Unreadable = 'cannot be read'; ContainsPrivateKey = 'contains the PRIVATE key, which must never be put on a client PC'; Expired = 'has expired'; WrongKeyUsage = 'is not an Folder Vault recovery certificate'; WeakKey = 'uses a key that is too weak' }[$cert.Reason]
    Stop-Install "The recovery certificate $why." 'Use the .cer file made by New-FVEscrowCertificate.ps1 for this client.'
}
Write-FVOk "Recovery certificate accepted ($(Split-Path -Leaf $EscrowCertificate))."
# A swapped certificate would send recovery keys to someone else, so show its fingerprint for checking.
Write-FVNote "Certificate fingerprint: $(($cert.Thumbprint.Substring(0, 16) -split '(.{4})' | Where-Object { $_ }) -join ' '). It should match the one the IT team recorded for this client."

$paths = Get-FVPaths -DataDir $DataDir -InstallDir $InstallDir
$cfgIn = $null
if (Test-Path -LiteralPath $paths.ConfigFile) { $cfgIn = ConvertFrom-Json ([System.IO.File]::ReadAllText($paths.ConfigFile)) }
$roots = @()
if ($null -ne $cfgIn -and $null -ne $cfgIn.PSObject.Properties['SharedRoots']) { $roots = @($cfgIn.SharedRoots) }
if ($Interactive -and $SharedRoot.Count -eq 0 -and $roots.Count -eq 0) {
    Write-Host ''
    Write-Host '  Shared folders: staff can share a protected folder on this PC if it sits in a shared area.' -ForegroundColor Gray
    $answer = Read-Host '  Type a shared area such as C:\Shared, or just press Enter for none'
    if (-not [string]::IsNullOrWhiteSpace($answer)) { $SharedRoot = @($answer.Trim()) }
}
foreach ($r in $SharedRoot) {
    $chk = Test-FVSharedRoot -Path $r
    if (-not $chk.Ok) { Stop-Install "'$r' cannot be used as a shared area." 'Choose a folder that is not inside Windows, Program Files, ProgramData or Users, for example C:\Shared.' }
    if ($roots -notcontains $chk.Path) { $roots += $chk.Path }
}

# --------------------------------------------------------------- 2. stop old copy
Write-FVStep 2 $total 'Stopping any older copy of Folder Vault'
$taskName = 'Folder Vault Broker'
$taskPath = '\Folder Vault\'
$existing = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
$oldVersion = $null
$oldManifest = Join-Path $DataDir 'install-manifest.json'
$oldRecord = Read-FVInstallManifest -DataDir $DataDir
if ($null -ne $oldRecord) { try { $oldVersion = [string]$oldRecord.version } catch { $oldVersion = '(unknown)' } }
if ($null -ne $existing) {
    Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
    $left = @(Stop-FVProcesses -CommandLineLike @('*FolderVault.Broker.ps1*', '*FolderVault.Tray.ps1*'))
    if ($left.Count -gt 0) { Stop-Install "The old Folder Vault background service did not stop (process $($left -join ', '))." 'Restart this PC, then run Install.cmd again.' }
    Write-FVOk "Updating from version $oldVersion. Protected folders stay protected; they are locked now."
} else {
    Write-FVOk 'No older copy found. This is a new installation.'
}

# --------------------------------------------------------------- 3. program files
Write-FVStep 3 $total "Copying Folder Vault to $InstallDir"
if (-not (Test-Path -LiteralPath $InstallDir)) { [void](New-Item -ItemType Directory -Path $InstallDir) }
# Staff may read and run the program, never change it.
Set-FVSecurity -Path $InstallDir -Sddl 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
foreach ($f in $programFiles) { Copy-Item -LiteralPath (Join-Path $source $f) -Destination (Join-Path $InstallDir $f) -Force }
foreach ($f in $setupFiles) { Copy-Item -LiteralPath (Join-Path $setupSource $f) -Destination (Join-Path $InstallDir $f) -Force }
Copy-Item -LiteralPath (Join-Path $stage 'Uninstall.cmd') -Destination (Join-Path $InstallDir 'Uninstall.cmd') -Force
Get-ChildItem -LiteralPath $InstallDir -File | ForEach-Object { Unblock-File -LiteralPath $_.FullName }
Write-FVOk 'Program copied.'

# --------------------------------------------------------------- 4. data folder
Write-FVStep 4 $total 'Preparing the secure data folder'
foreach ($d in @($paths.DataDir, $paths.VaultDir, $paths.EscrowDir, $paths.MountDir, $paths.LogDir)) { New-FVPrivateDirectory -Path $d }
Copy-Item -LiteralPath $EscrowCertificate -Destination $paths.EscrowCert -Force
$cfg = (ConvertTo-FVConfig -InputObject $cfgIn).Config
$cfg.SharedRoots = @($roots)
if ($FolderRule) { $cfg.AllowFoldersOutsideProfile = ($FolderRule -eq 'AnyFolder') }
[System.IO.File]::WriteAllText($paths.ConfigFile, (ConvertTo-Json -InputObject $cfg -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r)) { [void](New-Item -ItemType Directory -Path $r) }
    Write-FVOk "Shared area: $r"
}
Write-FVOk "$DataDir is ready (only SYSTEM and administrators can open it)."
if ($cfg.AllowFoldersOutsideProfile) { Write-FVOk 'Staff can protect any of their own folders on this PC''s drives, including OneDrive.' }
else { Write-FVOk 'Staff can protect folders inside their own user folder only.' }

# --------------------------------------------------------------- 5. background service
Write-FVStep 5 $total 'Setting up the background service'
if (-not [System.Diagnostics.EventLog]::SourceExists('FolderVault')) { New-EventLog -LogName Application -Source 'FolderVault' }
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$brokerArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\FolderVault.Broker.ps1`" -DataDir `"$DataDir`""
$action = New-ScheduledTaskAction -Execute $ps -Argument $brokerArgs -WorkingDirectory $InstallDir
$atStart = New-ScheduledTaskTrigger -AtStartup
# Restarts the service within 5 minutes if it ever stops; IgnoreNew prevents a second copy.
$repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# Priority 7 = below normal: the service never competes with the user's own work.
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Priority 7
if ($null -ne $existing) { Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false }
Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger @($atStart, $repeat) -Principal $principal -Settings $settings `
    -Description 'Folder Vault background service. Do not disable: protected folders cannot be unlocked without it.' | Out-Null
Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
Write-FVOk 'Background service registered and started (low priority).'

# --------------------------------------------------------------- 6. menus, shortcuts, Settings > Apps
Write-FVStep 6 $total 'Adding the right-click menu, shortcuts and tray icon'
$ui = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$InstallDir\FolderVault.UI.ps1`""
$verbs = @(
    @{ Key = 'FolderVault.Protect'; Text = 'Protect with Folder Vault...'; Action = 'Protect' },
    @{ Key = 'FolderVault.Unlock'; Text = 'Unlock with Folder Vault...'; Action = 'Unlock' },
    @{ Key = 'FolderVault.Lock'; Text = 'Lock with Folder Vault'; Action = 'Lock' }
)
foreach ($v in $verbs) {
    $k = "HKLM:\SOFTWARE\Classes\Directory\shell\$($v.Key)"
    [void](New-Item -Path "$k\command" -Force)
    Set-ItemProperty -Path $k -Name 'MUIVerb' -Value $v.Text
    Set-ItemProperty -Path $k -Name 'Icon' -Value '%SystemRoot%\System32\shell32.dll,47'
    Set-ItemProperty -Path "$k\command" -Name '(default)' -Value "$ui -Action $($v.Action) -Path `"%1`""
}
$run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
if ($NoTrayIcon) {
    Remove-ItemProperty -Path $run -Name 'FolderVault' -ErrorAction SilentlyContinue
    Write-FVOk 'Tray icon: off (folders still lock automatically).'
} else {
    $tray = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$InstallDir\FolderVault.Tray.ps1`""
    Set-ItemProperty -Path $run -Name 'FolderVault' -Value $tray
    Write-FVOk 'Tray icon: appears near the clock from each person''s next sign-in.'
}

$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$wsh = New-Object -ComObject WScript.Shell
function New-FVShortcut {
    param([string]$Name, [string]$Arguments, [string]$Description, [string]$Hotkey = '')
    $lnk = $wsh.CreateShortcut((Join-Path $startMenu $Name))
    $lnk.TargetPath = $ps
    $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$InstallDir\FolderVault.UI.ps1`" $Arguments"
    $lnk.IconLocation = "$env:SystemRoot\System32\shell32.dll,47"
    $lnk.WindowStyle = 7
    $lnk.Description = $Description
    if ($Hotkey) { $lnk.Hotkey = $Hotkey }
    $lnk.Save()
}
New-FVShortcut -Name 'Folder Vault.lnk' -Arguments '-Action Open' -Description 'Password-protected folders'
New-FVShortcut -Name 'Lock all Folder Vault folders.lnk' -Arguments '-Action LockAll' -Description 'Locks every folder you have unlocked (Ctrl+Alt+L)' -Hotkey 'CTRL+ALT+L'
Write-FVOk 'Start menu: "Folder Vault" and "Lock all Folder Vault folders" (shortcut keys Ctrl+Alt+L).'

$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FolderVault'
[void](New-Item -Path $uninstallKey -Force)
$sizeKb = [int]((Get-ChildItem -LiteralPath $InstallDir -File | Measure-Object Length -Sum).Sum / 1KB)
$entry = @{
    DisplayName = 'Folder Vault'; DisplayVersion = (Get-FVProductVersion); Publisher = 'Folder Vault'
    InstallLocation = $InstallDir; DisplayIcon = "$env:SystemRoot\System32\shell32.dll,47"
    UninstallString = "`"$InstallDir\Uninstall.cmd`""
}
foreach ($k in $entry.Keys) { Set-ItemProperty -Path $uninstallKey -Name $k -Value $entry[$k] }
foreach ($k in @('NoModify', 'NoRepair')) { New-ItemProperty -Path $uninstallKey -Name $k -PropertyType DWord -Value 1 -Force | Out-Null }
New-ItemProperty -Path $uninstallKey -Name 'EstimatedSize' -PropertyType DWord -Value $sizeKb -Force | Out-Null
Write-FVOk 'Listed in Settings > Apps, so it can be removed like any program.'

# Screen lock time: optional from 0.4.5. Earlier installers always set 10 minutes.
if ($InactivityLockMinutes -gt 0) {
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -PropertyType DWord -Value ($InactivityLockMinutes * 60) -Force | Out-Null
    Write-FVOk "The screen locks after $InactivityLockMinutes idle minutes (protected folders lock with it)."
} else {
    $reset = Reset-FVScreenLock -Manifest $oldRecord
    if ($null -ne $reset) { Write-FVOk $reset }
    else { Write-FVOk 'Screen lock: Windows'' own settings (Folder Vault does not change them).' }
}

# --------------------------------------------------------------- 7. confirm
Write-FVStep 7 $total 'Checking that everything works'
$manifest = [ordered]@{ product = 'Folder Vault'; version = (Get-FVProductVersion); installedUtc = ([datetime]::UtcNow.ToString('o')); escrowThumbprint = $cert.Thumbprint; trayIcon = (-not $NoTrayIcon); screenLockMinutesSet = $InactivityLockMinutes; files = [ordered]@{} }
foreach ($f in @(Get-ChildItem -LiteralPath $InstallDir -File | Sort-Object Name)) { $manifest.files[$f.Name] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash }
[System.IO.File]::WriteAllText($oldManifest, (ConvertTo-Json $manifest -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
Import-Module (Join-Path $InstallDir 'FolderVault.Client.psm1') -Force
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
    $p = Invoke-FVBroker -Request @{ op = 'Ping' } -ConnectTimeoutMs 1000
    if ($p.ok) { $ok = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ok) {
    $why = ''
    $startLog = Join-Path $paths.LogDir 'broker-startup.log'
    if (Test-Path -LiteralPath $startLog) { $why = ' Reason: ' + (@(Get-Content -LiteralPath $startLog -Tail 1) -join '') }
    Stop-Install "The background service did not start.$why" "Restart the PC and run Install.cmd again. If it still fails, send the IT team the files in $($paths.LogDir)."
}
Write-FVOk 'The background service is answering.'
Remove-FVAdminOnlyFolder -Path $stage

Write-Host ''
Write-Host "  Folder Vault $(Get-FVProductVersion) is installed on $env:COMPUTERNAME." -ForegroundColor Green
Write-Host ''
Write-Host '  What staff do next:' -ForegroundColor White
Write-Host '    * Right-click a folder in File Explorer and choose "Protect with Folder Vault...".'
Write-Host '      (On Windows 11, click "Show more options" first.)'
Write-Host '    * Give each person the one-page guide: docs\USER-GUIDE.md'
Write-Host ''
Write-Host '  Keep the recovery PRIVATE key (.pfx) off this PC, in the IT team''s safe.' -ForegroundColor Yellow
if (-not $sysProtected) { Write-Host '  Reminder: drive C: is not encrypted. Turn on BitLocker for C: as soon as you can.' -ForegroundColor Yellow }
if ($Interactive) { Wait-FVKey }
exit 0
