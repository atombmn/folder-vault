#Requires -Version 5.1
<#
.SYNOPSIS
    Removes Folder Vault from this PC.

.DESCRIPTION
    The easy way: Settings > Apps > Folder Vault > Uninstall, or double-click
    Uninstall.cmd. Windows asks for administrator permission.

    If folders are still protected, it lists them and offers two choices:
      * stop, so their owners can use "Remove protection" first (recommended); or
      * remove the program only and keep the protected folders, locked and
        encrypted, so that reinstalling Folder Vault brings them straight back.
    It never deletes a protected folder's contents.

    Scripted use, elevated:  .\Uninstall-FolderVault.ps1 [-LeaveVaultsInPlace]
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$LeaveVaultsInPlace,
    [switch]$Interactive,
    [string]$InstallDir = 'C:\Program Files\FolderVault',
    [string]$DataDir = 'C:\ProgramData\FolderVault'
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'FolderVault.Setup.psm1') -Force

if (-not (Test-FVElevated)) {
    if (-not $Interactive) { Write-Host 'Run this from an administrator PowerShell window, or use Settings > Apps.' -ForegroundColor Red; exit 1 }
    if (Start-FVElevated -ScriptPath $PSCommandPath -Arguments @('-Interactive')) { exit 0 }
    Wait-FVKey; exit 1
}

# Running from inside the folder we are about to delete: carry on from a temporary copy.
$here = (Resolve-Path -LiteralPath $PSScriptRoot).Path.TrimEnd('\')
if ([string]::Equals($here, $InstallDir.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
    # A private folder under C:\Windows\Temp, not the person's own TEMP folder, which
    # anyone signed in as that person could change before the copy runs (audit fix A-26).
    $tmp = New-FVAdminOnlyFolder -Prefix 'FolderVault-uninstall-'
    Copy-Item -LiteralPath $PSCommandPath -Destination $tmp
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'FolderVault.Setup.psm1') -Destination $tmp
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + (Join-Path $tmp (Split-Path -Leaf $PSCommandPath)) + '"'))
    if ($Interactive) { $a += '-Interactive' }
    if ($LeaveVaultsInPlace) { $a += '-LeaveVaultsInPlace' }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $ps -ArgumentList $a -WorkingDirectory $tmp | Out-Null
    exit 0
}

function Stop-Uninstall { param([string]$Text, [string]$Fix) Write-FVProblem $Text $Fix; if ($Interactive) { Wait-FVKey }; exit 1 }

Write-FVTitle "Removing Folder Vault from $env:COMPUTERNAME"

$registry = Join-Path $DataDir 'vaults.json'
$vaults = @()
$readable = $true
if (Test-Path -LiteralPath $registry) {
    try { $vaults = @((ConvertFrom-Json ([System.IO.File]::ReadAllText($registry))).vaults | Where-Object { $null -ne $_ }) } catch { $readable = $false }
}

if (-not $readable) {
    if (-not $Interactive -and -not $LeaveVaultsInPlace) { Stop-Uninstall 'The list of protected folders cannot be read.' 'Re-run with -LeaveVaultsInPlace, or contact the IT team.' }
    Write-FVWarn 'The list of protected folders cannot be read, so Folder Vault cannot tell whether any are still protected.'
    $LeaveVaultsInPlace = $true
}
elseif ($vaults.Count -gt 0 -and -not $LeaveVaultsInPlace) {
    Write-Host '  These folders are still protected:' -ForegroundColor Yellow
    foreach ($v in $vaults) { Write-Host ("    - {0}  ({1})" -f $v.Name, $v.FolderPath) -ForegroundColor Yellow }
    Write-Host ''
    if (-not $Interactive) { Stop-Uninstall 'Folders are still protected.' 'Ask their owners to use "Remove protection" first, or re-run with -LeaveVaultsInPlace.' }
    Write-Host '  You can:' -ForegroundColor White
    Write-Host '    1  Stop now. Each owner opens Folder Vault and uses "Remove protection" (recommended).'
    Write-Host '    2  Remove the program only. The folders stay locked and encrypted on this PC;'
    Write-Host '       installing Folder Vault again brings them straight back.'
    $choice = Read-Host '  Type 1 or 2'
    if ($choice.Trim() -ne '2') { Write-FVNote 'Nothing was removed.'; if ($Interactive) { Wait-FVKey }; exit 0 }
    $LeaveVaultsInPlace = $true
}
elseif ($Interactive) {
    if (-not (Read-FVYes 'No folders are protected. Remove Folder Vault from this PC?')) { Write-FVNote 'Nothing was removed.'; Wait-FVKey; exit 0 }
}
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Uninstall Folder Vault')) { return }

# 1. Stop the background service and every Folder Vault window or tray icon.
$taskName = 'Folder Vault Broker'; $taskPath = '\Folder Vault\'
if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
}
$left = @(Stop-FVProcesses -CommandLineLike @('*FolderVault.*.ps1*'))
if ($left.Count -gt 0) { Write-FVWarn "Some Folder Vault windows did not close (process $($left -join ', '))." 'If removal fails, restart the PC and run Uninstall.cmd again.' }
Write-FVOk 'Background service stopped.'

# 2. Lock anything still open.
Get-ChildItem -LiteralPath (Join-Path $DataDir 'Vaults') -Filter '*.vhdx' -ErrorAction SilentlyContinue | ForEach-Object {
    $img = Get-DiskImage -ImagePath $_.FullName -ErrorAction SilentlyContinue
    if ($null -ne $img -and $img.Attached) { Dismount-DiskImage -ImagePath $_.FullName | Out-Null }
}
Write-FVOk 'All protected folders are locked.'

# 3. Menus, shortcuts, tray, Settings > Apps entry, program files.
foreach ($k in @('FolderVault.Protect', 'FolderVault.Unlock', 'FolderVault.Lock')) {
    $p = "HKLM:\SOFTWARE\Classes\Directory\shell\$k"
    if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force }
}
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'FolderVault' -ErrorAction SilentlyContinue
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
foreach ($n in @('Folder Vault.lnk', 'Lock all Folder Vault folders.lnk')) { Remove-Item -LiteralPath (Join-Path $startMenu $n) -Force -ErrorAction SilentlyContinue }
$appsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FolderVault'
if (Test-Path $appsKey) { Remove-Item -Path $appsKey -Recurse -Force }
if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
Write-FVOk 'Program, menus and shortcuts removed.'

# 4. Data folder: only when nothing is protected.
if ($LeaveVaultsInPlace) {
    Write-FVNote "Kept $DataDir (the locked, encrypted folders and their recovery records)."
    Write-FVNote 'The protected folders will show as empty until Folder Vault is installed again.'
} else {
    # Never recurse through Mounts: a mount point could still lead into a volume.
    $mounts = Join-Path $DataDir 'Mounts'
    if (Test-Path -LiteralPath $mounts) {
        Get-ChildItem -LiteralPath $mounts -Force -Directory | ForEach-Object {
            # Only a mount point needs mountvol. Windows PowerShell 5.1 turns anything a
            # program writes to its error output into a stopping error when
            # ErrorActionPreference is Stop, so the call runs with Continue (audit fix A-28).
            if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $ErrorActionPreference = 'Continue'
                $null = & "$env:SystemRoot\System32\mountvol.exe" ($_.FullName + '\') /D 2>&1
                $ErrorActionPreference = 'Stop'
            }
            Get-ChildItem -LiteralPath $_.FullName -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue | Remove-Item -Force
            [System.IO.Directory]::Delete($_.FullName, $false)
        }
    }
    Remove-Item -LiteralPath $DataDir -Recurse -Force
    Write-FVOk 'Data folder removed.'
}
Write-Host ''
Write-Host '  Folder Vault has been removed.' -ForegroundColor Green
if ($Interactive) { Wait-FVKey }
exit 0
