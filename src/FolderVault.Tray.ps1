#Requires -Version 5.1
<#
    Folder Vault - tray icon (one per signed-in user).

    Kept deliberately small, because it runs all day:
      * Windows Forms only. The heavier window toolkit (WPF) is never loaded
        here; password and settings windows open in their own short-lived
        process (FolderVault.UI.ps1) and that process ends when the window closes.
      * No polling of the background service. The only timer is a cheap check,
        every 10 seconds, for whether this session's screen is locked. The
        service is asked for the folder list only when the menu opens or the
        screen has just locked.
      * Locking does not depend on this icon. The background service locks
        folders on its own; the icon just makes it faster and tidies the
        Windows "Recent" list.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Here = $PSScriptRoot
Import-Module (Join-Path $Here 'FolderVault.Common.psm1') -Force
Import-Module (Join-Path $Here 'FolderVault.Client.psm1') -Force
Import-Module (Join-Path $Here 'FolderVault.UserOps.psm1') -Force
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# One icon per session.
$created = $false
$script:Mutex = New-Object System.Threading.Mutex($true, 'Local\FolderVault.Tray', [ref]$created)
if (-not $created) { return }

$script:PsExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:UiScript = Join-Path $Here 'FolderVault.UI.ps1'
$script:MySession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
$script:WasLocked = $false
$script:Policy = $null
$script:Broker = { param([hashtable]$r) Invoke-FVBroker -Request $r -ResponseTimeoutMs 120000 }

function Start-FVWindow {
    <# Opens an Folder Vault window in its own process (keeps this one small). #>
    param([string[]]$Arguments)
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', ('"' + $script:UiScript + '"')) + $Arguments
    Start-Process -FilePath $script:PsExe -ArgumentList $a -WindowStyle Hidden | Out-Null
}

function Confirm-FVTray {
    param([string]$Message)
    $r = [System.Windows.Forms.MessageBox]::Show($Message, 'Folder Vault', 'YesNo', 'Warning')
    return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Show-FVTip {
    param([string]$Text, [string]$Kind = 'Info')
    try { $script:Icon.ShowBalloonTip(5000, 'Folder Vault', $Text, $Kind) } catch { Write-Verbose 'balloon failed' }
}

function Get-FVMyVaults {
    $r = Invoke-FVBroker -Request @{ op = 'List' }
    if ($r.ok) { return [pscustomobject]@{ Ok = $true; Vaults = @(Get-FVProp $r.data 'vaults' | Where-Object { $null -ne $_ }) } }
    return [pscustomobject]@{ Ok = $false; Vaults = @() }
}

function Update-FVTrayText {
    param([object[]]$Vaults)
    $open = @($Vaults | Where-Object { $_.state -eq 'Unlocked' -and $_.unlockedByMe }).Count
    $text = 'Folder Vault: all your folders are locked'
    if ($open -eq 1) { $text = 'Folder Vault: 1 folder unlocked' } elseif ($open -gt 1) { $text = "Folder Vault: $open folders unlocked" }
    $script:Icon.Text = $text
}

function Add-FVMenuItem {
    param([string]$Text, [scriptblock]$OnClick, $Tag = $null, [bool]$Enabled = $true, [bool]$Bold = $false)
    $it = $script:Menu.Items.Add($Text)
    $it.Tag = $Tag
    $it.Enabled = $Enabled
    if ($Bold) { $it.Font = New-Object System.Drawing.Font($it.Font, [System.Drawing.FontStyle]::Bold) }
    if ($null -ne $OnClick) { $it.Add_Click($OnClick) }
}

function Build-FVMenu {
    $m = $script:Menu
    $m.Items.Clear()
    $list = Get-FVMyVaults
    Update-FVTrayText -Vaults $list.Vaults
    Add-FVMenuItem -Text 'Folder Vault' -Enabled $false -Bold $true
    [void]$m.Items.Add('-')
    if (-not $list.Ok) {
        Add-FVMenuItem -Text 'Background service not running. Restart the PC or call IT.' -Enabled $false
    } elseif ($list.Vaults.Count -eq 0) {
        Add-FVMenuItem -Text 'No protected folders yet' -Enabled $false
    }
    foreach ($v in $list.Vaults) {
        switch ([string]$v.state) {
            'Locked' {
                Add-FVMenuItem -Text "Unlock '$($v.name)'..." -Tag $v -OnClick { param($src, $evt) Start-FVWindow @('-Action', 'Unlock', '-Id', [string]$src.Tag.id) }
            }
            'Unlocked' {
                Add-FVMenuItem -Text "Open '$($v.name)'" -Tag $v -OnClick { param($src, $evt) Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('"' + [string]$src.Tag.folderPath + '"') }
                Add-FVMenuItem -Text "Lock '$($v.name)'" -Tag $v -OnClick {
                    param($src, $evt)
                    $r = Invoke-FVLockVault -Vault $src.Tag -Broker $script:Broker -AskUser { param($msg) Confirm-FVTray $msg }
                    if ($r.Ok) { Show-FVTip $r.Message } elseif ($r.Code -ne 'Cancelled') { Show-FVTip $r.Message 'Warning' }
                }
            }
            'Creating' {
                Add-FVMenuItem -Text "Finish protecting '$($v.name)'..." -Tag $v -OnClick { param($src, $evt) Start-FVWindow @('-Action', 'Unlock', '-Id', [string]$src.Tag.id) }
            }
            default { Add-FVMenuItem -Text "'$($v.name)' needs IT" -Enabled $false }
        }
    }
    [void]$m.Items.Add('-')
    Add-FVMenuItem -Text 'Lock all my folders now' -OnClick {
        $r = Invoke-FVLockAll -Broker $script:Broker -AskUser { param($msg) Confirm-FVTray $msg }
        if ($r.Ok) { Show-FVTip $r.Message } else { Show-FVTip $r.Message 'Warning' }
    }
    Add-FVMenuItem -Text 'Protect a folder...' -OnClick { Start-FVWindow @('-Action', 'Protect') }
    Add-FVMenuItem -Text 'Open Folder Vault' -OnClick { Start-FVWindow @('-Action', 'Open') }
    [System.GC]::Collect()
}

function Invoke-FVTrayTick {
    <# Runs every 10 s: a single process-name lookup, nothing else, unless the screen has just locked. #>
    $locked = $false
    foreach ($p in @(Get-Process -Name 'LogonUI' -ErrorAction SilentlyContinue)) { if ($p.SessionId -eq $script:MySession) { $locked = $true; break } }
    if ($locked -and -not $script:WasLocked) {
        $lockOnScreen = $true
        $force = $true
        if ($null -ne $script:Policy) {
            $lockOnScreen = [bool](Get-FVProp $script:Policy 'lockOnScreenLock')
            $force = [bool](Get-FVProp $script:Policy 'forceDismountOnAutoLock')
        }
        if ($lockOnScreen) {
            try {
                $r = Invoke-FVLockAll -Broker $script:Broker -Force $force
                if ($r.Ok -and [int]$r.Data.locked -gt 0) { $script:ShowLockedTipOnReturn = $true }
            } catch { Write-Verbose "auto-lock from tray failed: $($_.Exception.Message)" }
        }
        [System.GC]::Collect()
    }
    if (-not $locked -and $script:WasLocked -and $script:ShowLockedTipOnReturn) {
        $script:ShowLockedTipOnReturn = $false
        Show-FVTip 'Your protected folders were locked while you were away.'
    }
    $script:WasLocked = $locked
}

# ---------------------------------------------------------------- start
try {
    $p = Invoke-FVBroker -Request @{ op = 'GetPolicy' }
    if ($p.ok) { $script:Policy = $p.data }
} catch { $script:Policy = $null }
$script:ShowLockedTipOnReturn = $false

$script:Icon = New-Object System.Windows.Forms.NotifyIcon
$script:Icon.Icon = [System.Drawing.SystemIcons]::Shield
$script:Icon.Text = 'Folder Vault'
$script:Menu = New-Object System.Windows.Forms.ContextMenuStrip
$script:Icon.ContextMenuStrip = $script:Menu
$script:Menu.Add_Opening({ Build-FVMenu })
# Left-click shows the same menu as right-click (people try left-click first).
$script:Icon.Add_MouseUp({
    param($src, $evt)
    if ($evt.Button -ne [System.Windows.Forms.MouseButtons]::Left) { return }
    $show = [System.Windows.Forms.NotifyIcon].GetMethod('ShowContextMenu', [System.Reflection.BindingFlags]'Instance,NonPublic')
    if ($null -ne $show) { [void]$show.Invoke($src, $null) }
})
$script:Icon.Add_BalloonTipClicked({ Start-FVWindow @('-Action', 'Open') })
$script:Icon.Visible = $true

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 10000
$timer.Add_Tick({ Invoke-FVTrayTick })
$timer.Start()

# Tell the user about a protection that was interrupted (for example by a restart).
$first = Get-FVMyVaults
Update-FVTrayText -Vaults $first.Vaults
$unfinished = @($first.Vaults | Where-Object { $_.state -eq 'Creating' -and $_.mine })
if ($unfinished.Count -gt 0) { Show-FVTip "Protecting '$($unfinished[0].name)' did not finish. Click here to finish it. No files have been lost." 'Warning' }
$first = $null
[System.GC]::Collect()

[System.Windows.Forms.Application]::Run()
