#Requires -Version 5.1
<#
    Folder Vault - windows and quick actions.

    Runs as the signed-in (standard) user, in its own short-lived process,
    and exits when its window closes. The tray icon is a separate, smaller
    script (FolderVault.Tray.ps1).

      -Action Open                 the main Folder Vault window
      -Action Protect [-Path X]    "Protect with Folder Vault..." (Explorer right-click)
      -Action Unlock  -Path X      "Unlock with Folder Vault..." (Explorer right-click)
      -Action Unlock  -Id G        the "double-click here to unlock" shortcut, the tray menu
      -Action Lock    -Path X      "Lock with Folder Vault" (Explorer right-click)
      -Action LockAll              "Lock all Folder Vault folders" shortcut (Ctrl+Alt+L)

    The window toolkit (WPF) is loaded only when a window is actually shown,
    so the quick lock actions start fast and use little memory.
#>
[CmdletBinding()]
param(
    [ValidateSet('Open', 'Protect', 'Unlock', 'Lock', 'LockAll')][string]$Action = 'Open',
    [string]$Path,
    [string]$Id
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Here = $PSScriptRoot
Import-Module (Join-Path $Here 'FolderVault.Common.psm1') -Force
Import-Module (Join-Path $Here 'FolderVault.Client.psm1') -Force
Import-Module (Join-Path $Here 'FolderVault.UserOps.psm1') -Force

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$script:WpfLoaded = $false
function Initialize-FVWpf {
    if ($script:WpfLoaded) { return }
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:WpfLoaded = $true
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
$script:Policy = $null
$script:Vaults = @()
$script:Busy = $false
$script:BgJobs = @{}

function Invoke-Broker { param([hashtable]$Request, [int]$TimeoutMs = 120000) return (Invoke-FVBroker -Request $Request -ResponseTimeoutMs $TimeoutMs) }
$script:BrokerSb = { param([hashtable]$r) Invoke-FVBroker -Request $r -ResponseTimeoutMs 120000 }

function Show-Message {
    <# Windows Forms message box: no need to load WPF just to say something. Returns 'Yes'/'No'/'OK'. #>
    param([string]$Text, [string]$Title = 'Folder Vault', [ValidateSet('Info', 'Warning', 'Error', 'Question')][string]$Kind = 'Info')
    $icon = @{ Info = 'Information'; Warning = 'Warning'; Error = 'Error'; Question = 'Question' }[$Kind]
    $buttons = 'OK'
    if ($Kind -eq 'Question') { $buttons = 'YesNo' }
    return [string][System.Windows.Forms.MessageBox]::Show($Text, $Title, $buttons, $icon)
}

function Confirm-Force { param([string]$Message) return ((Show-Message $Message -Kind Question) -eq 'Yes') }

function Show-Toast {
    <# A short notification near the clock, then this process exits. #>
    param([string]$Text, [string]$Kind = 'Info')
    $n = New-Object System.Windows.Forms.NotifyIcon
    try {
        $n.Icon = [System.Drawing.SystemIcons]::Shield
        $n.Visible = $true
        $n.ShowBalloonTip(4000, 'Folder Vault', $Text, $Kind)
        $until = [datetime]::UtcNow.AddSeconds(4)
        while ([datetime]::UtcNow -lt $until) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 100 }
    } finally { $n.Visible = $false; $n.Dispose() }
}

function Get-ResponseText {
    param($Resp)
    $text = [string]$Resp.message
    $data = $null
    if ($null -ne $Resp.PSObject.Properties['data']) { $data = $Resp.data }
    if ($Resp.code -eq 'PasswordPolicy' -and $null -ne $data -and $null -ne $data.PSObject.Properties['problems']) {
        $min = 12
        if ($null -ne $script:Policy) { $min = [int]$script:Policy.minPasswordLength }
        $lines = @($data.problems | ForEach-Object { '  - ' + (Get-FVPasswordProblemText -Code $_ -MinLength $min) })
        $text = $text + "`r`n`r`n" + ($lines -join "`r`n")
    }
    if (($Resp.code -eq 'Throttled' -or $Resp.code -eq 'LockedOut') -and $null -ne $data -and $null -ne $data.PSObject.Properties['retryAfterSeconds']) {
        $s = [int]$data.retryAfterSeconds
        if ($s -ge 90) { $text += "`r`nTry again in about $([math]::Ceiling($s / 60)) minutes." } else { $text += "`r`nTry again in $s seconds." }
    }
    return $text
}

function Update-Policy {
    $p = Invoke-Broker @{ op = 'GetPolicy' }
    if ($p.ok) { $script:Policy = $p.data; return $true }
    return $false
}

function Update-Vaults {
    $r = Invoke-Broker @{ op = 'List' }
    if ($r.ok) { $script:Vaults = @($r.data.vaults); return $true }
    $script:Vaults = @()
    return $false
}

function Get-VaultByFolder {
    param([string]$Folder)
    $n = ConvertTo-FVNormalizedPath -Path $Folder
    if (-not $n.Ok) { return $null }
    foreach ($v in $script:Vaults) { if (Test-FVPathEqual $v.folderPath $n.Path) { return $v } }
    return $null
}

function Get-VaultById {
    param([string]$VaultId)
    foreach ($v in $script:Vaults) { if ([string]::Equals([string]$v.id, $VaultId, [System.StringComparison]::OrdinalIgnoreCase)) { return $v } }
    return $null
}

function Open-Folder { param([string]$Folder) Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('"' + $Folder + '"') }

function Get-StateText {
    param($v)
    switch ($v.state) {
        'Locked'         { return 'Locked' }
        'Unlocked'       { return 'Unlocked' }
        'Creating'       { return 'Unfinished' }
        'NeedsAttention' { return 'Needs IT' }
    }
    return [string]$v.state
}

# ---------------------------------------------------------------------------
# Background work: long operations run in a separate runspace so the window
# never freezes. Progress comes back through a synchronised hashtable.
# ---------------------------------------------------------------------------
function Start-Background {
    param(
        [Parameter(Mandatory)][scriptblock]$Work,
        [hashtable]$Arguments = @{},
        [Parameter(Mandatory)][scriptblock]$OnDone,
        [scriptblock]$OnProgress
    )
    Initialize-FVWpf
    $sync = [hashtable]::Synchronized(@{ Text = ''; Percent = 0 })
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $boot = {
        param($here, $sync, $work, $workArgs)
        Set-StrictMode -Version 3.0
        $ErrorActionPreference = 'Stop'
        Import-Module (Join-Path $here 'FolderVault.Common.psm1') -Force
        Import-Module (Join-Path $here 'FolderVault.Client.psm1') -Force
        Import-Module (Join-Path $here 'FolderVault.UserOps.psm1') -Force
        $progress = { param($t, $p) $sync.Text = $t; $sync.Percent = $p }.GetNewClosure()
        $broker = { param([hashtable]$r) Invoke-FVBroker -Request $r -ResponseTimeoutMs 900000 }
        try { & ([scriptblock]::Create($work)) $workArgs $broker $progress }
        catch { [pscustomobject]@{ Ok = $false; Code = 'InternalError'; Message = "$(Get-FVMessage 'InternalError') ($($_.Exception.Message))"; Data = $null; Warnings = @() } }
    }
    [void]$ps.AddScript($boot).AddArgument($script:Here).AddArgument($sync).AddArgument($Work.ToString()).AddArgument($Arguments)
    $handle = $ps.BeginInvoke()
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    # Handlers below look their job up by timer: closures cannot see this script's functions.
    $script:BgJobs[$timer] = @{ Ps = $ps; Rs = $rs; Handle = $handle; Sync = $sync; OnDone = $OnDone; OnProgress = $OnProgress }
    $timer.Add_Tick({
        param($src, $evt)
        $job = $script:BgJobs[$src]
        if ($null -eq $job) { $src.Stop(); return }
        if ($null -ne $job.OnProgress) { & $job.OnProgress $job.Sync.Text $job.Sync.Percent }
        if ($job.Handle.IsCompleted) {
            $src.Stop()
            $script:BgJobs.Remove($src)
            $result = $null
            try { $result = @($job.Ps.EndInvoke($job.Handle)) | Select-Object -Last 1 } catch { $result = $null }
            $job.Ps.Dispose(); $job.Rs.Dispose()
            if ($null -eq $result) { $result = [pscustomobject]@{ Ok = $false; Code = 'InternalError'; Message = (Get-FVMessage 'InternalError'); Data = $null; Warnings = @() } }
            & $job.OnDone $result
        }
    })
    $timer.Start()
}

# ---------------------------------------------------------------------------
# XAML
# ---------------------------------------------------------------------------
$script:Styles = @'
<Window.Resources>
  <SolidColorBrush x:Key="Accent" Color="#0F5F59"/>
  <SolidColorBrush x:Key="AccentDark" Color="#0A4541"/>
  <SolidColorBrush x:Key="Muted" Color="#5B6670"/>
  <Style TargetType="Button">
    <Setter Property="Padding" Value="14,6"/>
    <Setter Property="Margin" Value="0,0,8,0"/>
    <Setter Property="MinWidth" Value="90"/>
    <Setter Property="FontSize" Value="13"/>
  </Style>
  <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
    <Setter Property="Background" Value="{StaticResource Accent}"/>
    <Setter Property="Foreground" Value="White"/>
    <Setter Property="BorderBrush" Value="{StaticResource AccentDark}"/>
  </Style>
  <Style TargetType="TextBlock"><Setter Property="FontSize" Value="13"/></Style>
  <Style TargetType="PasswordBox"><Setter Property="Padding" Value="4"/><Setter Property="FontSize" Value="14"/></Style>
  <Style TargetType="TextBox"><Setter Property="Padding" Value="4"/><Setter Property="FontSize" Value="13"/></Style>
</Window.Resources>
'@

function New-Window {
    param([string]$Xaml)
    Initialize-FVWpf
    $full = $Xaml.Replace('<!--STYLES-->', $script:Styles)
    [xml]$doc = $full
    $reader = New-Object System.Xml.XmlNodeReader $doc
    return [Windows.Markup.XamlReader]::Load($reader)
}

$script:MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Folder Vault" Width="820" Height="520" MinWidth="640" MinHeight="400"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" Background="White">
  <!--STYLES-->
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="{StaticResource Accent}" Padding="20,14">
      <StackPanel>
        <TextBlock Text="Folder Vault" Foreground="White" FontSize="22" FontWeight="SemiBold"/>
        <TextBlock Text="Password-protected folders. Locked folders look empty until you unlock them." Foreground="#D6ECEA" Margin="0,2,0,0"/>
      </StackPanel>
    </Border>
    <Border DockPanel.Dock="Bottom" Background="#F3F5F6" Padding="20,8">
      <TextBlock x:Name="StatusText" Foreground="{StaticResource Muted}" TextWrapping="Wrap"/>
    </Border>
    <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="20,16,20,8">
      <Button x:Name="BtnProtect" Content="Protect a folder..." Style="{StaticResource Primary}"/>
      <Button x:Name="BtnUnlock" Content="Unlock &amp; open"/>
      <Button x:Name="BtnLock" Content="Lock"/>
      <Button x:Name="BtnLockAll" Content="Lock all"/>
      <Button x:Name="BtnPassword" Content="Change password..."/>
      <Button x:Name="BtnRemove" Content="Remove protection..."/>
    </StackPanel>
    <Grid Margin="20,0,20,16">
      <ListView x:Name="VaultList" SelectionMode="Single" FontSize="13">
        <ListView.View>
          <GridView>
            <GridViewColumn Header="Status" Width="110" DisplayMemberBinding="{Binding Status}"/>
            <GridViewColumn Header="Name" Width="170" DisplayMemberBinding="{Binding Name}"/>
            <GridViewColumn Header="Folder" Width="380" DisplayMemberBinding="{Binding Folder}"/>
            <GridViewColumn Header="Type" Width="90" DisplayMemberBinding="{Binding Type}"/>
          </GridView>
        </ListView.View>
      </ListView>
      <TextBlock x:Name="EmptyText" Text="No protected folders yet. Click 'Protect a folder...' or right-click a folder in File Explorer." Foreground="{StaticResource Muted}" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" Margin="40"/>
    </Grid>
  </DockPanel>
</Window>
'@

$script:ProtectXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Protect a folder - Folder Vault" Width="560" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" Background="White">
  <!--STYLES-->
  <StackPanel Margin="24,20,24,20">
    <TextBlock Text="Protect a folder with a password" FontSize="18" FontWeight="SemiBold"/>
    <TextBlock Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,4,0,14"
      Text="The files are moved into an encrypted vault. The folder stays where it is but looks empty until someone unlocks it with this password. Share the password only with people who should see these files."/>
    <TextBlock Text="Folder"/>
    <DockPanel Margin="0,4,0,10">
      <Button x:Name="BtnBrowse" DockPanel.Dock="Right" Content="Browse..." Margin="8,0,0,0" MinWidth="80"/>
      <TextBox x:Name="TxtFolder"/>
    </DockPanel>
    <TextBlock x:Name="FolderInfo" Foreground="{StaticResource Muted}" Margin="0,-6,0,10" TextWrapping="Wrap"/>
    <Grid>
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="16"/><ColumnDefinition Width="180"/></Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
        <TextBlock Text="Name for this vault"/>
        <TextBox x:Name="TxtName" Margin="0,4,0,10" MaxLength="40"/>
      </StackPanel>
      <StackPanel Grid.Column="2">
        <TextBlock Text="Space reserved"/>
        <ComboBox x:Name="CmbSize" Margin="0,4,0,10" FontSize="13"/>
      </StackPanel>
    </Grid>
    <TextBlock Text="Password"/>
    <PasswordBox x:Name="Pw1" Margin="0,4,0,6"/>
    <ProgressBar x:Name="Strength" Height="6" Minimum="0" Maximum="4" Value="0" Margin="0,0,0,4"/>
    <TextBlock x:Name="PwHint" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <TextBlock Text="Type the password again"/>
    <PasswordBox x:Name="Pw2" Margin="0,4,0,10"/>
    <CheckBox x:Name="ChkUnderstand" Margin="0,4,0,14">
      <TextBlock TextWrapping="Wrap" Width="480" Text="I will keep this password safe. If it is forgotten, only IT can recover the folder."/>
    </CheckBox>
    <StackPanel x:Name="ProgressPanel" Visibility="Collapsed" Margin="0,0,0,12">
      <ProgressBar x:Name="Progress" Height="8" Minimum="0" Maximum="100"/>
      <TextBlock x:Name="ProgressText" Foreground="{StaticResource Muted}" Margin="0,4,0,0"/>
    </StackPanel>
    <TextBlock x:Name="ErrorText" Foreground="#B42318" TextWrapping="Wrap" Margin="0,0,0,10" Visibility="Collapsed"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="BtnOk" Content="Protect folder" Style="{StaticResource Primary}" IsDefault="True"/>
      <Button x:Name="BtnCancel" Content="Cancel" IsCancel="True" Margin="0"/>
    </StackPanel>
  </StackPanel>
</Window>
'@

$script:PasswordXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Folder Vault" Width="460" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" Background="White" Topmost="True">
  <!--STYLES-->
  <StackPanel Margin="24,20,24,20">
    <TextBlock x:Name="Heading" FontSize="18" FontWeight="SemiBold" TextWrapping="Wrap"/>
    <TextBlock x:Name="Body" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,4,0,14"/>
    <TextBlock x:Name="Label1" Text="Password"/>
    <PasswordBox x:Name="Pw1" Margin="0,4,0,10"/>
    <StackPanel x:Name="NewPanel" Visibility="Collapsed">
      <TextBlock Text="New password"/>
      <PasswordBox x:Name="Pw2" Margin="0,4,0,6"/>
      <ProgressBar x:Name="Strength" Height="6" Minimum="0" Maximum="4" Value="0" Margin="0,0,0,4"/>
      <TextBlock x:Name="PwHint" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,0,0,10"/>
      <TextBlock Text="Type the new password again"/>
      <PasswordBox x:Name="Pw3" Margin="0,4,0,10"/>
    </StackPanel>
    <StackPanel x:Name="ProgressPanel" Visibility="Collapsed" Margin="0,0,0,12">
      <ProgressBar x:Name="Progress" Height="8" Minimum="0" Maximum="100"/>
      <TextBlock x:Name="ProgressText" Foreground="{StaticResource Muted}" Margin="0,4,0,0"/>
    </StackPanel>
    <TextBlock x:Name="ErrorText" Foreground="#B42318" TextWrapping="Wrap" Margin="0,0,0,10" Visibility="Collapsed"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="BtnOk" Content="Unlock" Style="{StaticResource Primary}" IsDefault="True"/>
      <Button x:Name="BtnCancel" Content="Cancel" IsCancel="True" Margin="0"/>
    </StackPanel>
  </StackPanel>
</Window>
'@

function Get-Controls {
    param($Window, [string[]]$Names)
    $c = @{}
    foreach ($n in $Names) { $c[$n] = $Window.FindName($n) }
    return $c
}

function ConvertTo-FVBrush {
    <# A WPF brush from a colour name or #RRGGBB, made explicitly rather than left to PowerShell's type conversion. #>
    param([Parameter(Mandatory)][string]$Color)
    return (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Color)
}

function Get-FVPolicyWeakWords {
    <# The IT team's extra weak words from the background service (none from an older service). #>
    if ($null -eq $script:Policy -or $null -eq $script:Policy.PSObject.Properties['localWeakWords']) { return @() }
    return @($script:Policy.localWeakWords)
}

function Set-StrengthMeter {
    param($Bar, $Hint, [string]$Password)
    $score = Get-FVPasswordScore -Password $Password
    $Bar.Value = $score
    $colors = @('#B42318', '#B42318', '#B54708', '#027A48', '#027A48')
    $Bar.Foreground = ConvertTo-FVBrush $colors[$score]
    $min = 12
    if ($null -ne $script:Policy) { $min = [int]$script:Policy.minPasswordLength }
    $cfg = [pscustomobject]@{ MinPasswordLength = $min; LocalWeakWords = @(Get-FVPolicyWeakWords) }
    $check = Test-FVPassword -Password $Password -UserName $env:USERNAME -Config $cfg
    if ([string]::IsNullOrEmpty($Password)) { $Hint.Text = "At least $min characters. A short sentence is easiest to remember, e.g. 'Mangoes ripen in March 2027'." }
    elseif ($check.Ok) { $Hint.Text = 'Good password.' }
    else { $Hint.Text = Get-FVPasswordProblemText -Code $check.Problems[0] -MinLength $min }
}

function Show-Error { param($Controls, [string]$Text)
    $Controls.ErrorText.Text = $Text
    if ([string]::IsNullOrEmpty($Text)) { $Controls.ErrorText.Visibility = 'Collapsed' } else { $Controls.ErrorText.Visibility = 'Visible' }
}

function Set-DialogBusy { param($Controls, [bool]$Busy, [string[]]$Inputs)
    $script:Busy = $Busy
    foreach ($n in $Inputs) { if ($null -ne $Controls[$n]) { $Controls[$n].IsEnabled = -not $Busy } }
    $Controls.BtnOk.IsEnabled = -not $Busy
    $Controls.BtnCancel.IsEnabled = -not $Busy
    if ($Busy) { $Controls.ProgressPanel.Visibility = 'Visible' } else { $Controls.ProgressPanel.Visibility = 'Collapsed' }
}

# ---------------------------------------------------------------------------
# Dialog: protect a folder
# ---------------------------------------------------------------------------
function Show-ProtectDialog {
    param([string]$InitialPath, $Owner)
    if ($null -eq $script:Policy -and -not (Update-Policy)) { [void](Show-Message (Get-FVMessage 'BrokerUnavailable') -Kind Error); return $false }
    $w = New-Window $script:ProtectXaml
    if ($null -ne $Owner) { $w.Owner = $Owner }
    $c = Get-Controls $w @('BtnBrowse', 'TxtFolder', 'FolderInfo', 'TxtName', 'CmbSize', 'Pw1', 'Pw2', 'Strength', 'PwHint', 'ChkUnderstand', 'ProgressPanel', 'Progress', 'ProgressText', 'ErrorText', 'BtnOk', 'BtnCancel')
    $state = @{ Check = $null; Done = $false }
    $sizeCfg = [pscustomobject]@{ DefaultVaultSizeGB = [int]$script:Policy.defaultVaultSizeGB; MinVaultSizeGB = [int]$script:Policy.minVaultSizeGB; MaxVaultSizeGB = [int]$script:Policy.maxVaultSizeGB }

    $fillSizes = {
        param([long]$bytes)
        $c.CmbSize.Items.Clear()
        $suggest = Get-FVSuggestedSizeGB -ContentBytes $bytes -Config $sizeCfg
        $options = @($suggest) + @(5, 10, 25, 50, 100, 200, 500 | Where-Object { $_ -gt $suggest -and $_ -le $sizeCfg.MaxVaultSizeGB })
        foreach ($o in $options) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $label = "$o GB"
            if ($o -eq $suggest) { $label += ' (recommended)' }
            $item.Content = $label; $item.Tag = $o
            [void]$c.CmbSize.Items.Add($item)
        }
        $c.CmbSize.SelectedIndex = 0
    }

    $inspect = {
        $p = $c.TxtFolder.Text
        $state.Check = $null
        if ([string]::IsNullOrWhiteSpace($p)) { $c.FolderInfo.Text = ''; return }
        $chk = Get-FVFolderCheck -Path $p -ProfilePath $env:USERPROFILE -Policy $script:Policy
        if (-not $chk.Ok) { $c.FolderInfo.Text = Get-FVMessage $chk.Code; $c.FolderInfo.Foreground = ConvertTo-FVBrush '#B42318'; return }
        $state.Check = $chk
        $c.FolderInfo.Foreground = ConvertTo-FVBrush '#5B6670'
        $c.FolderInfo.Text = '{0:N0} files, {1:N1} MB' -f $chk.Files, ($chk.Bytes / 1MB)
        if ($chk.Synced) { $c.FolderInfo.Text += '. In OneDrive: it will stop syncing once protected.' }
        elseif ($chk.Scope -eq 'Local') { $c.FolderInfo.Text += '. Outside your user folder: only you will be able to open it.' }
        if ([string]::IsNullOrWhiteSpace($c.TxtName.Text)) {
            $leaf = Split-Path -Leaf $chk.Path
            $clean = ($leaf -replace "[^\p{L}\p{N} _\-\.\(\)']", '').Trim()
            if ($clean.Length -gt 40) { $clean = $clean.Substring(0, 40).Trim() }
            $c.TxtName.Text = $clean
        }
        & $fillSizes $chk.Bytes
    }

    & $fillSizes 0
    Set-StrengthMeter $c.Strength $c.PwHint ''
    if (-not [string]::IsNullOrEmpty($InitialPath)) { $c.TxtFolder.Text = $InitialPath; & $inspect }

    $c.BtnBrowse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Choose the folder to protect'
        $dlg.SelectedPath = [Environment]::GetFolderPath('MyDocuments')
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $c.TxtFolder.Text = $dlg.SelectedPath; & $inspect }
    })
    $c.TxtFolder.Add_LostFocus({ & $inspect })
    $c.Pw1.Add_PasswordChanged({ Set-StrengthMeter $c.Strength $c.PwHint $c.Pw1.Password })
    $w.Add_Closing({ param($s, $e) if ($script:Busy) { $e.Cancel = $true } })

    $c.BtnOk.Add_Click({
        Show-Error $c ''
        & $inspect
        if ($null -eq $state.Check) { Show-Error $c 'Choose a folder that can be protected.'; return }
        if (-not (Test-FolderVaultName -Name $c.TxtName.Text)) { Show-Error $c (Get-FVMessage 'NameInvalid'); return }
        if ($c.Pw1.Password -cne $c.Pw2.Password) { Show-Error $c (Get-FVPasswordProblemText -Code 'Mismatch'); return }
        $check = Test-FVPassword -Password $c.Pw1.Password -UserName $env:USERNAME -Config ([pscustomobject]@{ MinPasswordLength = [int]$script:Policy.minPasswordLength; LocalWeakWords = @(Get-FVPolicyWeakWords) })
        if (-not $check.Ok) { Show-Error $c (Get-FVPasswordProblemText -Code $check.Problems[0] -MinLength ([int]$script:Policy.minPasswordLength)); return }
        if (-not $c.ChkUnderstand.IsChecked) { Show-Error $c 'Please tick the box to confirm you will keep the password safe.'; return }
        foreach ($warn in @(Get-FVProtectWarnings -Check $state.Check)) {
            if ((Show-Message ($warn + "`r`n`r`nProtect this folder?") -Kind Question) -ne 'Yes') { Show-Error $c 'Nothing was changed.'; return }
        }

        $args2 = @{ Path = $state.Check.Path; Name = $c.TxtName.Text; Password = $c.Pw1.Password; SizeGB = [int]$c.CmbSize.SelectedItem.Tag; Verify = [string]$script:Policy.verifyMode; Profile = $env:USERPROFILE; Policy = $script:Policy }
        $state.Drive = $state.Check.Path.Substring(0, 2)
        $c.Pw1.Clear(); $c.Pw2.Clear()
        Set-DialogBusy $c $true @('BtnBrowse', 'TxtFolder', 'TxtName', 'CmbSize', 'Pw1', 'Pw2', 'ChkUnderstand')
        Start-Background -Arguments $args2 -Work {
            param($a, $broker, $progress)
            Invoke-FVProtectFolder -Path $a.Path -Name $a.Name -Password $a.Password -SizeGB $a.SizeGB -ProfilePath $a.Profile -Policy $a.Policy -Broker $broker -Progress $progress -VerifyMode $a.Verify
        } -OnProgress {
            param($t, $p) $c.ProgressText.Text = $t; $c.Progress.Value = $p
        } -OnDone {
            param($r)
            Set-DialogBusy $c $false @('BtnBrowse', 'TxtFolder', 'TxtName', 'CmbSize', 'Pw1', 'Pw2', 'ChkUnderstand')
            if ($r.Ok) {
                $msg = $r.Message
                if (@($r.Warnings).Count -gt 0) { $msg += "`r`n`r`n" + (@($r.Warnings) -join "`r`n`r`n") }
                $msg += "`r`n`r`nTip: for the strongest protection, ask IT to confirm BitLocker is switched on for this computer's $($state.Drive) drive."
                [void](Show-Message $msg)
                $state.Done = $true
                $w.Close()
            } else {
                Show-Error $c (Get-ResponseText ([pscustomobject]@{ code = $r.Code; message = $r.Message; data = $r.Data }))
            }
        }
    })
    [void]$w.ShowDialog()
    return $state.Done
}

# ---------------------------------------------------------------------------
# Dialog: password prompt (unlock / remove / change password / finish)
# ---------------------------------------------------------------------------
function Show-PasswordDialog {
    <#
        $Mode: Unlock | Remove | Change | Resume
        Runs the operation in the background and returns the final result object, or $null if cancelled.
    #>
    param([Parameter(Mandatory)]$Vault, [ValidateSet('Unlock', 'Remove', 'Change', 'Resume')][string]$Mode, $Owner)
    $w = New-Window $script:PasswordXaml
    if ($null -ne $Owner) { $w.Owner = $Owner; $w.Topmost = $false }
    $c = Get-Controls $w @('Heading', 'Body', 'Label1', 'Pw1', 'NewPanel', 'Pw2', 'Pw3', 'Strength', 'PwHint', 'ProgressPanel', 'Progress', 'ProgressText', 'ErrorText', 'BtnOk', 'BtnCancel')
    $state = @{ Result = $null }
    switch ($Mode) {
        'Unlock' { $c.Heading.Text = "Unlock '$($Vault.name)'"; $c.Body.Text = $Vault.folderPath; $c.BtnOk.Content = 'Unlock' }
        'Remove' {
            $c.Heading.Text = "Remove protection from '$($Vault.name)'"
            $c.Body.Text = "The files will be put back in $($Vault.folderPath) as a normal folder that anyone using this Windows account can open. Close any open files from this folder first."
            $c.BtnOk.Content = 'Remove protection'
        }
        'Change' {
            $c.Heading.Text = "Change the password for '$($Vault.name)'"
            $c.Body.Text = 'Lock the folder and close its files first. Tell the new password to the people who share this folder.'
            $c.Label1.Text = 'Current password'; $c.NewPanel.Visibility = 'Visible'; $c.BtnOk.Content = 'Change password'
            Set-StrengthMeter $c.Strength $c.PwHint ''
            $c.Pw2.Add_PasswordChanged({ Set-StrengthMeter $c.Strength $c.PwHint $c.Pw2.Password })
        }
        'Resume' {
            $c.Heading.Text = "Finish protecting '$($Vault.name)'"
            $c.Body.Text = 'Protecting this folder was interrupted. Enter its password and Folder Vault will finish or safely undo it. No files will be lost.'
            $c.BtnOk.Content = 'Continue'
        }
    }
    $w.Add_Closing({ param($s, $e) if ($script:Busy) { $e.Cancel = $true } })
    $w.Add_ContentRendered({ [void]$c.Pw1.Focus() })

    $c.BtnOk.Add_Click({
        Show-Error $c ''
        if ([string]::IsNullOrEmpty($c.Pw1.Password)) { Show-Error $c 'Enter the password.'; return }
        $a = @{ Vault = $Vault; Password = $c.Pw1.Password; Mode = $Mode; Verify = 'Hash' }
        if ($null -ne $script:Policy) { $a.Verify = [string]$script:Policy.verifyMode }
        if ($Mode -eq 'Change') {
            if ($c.Pw2.Password -cne $c.Pw3.Password) { Show-Error $c (Get-FVPasswordProblemText -Code 'Mismatch'); return }
            $a.NewPassword = $c.Pw2.Password
        }
        $c.Pw1.Clear(); $c.Pw2.Clear(); $c.Pw3.Clear()
        Set-DialogBusy $c $true @('Pw1', 'Pw2', 'Pw3')
        Start-Background -Arguments $a -Work {
            param($a, $broker, $progress)
            switch ($a.Mode) {
                'Unlock' {
                    & $progress 'Unlocking...' 30
                    $r = & $broker @{ op = 'Unlock'; id = [string]$a.Vault.id; password = $a.Password }
                    return [pscustomobject]@{ Ok = [bool]$r.ok; Code = $r.code; Message = $r.message; Data = $r.data; Warnings = @() }
                }
                'Change' {
                    & $progress 'Locking...' 20
                    $l = Invoke-FVLockVault -Vault $a.Vault -Broker $broker
                    if (-not $l.Ok) { return $l }
                    & $progress 'Changing the password...' 50
                    $r = & $broker @{ op = 'ChangePassword'; id = [string]$a.Vault.id; password = $a.Password; newPassword = $a.NewPassword }
                    return [pscustomobject]@{ Ok = [bool]$r.ok; Code = $r.code; Message = $r.message; Data = $r.data; Warnings = @() }
                }
                'Remove' { return (Invoke-FVUnprotectFolder -Vault $a.Vault -Password $a.Password -Broker $broker -Progress $progress -VerifyMode $a.Verify) }
                'Resume' { return (Resolve-FVUnfinished -Vault $a.Vault -Password $a.Password -Broker $broker -VerifyMode $a.Verify) }
            }
        } -OnProgress {
            param($t, $p) $c.ProgressText.Text = $t; $c.Progress.Value = $p
        } -OnDone {
            param($r)
            Set-DialogBusy $c $false @('Pw1', 'Pw2', 'Pw3')
            if ($r.Ok) { $state.Result = $r; $w.Close(); return }
            Show-Error $c (Get-ResponseText ([pscustomobject]@{ code = $r.Code; message = $r.Message; data = $r.Data }))
            [void]$c.Pw1.Focus()
        }
    })
    [void]$w.ShowDialog()
    return $state.Result
}

# ---------------------------------------------------------------------------
# Actions shared by the window, the tray and the Explorer menu
# ---------------------------------------------------------------------------
function Invoke-UnlockAndOpen {
    param($Vault, $Owner)
    if ($Vault.state -eq 'NeedsAttention') { [void](Show-Message (Get-FVMessage 'NeedsAttention') -Kind Warning); return }
    if ($Vault.state -eq 'Creating') { [void](Invoke-Resume -Vault $Vault -Owner $Owner); return }
    if ($Vault.state -eq 'Unlocked') { Open-Folder $Vault.folderPath; return }
    $r = Show-PasswordDialog -Vault $Vault -Mode Unlock -Owner $Owner
    if ($null -ne $r) { Open-Folder $Vault.folderPath }
}

function Invoke-Resume {
    param($Vault, $Owner)
    $r = Show-PasswordDialog -Vault $Vault -Mode Resume -Owner $Owner
    if ($null -ne $r) {
        $msg = $r.Message
        if (@($r.Warnings).Count -gt 0) { $msg += "`r`n`r`n" + (@($r.Warnings) -join "`r`n") }
        [void](Show-Message $msg)
        return $true
    }
    return $false
}

function Invoke-LockVault {
    param($Vault)
    $r = Invoke-FVLockVault -Vault $Vault -Broker $script:BrokerSb -AskUser { param($m) Confirm-Force $m }
    if (-not $r.Ok -and $r.Code -ne 'Cancelled') { [void](Show-Message $r.Message -Kind Error) }
    return $r
}

function Invoke-LockAll {
    $r = Invoke-FVLockAll -Broker $script:BrokerSb -AskUser { param($m) Confirm-Force $m }
    if (-not $r.Ok) { [void](Show-Message $r.Message -Kind Warning) }
    return $r
}

# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
$script:Main = $null
$script:MainControls = $null

function Update-MainWindow {
    $c = $script:MainControls
    if ($null -eq $c) { return }
    $ok = Update-Vaults
    $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    foreach ($v in $script:Vaults) {
        $type = 'Personal'
        if ($v.scope -eq 'Shared') { $type = 'Shared' }
        $rows.Add([pscustomobject]@{ Status = (Get-StateText $v); Name = $v.name; Folder = $v.folderPath; Type = $type; Vault = $v })
    }
    $c.VaultList.ItemsSource = $rows
    if ($rows.Count -gt 0) { $c.EmptyText.Visibility = 'Collapsed' } else { $c.EmptyText.Visibility = 'Visible' }
    if ($ok) { $c.StatusText.Text = 'Folders lock automatically when you lock the screen (Windows key + L), sign out, or after a while.' }
    else { $c.StatusText.Text = Get-FVMessage 'BrokerUnavailable' }
}

function Get-SelectedVault {
    param([switch]$Require)
    $i = $script:MainControls.VaultList.SelectedItem
    if ($null -eq $i) {
        if ($Require) { [void](Show-Message 'Select a protected folder in the list first.') }
        return $null
    }
    return $i.Vault
}

function Get-MainWindow {
    if ($null -ne $script:Main) { return $script:Main }
    $w = New-Window $script:MainXaml
    $c = Get-Controls $w @('StatusText', 'BtnProtect', 'BtnUnlock', 'BtnLock', 'BtnLockAll', 'BtnPassword', 'BtnRemove', 'VaultList', 'EmptyText')
    $script:MainControls = $c
    $script:Main = $w

    $c.BtnProtect.Add_Click({ if (Show-ProtectDialog -Owner $script:Main) { Update-MainWindow } })
    $c.BtnUnlock.Add_Click({ $v = Get-SelectedVault -Require; if ($null -ne $v) { Invoke-UnlockAndOpen -Vault $v -Owner $script:Main; Update-MainWindow } })
    $c.VaultList.Add_MouseDoubleClick({ $v = Get-SelectedVault; if ($null -ne $v) { Invoke-UnlockAndOpen -Vault $v -Owner $script:Main; Update-MainWindow } })
    $c.BtnLock.Add_Click({ $v = Get-SelectedVault -Require; if ($null -ne $v) { [void](Invoke-LockVault -Vault $v); Update-MainWindow } })
    $c.BtnLock.ToolTip = 'Locks the selected folder. Folders also lock by themselves when you lock the screen.'
    $c.BtnLockAll.Add_Click({ $r = Invoke-LockAll; if ($r.Ok) { [void](Show-Message $r.Message) }; Update-MainWindow })
    $c.BtnPassword.Add_Click({
        $v = Get-SelectedVault -Require
        if ($null -eq $v) { return }
        $r = Show-PasswordDialog -Vault $v -Mode Change -Owner $script:Main
        if ($null -ne $r) { [void](Show-Message 'Password changed. The folder is locked.') }
        Update-MainWindow
    })
    $c.BtnRemove.Add_Click({
        $v = Get-SelectedVault -Require
        if ($null -eq $v) { return }
        $r = Show-PasswordDialog -Vault $v -Mode Remove -Owner $script:Main
        if ($null -ne $r) {
            $msg = $r.Message
            if (@($r.Warnings).Count -gt 0) { $msg += "`r`n`r`n" + (@($r.Warnings) -join "`r`n") }
            [void](Show-Message $msg)
        }
        Update-MainWindow
    })
    $w.Add_Activated({ Update-MainWindow })
    return $w
}

function Request-ResumeUnfinished {
    param($Owner)
    foreach ($v in @($script:Vaults | Where-Object { $_.state -eq 'Creating' -and $_.mine })) {
        $ans = Show-Message "Protecting '$($v.name)' did not finish last time.`r`n`r`nFinish it now? No files will be lost either way." -Kind Question
        if ($ans -eq 'Yes') { [void](Invoke-Resume -Vault $v -Owner $Owner) }
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
try {
    switch ($Action) {
        'Open' {
            [void](Update-Policy)
            $m = Get-MainWindow
            $m.Add_ContentRendered({ Request-ResumeUnfinished -Owner $script:Main })
            [void]$m.ShowDialog()
        }
        'Protect' {
            [void](Update-Vaults)
            if (-not [string]::IsNullOrEmpty($Path)) {
                $existing = Get-VaultByFolder -Folder $Path
                if ($null -ne $existing) { [void](Show-Message "'$Path' is already protected."); return }
            }
            [void](Show-ProtectDialog -InitialPath $Path)
        }
        'Unlock' {
            [void](Update-Policy)
            if (-not (Update-Vaults)) { [void](Show-Message (Get-FVMessage 'BrokerUnavailable') -Kind Error); return }
            $v = $null
            if (-not [string]::IsNullOrEmpty($Id)) { $v = Get-VaultById -VaultId $Id }
            elseif (-not [string]::IsNullOrEmpty($Path)) { $v = Get-VaultByFolder -Folder $Path }
            if ($null -eq $v) {
                if ([string]::IsNullOrEmpty($Path)) { [void](Show-Message (Get-FVMessage 'NotFound') -Kind Warning); return }
                $ans = Show-Message "'$Path' is not protected by Folder Vault.`r`n`r`nProtect it now?" -Kind Question
                if ($ans -eq 'Yes') { [void](Show-ProtectDialog -InitialPath $Path) }
                return
            }
            Invoke-UnlockAndOpen -Vault $v
        }
        'Lock' {
            if (-not (Update-Vaults)) { [void](Show-Message (Get-FVMessage 'BrokerUnavailable') -Kind Error); return }
            $v = Get-VaultByFolder -Folder $Path
            if ($null -eq $v) { [void](Show-Message "'$Path' is not protected by Folder Vault."); return }
            if ($v.state -ne 'Unlocked') { Show-Toast "'$($v.name)' is already locked."; return }
            $r = Invoke-LockVault -Vault $v
            if ($r.Ok) { Show-Toast $r.Message }
        }
        'LockAll' {
            $r = Invoke-LockAll
            if ($r.Ok) { Show-Toast $r.Message }
        }
    }
} catch {
    [void][System.Windows.Forms.MessageBox]::Show("$(Get-FVMessage 'InternalError')`r`n`r`n$($_.Exception.Message)", 'Folder Vault', 'OK', 'Error')
}
