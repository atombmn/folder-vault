#Requires -Version 5.1
<#
    Folder Vault - background broker. Runs as LocalSystem from the scheduled task
    "Folder Vault Broker" (at startup, restarted on failure).

    Listens on \\.\pipe\FolderVaultBroker. One request per connection.
    Security properties (see docs/ARCHITECTURE.md):
      * Only INTERACTIVE logons may connect; NETWORK is explicitly denied.
      * Clients get Read/Write only - never CreateNewInstance (no pipe squatting
        through a second instance).
      * The pipe instance is created once and reused, so there is no window in
        which another process could claim the name.
      * Caller identity comes from the pipe (impersonation), never from the request.
      * Requests are size-capped, time-limited and strictly validated.
#>
[CmdletBinding()]
param(
    [string]$DataDir = 'C:\ProgramData\FolderVault',
    # Left empty on purpose: Windows PowerShell 5.1 does not always fill in
    # $PSScriptRoot inside param() when started with -File (as the scheduled
    # task does), so the folder is worked out in the body below.
    [string]$InstallDir
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Any error that stops start-up is written down before the service exits,
# so a failed start never goes unexplained. The log folder may not exist yet,
# so this uses plain .NET calls and swallows its own failures.
trap {
    $msg = 'Folder Vault background service failed to start: {0} (script line {1})' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber
    try {
        $dir = $DataDir.TrimEnd('\') + '\Logs'
        if (-not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
        [System.IO.File]::AppendAllText($dir + '\broker-startup.log', ([datetime]::UtcNow.ToString('o') + ' ' + $msg + "`r`n"))
    } catch { Write-Verbose 'startup log failed' }
    try { if ([System.Diagnostics.EventLog]::SourceExists('FolderVault')) { [System.Diagnostics.EventLog]::WriteEntry('FolderVault', $msg, 'Error', 1930) } } catch { Write-Verbose 'startup event failed' }
    [Console]::Error.WriteLine($msg)
    exit 1
}

if ([string]::IsNullOrEmpty($InstallDir)) { $InstallDir = $PSScriptRoot }
if ([string]::IsNullOrEmpty($InstallDir)) { $InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrEmpty($InstallDir)) { throw 'Cannot work out the Folder Vault program folder.' }

Import-Module (Join-Path $InstallDir 'FolderVault.Common.psm1') -Force
Import-Module (Join-Path $InstallDir 'FolderVault.Engine.psm1') -Force
Import-Module (Join-Path $InstallDir 'FolderVault.BrokerCore.psm1') -Force

$paths = Get-FVPaths -DataDir $DataDir -InstallDir $InstallDir

# ---------------------------------------------------------------- logging
$logFile = Join-Path $paths.LogDir 'broker.log'
$eventSourceOk = $false
try { $eventSourceOk = [System.Diagnostics.EventLog]::SourceExists('FolderVault') } catch { $eventSourceOk = $false }

Set-FVLogSink -Sink {
    param($level, $eventId, $message)
    $line = '{0} {1} [{2}] {3}' -f ([datetime]::UtcNow.ToString('o')), $level.ToUpperInvariant(), $eventId, $message
    try {
        if ((Test-Path -LiteralPath $logFile) -and (Get-Item -LiteralPath $logFile).Length -gt 5MB) {
            Move-Item -LiteralPath $logFile -Destination "$logFile.1" -Force
        }
        [System.IO.File]::AppendAllText($logFile, $line + "`r`n")
    } catch { Write-Verbose 'log write failed' }
    if ($eventSourceOk) {
        try {
            $type = [System.Diagnostics.EventLogEntryType]::$level
            [System.Diagnostics.EventLog]::WriteEntry('FolderVault', $message, $type, [int]$eventId)
        } catch { Write-Verbose 'event write failed' }
    }
}

# ---------------------------------------------------------------- state
foreach ($d in @($paths.DataDir, $paths.VaultDir, $paths.EscrowDir, $paths.MountDir, $paths.LogDir)) {
    New-FVPrivateDirectory -Path $d
}

$configObj = $null
if (Test-Path -LiteralPath $paths.ConfigFile) {
    try { $configObj = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($paths.ConfigFile)) }
    catch { Write-FVLog -Level Error -EventId 1910 -Name 'ConfigUnreadable' }
}
$cfgResult = ConvertTo-FVConfig -InputObject $configObj
foreach ($w in $cfgResult.Warnings) { Write-FVLog -Level Warning -EventId 1911 -Name 'ConfigWarning' -Fields @{ detail = $w } }
$config = $cfgResult.Config

$reg = Read-FVRegistry -Path $paths.RegistryFile
if (-not $reg.Ok) {
    Write-FVLog -Level Error -EventId 1912 -Name 'RegistryCorrupt' -Fields @{ detail = 'Broker running in safe mode; no vault operations allowed. Restore vaults.json.bak.' }
}
$registryPath = $paths.RegistryFile
$context = New-FVBrokerContext -Config $config -Paths $paths -Vaults @($reg.Vaults) -RegistryOk $reg.Ok -ComputerName $env:COMPUTERNAME -SaveAction {
    param($vaults)
    Save-FVRegistry -Path $registryPath -Vaults $vaults
}

Initialize-FVBrokerState -Context $context
Write-FVLog -EventId 100 -Name 'BrokerStarted' -Fields @{ count = $context.Vaults.Count; detail = (Get-FVProductVersion) }

# ---------------------------------------------------------------- pipe
function New-FVPipeSecurity {
    $sec = New-Object System.IO.Pipes.PipeSecurity
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $interactive = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-4')
    $network = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-2')
    $sec.SetOwner($system)
    $sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($system, [System.IO.Pipes.PipeAccessRights]::FullControl, 'Allow')))
    $sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($admins, [System.IO.Pipes.PipeAccessRights]::FullControl, 'Allow')))
    $rw = [System.IO.Pipes.PipeAccessRights]::ReadWrite -bor [System.IO.Pipes.PipeAccessRights]::Synchronize
    $sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($interactive, $rw, 'Allow')))
    $sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($network, [System.IO.Pipes.PipeAccessRights]::FullControl, 'Deny')))
    return $sec
}

function Get-FVPipeCaller {
    <# Identity of the connected client, read from its token via impersonation. #>
    param([System.IO.Pipes.NamedPipeServerStream]$Server)
    $info = @{ Sid = $null; Name = $null; IsElevatedAdmin = $false; Interactive = $false }
    $worker = [System.IO.Pipes.PipeStreamImpersonationWorker] ({
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent($true)
        if ($null -eq $id) { $id = [System.Security.Principal.WindowsIdentity]::GetCurrent() }
        $info.Sid = $id.User.Value
        $info.Name = $id.Name
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        $info.IsElevatedAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        foreach ($g in $id.Groups) { if ($g.Value -eq 'S-1-5-4') { $info.Interactive = $true } }
    }.GetNewClosure())
    $Server.RunAsClient($worker)
    if ([string]::IsNullOrEmpty($info.Sid)) { return $null }
    $info.ProfilePath = Get-FVProfilePath -Sid $info.Sid
    return [pscustomobject]$info
}

function Invoke-FVConnection {
    param([System.IO.Pipes.NamedPipeServerStream]$Server)
    $caller = $null
    try { $caller = Get-FVPipeCaller -Server $Server } catch { $caller = $null }
    if ($null -eq $caller -or -not $caller.Interactive) {
        Write-FVLog -Level Warning -EventId 1060 -Name 'CallerRejected' -Fields @{ reason = 'identity' }
        return
    }
    $raw = $null
    try { $raw = Read-FVFrame -Stream $Server -TimeoutMs 10000 }
    catch {
        Write-FVLog -Level Warning -EventId 1061 -Name 'BadFrame' -Fields @{ sid = $caller.Sid; detail = $_.Exception.GetType().Name }
        try { Write-FVFrame -Stream $Server -Object (New-FVResponse -Ok $false -Code 'BadRequest') } catch { Write-Verbose 'reply failed' }
        return
    }
    $check = Test-FVRequest -Request $raw
    $raw = $null
    if (-not $check.Ok) {
        Write-FVLog -Level Warning -EventId 1062 -Name 'BadRequest' -Fields @{ sid = $caller.Sid; code = $check.Code }
        Write-FVFrame -Stream $Server -Object (New-FVResponse -Ok $false -Code $check.Code)
        return
    }
    $req = $check.Request
    $secrets = @()
    foreach ($k in @('password', 'newPassword', 'recoveryKey')) { if ($req.ContainsKey($k)) { $secrets += [string]$req[$k] } }
    Set-FVLogRedaction -Secrets $secrets
    try { $resp = Invoke-FVBrokerRequest -Context $context -Caller $caller -Request $req }
    finally {
        Set-FVLogRedaction -Secrets @()
        $secrets = $null
        foreach ($k in @('password', 'newPassword', 'recoveryKey')) { if ($req.ContainsKey($k)) { $req[$k] = $null } }
    }
    Write-FVFrame -Stream $Server -Object $resp
}

$pipeName = Get-FVPipeName
$server = New-Object System.IO.Pipes.NamedPipeServerStream(
    $pipeName,
    [System.IO.Pipes.PipeDirection]::InOut,
    1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte,
    [System.IO.Pipes.PipeOptions]::Asynchronous,
    65536, 65536,
    (New-FVPipeSecurity))

$script:nextWatchdog = [datetime]::UtcNow
function Get-FVWaitMs {
    if (Test-FVAnyUnlocked -Context $context) { return 1000 }
    return 60000
}
function Invoke-FVWatchdogIfDue {
    # Called while idle AND after every connection, so a client that keeps the
    # pipe busy cannot postpone auto-lock by more than one request timeout.
    # While every vault is locked there is nothing to watch, so no session
    # query runs at all.
    if ([datetime]::UtcNow -lt $script:nextWatchdog) { return }
    if (-not (Test-FVAnyUnlocked -Context $context)) {
        $script:nextWatchdog = [datetime]::UtcNow.AddSeconds($config.WatchdogIntervalSeconds)
        return
    }
    $states = $null
    try { $states = Get-FVSessionStates } catch {
        Write-FVLog -Level Warning -EventId 1005 -Name 'SessionQueryFailed' -Fields @{ detail = $_.Exception.Message }
    }
    try { Invoke-FVBrokerWatchdog -Context $context -SessionStates $states }
    catch { Write-FVLog -Level Error -EventId 1006 -Name 'WatchdogError' -Fields @{ detail = $_.Exception.Message } }
    $script:nextWatchdog = [datetime]::UtcNow.AddSeconds($config.WatchdogIntervalSeconds)
}

while ($true) {
    try {
        $ar = $server.BeginWaitForConnection($null, $null)
        # Wake every second while something is unlocked; otherwise sleep for up
        # to a minute. A connecting client wakes the broker immediately either way.
        while (-not $ar.AsyncWaitHandle.WaitOne((Get-FVWaitMs))) { Invoke-FVWatchdogIfDue }
        $server.EndWaitForConnection($ar)
        Invoke-FVConnection -Server $server
    } catch {
        Write-FVLog -Level Error -EventId 1920 -Name 'PipeError' -Fields @{ detail = $_.Exception.Message }
    } finally {
        try { if ($server.IsConnected) { $server.WaitForPipeDrain() } } catch { Write-Verbose 'drain failed' }
        try { $server.Disconnect() } catch { Write-Verbose 'disconnect failed' }
    }
    Invoke-FVWatchdogIfDue
    # Hand memory used by the last request back to Windows.
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
