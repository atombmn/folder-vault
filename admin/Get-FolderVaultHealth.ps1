#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Health and audit check for Folder Vault on this PC.

.DESCRIPTION
    Reports PASS / WARN / FAIL / INFO for:
      * installed files unchanged since install (SHA-256 manifest)
      * folder permissions not loosened (Program Files, ProgramData)
      * background service task present, running as SYSTEM, answering
      * memory and CPU used by Folder Vault (live 10-second sample)
      * drive C: BitLocker protection
      * every protected folder and its recovery record
      * restore points that may still hold pre-protection copies
      * programs that start when each person signs in, compared with a
        baseline (the first run records it; later runs warn about new ones)
      * security events in the last N days

    It changes nothing, except recording the sign-in baseline in
    C:\ProgramData\FolderVault\signin-baseline.json (readable by administrators
    only) the first time, or when -ResetBaseline is given.

.PARAMETER ResetBaseline
    After checking every new sign-in program reported, accept them as the new normal.

.EXAMPLE
    .\admin\Get-FolderVaultHealth.ps1
    .\admin\Get-FolderVaultHealth.ps1 -Json        # for an RMM tool
#>
[CmdletBinding()]
param(
    [int]$Days = 30,
    [switch]$Json,
    [switch]$ResetBaseline,
    # Only for the automated tests, which point these at test folders.
    [string]$InstallDir = 'C:\Program Files\FolderVault',
    [string]$DataDir = 'C:\ProgramData\FolderVault'
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
# Common holds Test-FVGrantsWrite. Use the package's own copy, which matches this
# health check even when the PC still runs an older Folder Vault; else the installed one.
$commonModule = Join-Path $PSScriptRoot '..\src\FolderVault.Common.psm1'
if (-not (Test-Path -LiteralPath $commonModule)) { $commonModule = Join-Path $InstallDir 'FolderVault.Common.psm1' }
Import-Module $commonModule -Force
Import-Module (Join-Path $PSScriptRoot 'FolderVault.Health.psm1') -Force
$results = New-Object System.Collections.Generic.List[object]
function Add-Result { param([string]$Check, [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
}

# ---------------------------------------------------------------- program files
$manifestPath = Join-Path $DataDir 'install-manifest.json'
if (Test-Path -LiteralPath $manifestPath) {
    $m = ConvertFrom-Json ([System.IO.File]::ReadAllText($manifestPath))
    $bad = @()
    foreach ($p in $m.files.PSObject.Properties) {
        $f = Join-Path $InstallDir $p.Name
        if (-not (Test-Path -LiteralPath $f)) { $bad += "$($p.Name) missing" }
        elseif ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $p.Value) { $bad += "$($p.Name) modified" }
    }
    $extra = @(Get-ChildItem -LiteralPath $InstallDir -File | Where-Object { $null -eq $m.files.PSObject.Properties[$_.Name] } | ForEach-Object { $_.Name })
    if ($extra.Count -gt 0) { $bad += "unexpected files: $($extra -join ', ')" }
    if ($bad.Count -eq 0) { Add-Result 'Program files unchanged' 'PASS' "version $($m.version)" } else { Add-Result 'Program files unchanged' 'FAIL' ($bad -join '; ') }
} else { Add-Result 'Program files unchanged' 'FAIL' 'install-manifest.json missing' }

# ---------------------------------------------------------------- permissions
# Staff may read and run the program; only SYSTEM, Administrators and
# TrustedInstaller may change it.
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Get-WriteOffenders {
    param([string]$Path, [string[]]$Allowed)
    $offenders = @()
    foreach ($ace in (Get-Acl -LiteralPath $Path).Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($Allowed -contains $sid) { continue }
        if (Test-FVGrantsWrite -Rights ([long]$ace.FileSystemRights)) { $offenders += "$($ace.IdentityReference) $($ace.FileSystemRights)" }
    }
    return $offenders
}
$o = @(Get-WriteOffenders $InstallDir $trusted)
if ($o.Count -eq 0) { Add-Result 'Program folder permissions' 'PASS' 'staff can run it; only administrators can change it' }
else { Add-Result 'Program folder permissions' 'FAIL' ('can be changed by: ' + ($o -join '; ')) }
foreach ($sub in @('', 'Vaults', 'Escrow', 'Logs')) {
    $p = Join-Path $DataDir $sub
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $acl = Get-Acl -LiteralPath $p
    $others = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $trusted -notcontains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })
    $name = "Data folder permissions ($(if ($sub) { $sub } else { 'root' }))"
    if ($others.Count -eq 0) { Add-Result $name 'PASS' 'SYSTEM and Administrators only' } else { Add-Result $name 'FAIL' (($others | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join '; ') }
}

# ---------------------------------------------------------------- background service
$task = Get-ScheduledTask -TaskName 'Folder Vault Broker' -TaskPath '\Folder Vault\' -ErrorAction SilentlyContinue
if ($null -eq $task) { Add-Result 'Background service task' 'FAIL' 'not registered' }
else {
    if ($task.Principal.UserId -match 'SYSTEM') { Add-Result 'Background service account' 'PASS' $task.Principal.UserId } else { Add-Result 'Background service account' 'FAIL' $task.Principal.UserId }
    if ($task.State -eq 'Running') { Add-Result 'Background service state' 'PASS' 'Running' } else { Add-Result 'Background service state' 'FAIL' $task.State }
    $exe = @($task.Actions)[0]
    if ($exe.Arguments -like "*$InstallDir\FolderVault.Broker.ps1*") { Add-Result 'Background service command' 'PASS' 'points at the installed program' } else { Add-Result 'Background service command' 'FAIL' $exe.Arguments }
}
Import-Module (Join-Path $InstallDir 'FolderVault.Client.psm1') -Force
$ping = Invoke-FVBroker -Request @{ op = 'Ping' }
if ($ping.ok) { Add-Result 'Background service answering' 'PASS' "genuine (pipe owner verified); version $($ping.data.version)" } else { Add-Result 'Background service answering' 'FAIL' $ping.code }
$startLog = Join-Path $DataDir 'Logs\broker-startup.log'
if (Test-Path -LiteralPath $startLog) {
    $last = @(Get-Content -LiteralPath $startLog -Tail 1) -join ''
    Add-Result 'Background service start-up failures' 'INFO' "at least one earlier start failed. Last: $last"
}

# ---------------------------------------------------------------- resource use
# Targets: docs\ARCHITECTURE.md, section 7.
$fvProcs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*FolderVault.Broker.ps1*' -or $_.CommandLine -like '*FolderVault.Tray.ps1*' })
$samples = @()
foreach ($proc in $fvProcs) {
    $gp = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $gp) { continue }
    $role = 'tray icon'
    if ($proc.CommandLine -like '*FolderVault.Broker.ps1*') { $role = 'background service' }
    $owner = ''
    try { $owner = ' (' + (Invoke-CimMethod -InputObject $proc -MethodName GetOwner).User + ')' } catch { $owner = '' }
    $samples += [pscustomobject]@{ Name = "Resources: $role$owner"; Process = $gp; Cpu0 = $gp.TotalProcessorTime; T0 = [datetime]::UtcNow }
}
if ($samples.Count -gt 0) { Start-Sleep -Seconds 10 }
foreach ($s in $samples) {
    $gp = $s.Process
    $sample = -1
    try {
        $gp.Refresh()
        $secs = ([datetime]::UtcNow - $s.T0).TotalSeconds
        $sample = ($gp.TotalProcessorTime - $s.Cpu0).TotalSeconds / $secs / [Environment]::ProcessorCount * 100
    } catch { $sample = -1 }
    $mins = [math]::Max(1, ((Get-Date) - $gp.StartTime).TotalMinutes)
    $avg = $gp.TotalProcessorTime.TotalSeconds / ($mins * 60) / [Environment]::ProcessorCount * 100
    Add-Result $s.Name 'INFO' (('{0:N0} MB memory; ' -f ($gp.WorkingSet64 / 1MB)) + (Get-FVCpuText -SamplePercent $sample -AveragePercent $avg -Minutes $mins))
}

# ---------------------------------------------------------------- drive C:
$sys = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='C:'"
$prot = 0
if ($null -ne $sys) { $prot = [int](Invoke-CimMethod -InputObject $sys -MethodName GetProtectionStatus).ProtectionStatus }
if ($prot -eq 1) { Add-Result 'Drive C: BitLocker' 'PASS' 'protection on' } else { Add-Result 'Drive C: BitLocker' 'FAIL' 'drive C: is not protected: originals deleted when folders were protected may be recoverable' }

# ---------------------------------------------------------------- protected folders
$list = Invoke-FVBroker -Request @{ op = 'AdminList' }
if ($list.ok) {
    $vs = @($list.data.vaults)
    Add-Result 'Protected folders' 'INFO' "$($vs.Count) on this PC"
    foreach ($v in $vs) {
        $vhdx = Join-Path $DataDir "Vaults\$($v.id).vhdx"
        $esc = Join-Path $DataDir "Escrow\$($v.id).cms"
        $st = 'PASS'; $d = "$($v.state); owner $($v.ownerSid)"
        if (-not (Test-Path -LiteralPath $vhdx)) { $st = 'FAIL'; $d += '; encrypted container missing' }
        if (-not (Test-Path -LiteralPath $esc)) { $st = 'FAIL'; $d += '; recovery key not stored' }
        if ($st -eq 'PASS' -and ($v.state -eq 'NeedsAttention' -or $v.state -eq 'Creating')) { $st = 'WARN' }
        if ([int]$v.failedCount -gt 0) { $d += "; $($v.failedCount) recent wrong passwords" }
        Add-Result "Folder '$($v.name)'" $st $d
    }
} else { Add-Result 'Protected folders' 'FAIL' "list refused: $($list.code) (run as administrator)" }

# ---------------------------------------------------------------- restore points
$shadows = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
if ($shadows.Count -gt 0) { Add-Result 'Restore points' 'WARN' "$($shadows.Count) exist. Ones made before a folder was protected still hold its old, unencrypted copy. Review with: vssadmin list shadows" }
else { Add-Result 'Restore points' 'PASS' 'none' }

# ---------------------------------------------------------------- sign-in programs
# Anyone who knows a person's Windows password could add a program that runs
# when that person signs in (a keylogger, or a fake Folder Vault password window).
# A standard user can only add these in their own profile, so this compares
# each person's Run key and Startup folder with a baseline and reports new ones.
$baselineFile = Join-Path $DataDir 'signin-baseline.json'
$baseline = @{}
$baselineDate = ''
if ((Test-Path -LiteralPath $baselineFile) -and -not $ResetBaseline) {
    try {
        $b = ConvertFrom-Json ([System.IO.File]::ReadAllText($baselineFile))
        $baselineDate = ([datetime]$b.recordedUtc).ToLocalTime().ToString('d MMM yyyy')
        foreach ($u in $b.users.PSObject.Properties) { $baseline[$u.Name] = @($u.Value) }
    } catch { Add-Result 'Sign-in baseline' 'WARN' 'baseline file unreadable; a new one will be recorded'; $baseline = @{} }
}
$newBaseline = @{}
foreach ($k in $baseline.Keys) { $newBaseline[$k] = $baseline[$k] }
$recorded = $false
$profiles = @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.SID -like 'S-1-5-21-*' -and -not [string]::IsNullOrEmpty($_.LocalPath) })
$i = 0
foreach ($p in $profiles) {
    $i++
    $user = Split-Path -Leaf $p.LocalPath
    $items = @(); $overrides = @(); $note = ''
    $startup = Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    if (Test-Path -LiteralPath $startup) {
        foreach ($f in @(Get-ChildItem -LiteralPath $startup -Force -File | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $target = ''
            if ($f.Extension -eq '.lnk') { $target = Get-FVShortcutTarget -Path $f.FullName }
            $items += ('Startup: {0} = {1}' -f $f.Name, $target)
        }
    }
    # Read the person's registry; if they are signed out, open it briefly.
    $hiveRoot = "Registry::HKEY_USERS\$($p.SID)"
    $loaded = $null
    if (-not (Test-FVRegistryKey -Path $hiveRoot)) {
        $dat = Join-Path $p.LocalPath 'NTUSER.DAT'
        $tmpName = "FolderVaultHealth$i"
        $hiveRoot = $null
        if ((Test-Path -LiteralPath $dat) -and (Mount-FVUserHive -Name $tmpName -HiveFile $dat)) { $loaded = $tmpName; $hiveRoot = "Registry::HKEY_USERS\$tmpName" }
        else { $note = ' (their registry could not be opened, so only the Startup folder was checked)' }
    }
    try {
        if ($null -ne $hiveRoot) {
            $reg = Get-FVUserRegistryItems -HiveRoot $hiveRoot
            $items += @($reg.Items)
            $overrides += @($reg.Overrides)
        }
    } finally {
        if ($null -ne $loaded -and -not (Dismount-FVUserHive -Name $loaded)) {
            Add-Result "Registry closed ($user)" 'FAIL' "the health check could not close $user's registry (HKEY_USERS\$loaded). Restart this PC before $user next signs in, or Windows may give them a temporary profile."
        }
    }
    $prior = $null
    if ($baseline.ContainsKey($p.SID)) { $prior = [string[]]$baseline[$p.SID] }
    $v = Get-FVSignInVerdict -Current $items -Baseline $prior -Overrides $overrides -BaselineDate $baselineDate
    if ($v.Record) { $newBaseline[$p.SID] = $items; $recorded = $true }
    Add-Result "Sign-in programs ($user)" $v.Status ($v.Detail + $note)
}
if ($recorded -or $ResetBaseline) {
    $doc = [ordered]@{ recordedUtc = [datetime]::UtcNow.ToString('o'); users = $newBaseline }
    [System.IO.File]::WriteAllText($baselineFile, (ConvertTo-Json $doc -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------- events
$since = (Get-Date).AddDays(-$Days)
$ev = @()
try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'FolderVault'; StartTime = $since } -ErrorAction Stop) } catch { $ev = @() }
foreach ($line in @(Get-FVEventSummary -Events $ev -Days $Days)) { Add-Result $line.Check $line.Status $line.Detail }

if ($Json) { $results | ConvertTo-Json -Depth 3; return }
$color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }
foreach ($r in $results) { Write-Host ("[{0}] {1,-40} {2}" -f $r.Status, $r.Check, $r.Detail) -ForegroundColor $color[$r.Status] }
$fails = @($results | Where-Object Status -eq 'FAIL').Count
$warns = @($results | Where-Object Status -eq 'WARN').Count
Write-Host ''
if ($fails -eq 0 -and $warns -eq 0) { Write-Host 'All checks passed.' -ForegroundColor Green }
elseif ($fails -eq 0) { Write-Host "No failures. $warns item(s) to look at (WARN)." -ForegroundColor Yellow }
else { Write-Host "$fails failure(s), $warns warning(s)." -ForegroundColor Red }
