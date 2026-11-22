#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    End-to-end and adversarial tests of an installed Folder Vault on a real Windows PC.

.DESCRIPTION
    RUN ONLY ON A DISPOSABLE TEST VM (Windows 10/11 Pro, C: BitLocker on or
    Folder Vault installed with -AllowUnencryptedSystemDrive), never on a client PC.
    It creates and deletes local test users, restarts the broker, swaps the
    config temporarily and kills processes.

    Prerequisites on the VM:
      1. A TEST escrow key:  admin\New-FVEscrowCertificate.ps1 -ClientName TEST -OutputDirectory C:\FVTestKeys
      2. Install:             install\Install-FolderVault.ps1 -EscrowCertificate C:\FVTestKeys\FolderVault-Escrow-TEST.cer
      3. Run this script from an elevated Windows PowerShell 5.1 window, signed in
         interactively (it needs your desktop session for the "signed-in" tests):
            .\tests\windows\Invoke-FolderVaultIntegrationTests.ps1 -TestPfxPath C:\FVTestKeys\FolderVault-Escrow-TEST.pfx

    Output: a PASS/FAIL table, results.json and a transcript in C:\FolderVaultTest\.
    Exit code = number of failed tests.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TestPfxPath,
    [switch]$IncludeScreenLockTest,
    [switch]$KeepArtifacts
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$InstallDir = 'C:\Program Files\FolderVault'
$DataDir = 'C:\ProgramData\FolderVault'
$Work = 'C:\FolderVaultTest'
$SharedRoot = 'C:\FolderVaultTestShared'
$TaskName = 'Folder Vault Broker'; $TaskPath = '\Folder Vault\'
$PwA = 'Mangoes ripen in March 2027 ' + (Get-Random -Maximum 99999)
$PwB = 'Pineapples grow slowly 2028 ' + (Get-Random -Maximum 99999)
$Canary = 'CANARY-' + [guid]::NewGuid().ToString('N')

if (Test-Path $Work) { Remove-Item $Work -Recurse -Force }
[void](New-Item -ItemType Directory -Path $Work)
Start-Transcript -Path (Join-Path $Work 'transcript.txt') | Out-Null

Import-Module (Join-Path $InstallDir 'FolderVault.Common.psm1') -Force
Import-Module (Join-Path $InstallDir 'FolderVault.Client.psm1') -Force
Import-Module (Join-Path $InstallDir 'FolderVault.UserOps.psm1') -Force
Import-Module (Join-Path $InstallDir 'FolderVault.Engine.psm1') -Force   # only to read a vault root's permissions (W26)
$broker = { param([hashtable]$r) Invoke-FVBroker -Request $r -ResponseTimeoutMs 900000 }

# ------------------------------------------------------------------ harness
$results = New-Object System.Collections.Generic.List[object]
function Test-Case {
    param([string]$Id, [string]$Title, [scriptblock]$Body)
    $t0 = Get-Date
    try {
        $detail = & $Body
        $results.Add([pscustomobject]@{ Id = $Id; Result = 'PASS'; Title = $Title; Detail = [string]$detail; Seconds = [int]((Get-Date) - $t0).TotalSeconds })
        Write-Host ("[PASS] {0} {1}" -f $Id, $Title) -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -like 'SKIP:*') {
            $results.Add([pscustomobject]@{ Id = $Id; Result = 'SKIP'; Title = $Title; Detail = $_.Exception.Message.Substring(5).Trim(); Seconds = 0 })
            Write-Host ("[SKIP] {0} {1}: {2}" -f $Id, $Title, $_.Exception.Message.Substring(5).Trim()) -ForegroundColor Yellow
            return
        }
        $results.Add([pscustomobject]@{ Id = $Id; Result = 'FAIL'; Title = $Title; Detail = $_.Exception.Message; Seconds = [int]((Get-Date) - $t0).TotalSeconds })
        Write-Host ("[FAIL] {0} {1}: {2}" -f $Id, $Title, $_.Exception.Message) -ForegroundColor Red
    }
}
function Assert-True { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Assert-Code { param($Resp, [string]$Code) if ($Resp.code -ne $Code) { throw "expected $Code, got $($Resp.code): $($Resp.message)" } }

function Restart-Broker {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*FolderVault.Broker.ps1*' } | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    for ($i = 0; $i -lt 40; $i++) { if ((Invoke-FVBroker -Request @{ op = 'Ping' } -ConnectTimeoutMs 1000).ok) { return }; Start-Sleep -Milliseconds 500 }
    throw 'broker did not come back'
}
function Stop-Broker {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*FolderVault.Broker.ps1*' } | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }
    Start-Sleep -Seconds 2
}
function Get-Vault { param([string]$Id) return @((Invoke-FVBroker -Request @{ op = 'AdminList' }).data.vaults | Where-Object { $_.id -eq $Id })[0] }

function New-TestUser {
    param([string]$Name)
    $pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ }) + '!a1'
    $sec = ConvertTo-SecureString $pw -AsPlainText -Force
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $Name }
    New-LocalUser -Name $Name -Password $sec -PasswordNeverExpires -AccountNeverExpires -Description 'Folder Vault test (delete me)' | Out-Null
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $Name
    return New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$Name", $sec)
}
function Invoke-AsUser {
    <# Runs a script block as another (standard, interactive-logon) user and returns its JSON output. #>
    param([System.Management.Automation.PSCredential]$Credential, [string]$Name, [string]$Script, [int]$TimeoutSeconds = 300)
    $file = Join-Path $Work "$Name.ps1"; $out = Join-Path $Work "$Name.out.json"
    $prelude = @"
`$ErrorActionPreference = 'Stop'
Import-Module '$InstallDir\FolderVault.Common.psm1' -Force
Import-Module '$InstallDir\FolderVault.Client.psm1' -Force
Import-Module '$InstallDir\FolderVault.UserOps.psm1' -Force
`$R = [ordered]@{}
try {
"@
    $post = @"
} catch { `$R['error'] = `$_.Exception.Message }
`$R | ConvertTo-Json -Depth 6 | Set-Content -Path '$out' -Encoding UTF8
"@
    Set-Content -Path $file -Value ($prelude + "`r`n" + $Script + "`r`n" + $post) -Encoding UTF8
    if (Test-Path $out) { Remove-Item $out -Force }
    $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $Credential -LoadUserProfile -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$file`"") -WorkingDirectory $Work -PassThru
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) { $p.Kill(); throw "$Name timed out" }
    if (-not (Test-Path $out)) { throw "$Name produced no output" }
    $o = Get-Content $out -Raw | ConvertFrom-Json
    if ($null -ne $o.PSObject.Properties['error']) { throw "$Name failed: $($o.error)" }
    return $o
}
function New-SampleTree {
    param([string]$Path)
    New-Item -ItemType Directory -Path (Join-Path $Path 'Q1\Deep\Deeper'), (Join-Path $Path 'Empty dir') -Force | Out-Null
    Set-Content -Path (Join-Path $Path 'salaries.csv') -Value "name,salary`r`n$Canary,1"
    [System.IO.File]::WriteAllText((Join-Path $Path 'Q1\Deep\Deeper\relevé de paie 2026 ü.txt'), 'unicode name', [System.Text.Encoding]::UTF8)
    $big = New-Object byte[] (64MB); (New-Object System.Random 7).NextBytes($big)
    [System.IO.File]::WriteAllBytes((Join-Path $Path 'Q1\scan.pdf'), $big)
    New-Item -ItemType File -Path (Join-Path $Path 'empty.txt') | Out-Null
    $ro = Join-Path $Path 'readonly.docx'; Set-Content $ro 'ro'; (Get-Item $ro).Attributes = 'ReadOnly'
    $long = Join-Path $Path ('L' * 120)
    New-Item -ItemType Directory -Path $long -Force | Out-Null
    Set-Content -Path (Join-Path $long ('f' * 100 + '.txt')) -Value 'long path'
}

# ------------------------------------------------------------------ setup
Write-Host 'Setting up...' -ForegroundColor Cyan
$cfgFile = Join-Path $DataDir 'config.json'
$cfgBackup = Join-Path $Work 'config.json.bak'
Copy-Item $cfgFile $cfgBackup -Force
$cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json
$cfg.SharedRoots = @($SharedRoot)
$cfg | ConvertTo-Json -Depth 4 | Set-Content $cfgFile -Encoding UTF8
function Set-TestConfig { param([int]$MaxUnlockMinutes)
    $c = Get-Content $cfgBackup -Raw | ConvertFrom-Json
    $c.SharedRoots = @($SharedRoot); $c.MaxUnlockMinutes = $MaxUnlockMinutes
    $c | ConvertTo-Json -Depth 4 | Set-Content $cfgFile -Encoding UTF8
    Restart-Broker
}
$origMaxUnlock = [int]$cfg.MaxUnlockMinutes
if (-not (Test-Path $SharedRoot)) { [void](New-Item -ItemType Directory $SharedRoot) }
Restart-Broker
$credB = New-TestUser -Name 'fvtest_b'
$sidB = (Get-LocalUser -Name 'fvtest_b').SID.Value
# First sign-in creates the profile (slow); do it now so later tests are quick.
[void](Invoke-AsUser -Credential $credB -Name 'warmup' -Script "`$R['ok'] = `$true" -TimeoutSeconds 600)
$folderA = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ('FV-Test-' + (Get-Random -Maximum 99999))
New-SampleTree -Path $folderA
$before = Get-FVTreeManifest -Path $folderA -Mode Hash
$script:vaultA = $null
$script:sharedVault = $null
$script:sharedFolder = $null
$escrowCopy = Join-Path $Work 'escrow-copy.cms'

try {
# ------------------------------------------------------------------ install and plumbing
Test-Case 'W01' 'Broker answers and the pipe is owned by SYSTEM/Administrators' {
    $p = Invoke-FVBroker -Request @{ op = 'Ping' }
    Assert-True $p.ok "ping failed: $($p.code)"
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'FolderVaultBroker', 'InOut', 'None', 'Identification')
    $c.Connect(3000)
    $owner = $c.GetAccessControl().GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    $rules = $c.GetAccessControl().GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $c.Dispose()
    Assert-True (@('S-1-5-18', 'S-1-5-32-544') -contains $owner) "owner $owner"
    $inter = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-4' -and $_.AccessControlType -eq 'Allow' })
    Assert-True ($inter.Count -eq 1) 'no INTERACTIVE rule'
    Assert-True (($inter[0].PipeAccessRights -band [System.IO.Pipes.PipeAccessRights]::CreateNewInstance) -eq 0) 'INTERACTIVE may create pipe instances'
    $net = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-2' -and $_.AccessControlType -eq 'Deny' })
    Assert-True ($net.Count -eq 1) 'NETWORK not denied'
    "owner $owner"
}

Test-Case 'W02' 'Pipe refuses network (SMB loopback) clients' {
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('127.0.0.1', 'FolderVaultBroker', 'InOut', 'None', 'Identification')
    $connected = $false
    try { $c.Connect(3000); $connected = $c.IsConnected } catch { $connected = $false } finally { $c.Dispose() }
    Assert-True (-not $connected) 'connected over the network path'
    'refused'
}

Test-Case 'W03' 'Standard user cannot read containers, escrow or registry' {
    $o = Invoke-AsUser -Credential $credB -Name 'w03' -Script @"
foreach (`$p in @('$DataDir\vaults.json', '$DataDir\config.json', '$DataDir\escrow.cer', '$DataDir\Logs\broker.log')) {
    try { `$null = [System.IO.File]::ReadAllBytes(`$p); `$R[`$p] = 'READABLE' } catch { `$R[`$p] = 'denied' }
}
foreach (`$p in @('$DataDir', '$DataDir\Vaults', '$DataDir\Escrow', '$DataDir\Mounts')) {
    try { `$null = [System.IO.Directory]::GetFileSystemEntries(`$p); `$R[`$p] = 'READABLE' } catch { `$R[`$p] = 'denied' }
}
try { [System.IO.File]::WriteAllText('$InstallDir\evil.ps1', 'x'); `$R['writeInstall'] = 'WRITABLE' } catch { `$R['writeInstall'] = 'denied' }
"@
    foreach ($p in $o.PSObject.Properties) { Assert-True ($p.Value -eq 'denied') "$($p.Name) is $($p.Value)" }
    'all denied'
}

# ------------------------------------------------------------------ protect
Test-Case 'W10' 'Protect a folder (64 MB file, unicode and long names, read-only, empty dir)' {
    $r = Invoke-FVProtectFolder -Path $folderA -Name 'FV Test A' -Password $PwA -SizeGB 2 -ProfilePath $env:USERPROFILE -Broker $broker -VerifyMode Hash
    Assert-True $r.Ok "$($r.Code): $($r.Message)"
    Assert-True (@($r.Warnings).Count -eq 0) ("warnings: " + (@($r.Warnings) -join ' | '))
    $script:vaultA = $r.Data.id
    Copy-Item (Join-Path $DataDir "Escrow\$($r.Data.id).cms") $escrowCopy
    "vault $($r.Data.id)"
}
Test-Case 'W11' 'Locked folder is a link showing only the unlock shortcut; no plaintext left beside it' {
    Assert-True (Test-FVReparsePath -Path $folderA) 'folder is not a link'
    $shown = @(Get-ChildItem -Force $folderA -ErrorAction SilentlyContinue)
    Assert-True ($shown.Count -eq 1 -and $shown[0].Name -eq 'Locked - double-click here to unlock.lnk') ("locked folder shows: " + ($shown.Name -join ', '))
    $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut($shown[0].FullName)
    Assert-True ($lnk.Arguments -like "*FolderVault.UI.ps1*-Action Unlock -Id $vaultA*") "shortcut arguments: $($lnk.Arguments)"
    # The owner may only read the locked placeholder, never add files to it.
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = Get-Acl -LiteralPath (Join-Path $DataDir "Mounts\$vaultA")
    $mine = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $me })
    $write = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership'
    Assert-True (@($mine | Where-Object { ($_.FileSystemRights -band $write) -ne 0 }).Count -eq 0) 'owner can write to the locked placeholder'
    $leftover = @(Get-ChildItem -Force (Split-Path $folderA) | Where-Object { $_.Name -like '*foldervault-original*' -or $_.Name -like '*foldervault-probe*' })
    Assert-True ($leftover.Count -eq 0) "leftover: $($leftover.Name -join ',')"
    $v = Get-Vault $vaultA
    Assert-True ($v.state -eq 'Locked') "state $($v.state)"
    Assert-True (-not (Get-DiskImage -ImagePath (Join-Path $DataDir "Vaults\$vaultA.vhdx")).Attached) 'container still attached'
    'locked'
}
Test-Case 'W12' 'Container is unreadable without the password (raw VHDX bytes contain no plaintext)' {
    $vhdx = Join-Path $DataDir "Vaults\$vaultA.vhdx"
    $fs = [System.IO.File]::OpenRead($vhdx)
    try {
        $buf = New-Object byte[] (4MB); $hit = $false; $tail = ''
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            $chunk = $tail + [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
            if ($chunk.Contains($Canary)) { $hit = $true; break }
            $tail = $chunk.Substring([math]::Max(0, $chunk.Length - 64))
        }
    } finally { $fs.Dispose() }
    Assert-True (-not $hit) 'canary text found in the container file'
    'no plaintext'
}

# ------------------------------------------------------------------ unlock / lock
Test-Case 'W20' 'Wrong password refused and logged without the password' {
    $r = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = "$Canary wrong" }
    Assert-Code $r 'BadPassword'
    Start-Sleep -Seconds 2
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'FolderVault'; Id = 1010; StartTime = (Get-Date).AddMinutes(-2) })
    Assert-True ($ev.Count -ge 1) 'no 1010 event'
    $log = Get-Content (Join-Path $DataDir 'Logs\broker.log') -Raw
    Assert-True (-not $log.Contains($Canary)) 'password text reached broker.log'
    Start-Sleep -Seconds 3
    'refused + logged'
}
Test-Case 'W21' 'Correct password unlocks; every file is byte-identical' {
    Start-Sleep -Seconds 3
    $r = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $PwA }
    Assert-True $r.ok "$($r.code)"
    $after = Get-FVTreeManifest -Path $folderA -Mode Hash -ExcludeTopLevel (Get-FVVolumeSystemNames)
    $cmp = Compare-FVManifest -Source $before -Destination $after
    Assert-True $cmp.Ok ("missing: " + ($cmp.Missing -join ',') + " mismatched: " + ($cmp.Mismatched -join ','))
    "$($before.Count) entries verified"   # count-safe: manifest is a Dictionary
}
Test-Case 'W26' 'Unlocked vault has no drive letter, is our own virtual disk, and its root lets in only its owner (A-20, A-23, A-33)' {
    $img = Get-DiskImage -ImagePath (Join-Path $DataDir "Vaults\$vaultA.vhdx")
    Assert-True ($img.Attached -and $null -ne $img.Number) 'container not attached while unlocked'
    $disk = Get-Disk -Number $img.Number
    Assert-True ([string]$disk.BusType -eq 'File Backed Virtual' -or [string]$disk.BusType -eq '15') "bus type $($disk.BusType)"
    $letters = @(Get-Partition -DiskNumber $img.Number | Where-Object { [string]$_.DriveLetter -match '^[A-Za-z]$' })
    Assert-True ($letters.Count -eq 0) ('vault has drive letter ' + (($letters | ForEach-Object { $_.DriveLetter }) -join ','))
    $parts = @(Get-Partition -DiskNumber $img.Number | Where-Object { $_.Type -eq 'Basic' })
    Assert-True ($parts.Count -eq 1) "basic partitions: $($parts.Count)"
    Assert-True ([bool]$parts[0].NoDefaultDriveLetter) 'NoDefaultDriveLetter is off'
    # A-33: the volume's own root grants the owner, not just the mount point folder.
    $volPath = @($parts[0].AccessPaths | Where-Object { $_ -like '\\?\Volume*' })[0]
    if (-not ('FolderVault.VolumeAcl' -as [type])) { Add-Type -TypeDefinition (& (Get-Module FolderVault.Engine) { $script:FVVolumeAclSource }) }
    $rootSddl = ('FolderVault.VolumeAcl' -as [type])::Get($volPath)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert-True ($rootSddl -match [regex]::Escape(";;;$me)")) "vault root does not grant its owner: $rootSddl"
    Assert-True ($rootSddl -notmatch ';;;(BU|AU|WD)\)') "vault root grants other people: $rootSddl"
    @(Get-ChildItem -LiteralPath (Join-Path $DataDir "Mounts\$vaultA") -Force -ErrorAction Stop) | Out-Null
    "disk $($img.Number), no letter"
}
Test-Case 'W22' 'Vault volume: XTS-AES-256, passphrase + recovery protectors only, no auto-unlock' {
    $disk = Get-DiskImage -ImagePath (Join-Path $DataDir "Vaults\$vaultA.vhdx") | Get-Disk
    $part = @(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.GptType -eq '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' })[0]
    $volPath = @($part.AccessPaths | Where-Object { $_ -like '\\?\Volume*' })[0]
    $v = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume | Where-Object DeviceID -eq $volPath
    $m = (Invoke-CimMethod -InputObject $v -MethodName GetEncryptionMethod).EncryptionMethod
    Assert-True ($m -eq 7) "encryption method $m"
    $types = @()
    foreach ($kp in @((Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 }).VolumeKeyProtectorID)) {
        $types += [int](Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = $kp }).KeyProtectorType
    }
    Assert-True ((@($types | Sort-Object) -join ',') -eq '3,8') "protector types $($types -join ',')"
    $au = (Invoke-CimMethod -InputObject $v -MethodName IsAutoUnlockEnabled).IsAutoUnlockEnabled
    Assert-True (-not $au) 'auto-unlock enabled'
    'XTS-AES-256; protectors 3,8'
}
Test-Case 'W23' 'Another standard user cannot see, unlock or read the vault (even while unlocked)' {
    $mount = Join-Path $DataDir "Mounts\$vaultA"
    $o = Invoke-AsUser -Credential $credB -Name 'w23' -Script @"
`$l = Invoke-FVBroker -Request @{ op = 'List' }
`$R['listed'] = @(`$l.data.vaults | Where-Object { `$_.id -eq '$vaultA' }).Count
`$R['unlock'] = (Invoke-FVBroker -Request @{ op = 'Unlock'; id = '$vaultA'; password = 'x' }).code
`$R['remove'] = (Invoke-FVBroker -Request @{ op = 'Remove'; id = '$vaultA'; password = 'x' }).code
`$R['lockForce'] = (Invoke-FVBroker -Request @{ op = 'Lock'; id = '$vaultA'; force = `$true }).code
try { `$null = Get-ChildItem -LiteralPath '$mount' -ErrorAction Stop; `$R['readMount'] = 'READABLE' } catch { `$R['readMount'] = 'denied' }
try { `$null = Get-ChildItem -LiteralPath '$folderA' -ErrorAction Stop; `$R['readLink'] = 'READABLE' } catch { `$R['readLink'] = 'denied' }
"@
    Assert-True ($o.listed -eq 0) 'vault listed for user B'
    Assert-True ($o.unlock -eq 'NotFound') "unlock: $($o.unlock)"
    Assert-True ($o.remove -eq 'NotFound') "remove: $($o.remove)"
    Assert-True ($o.lockForce -eq 'NotFound') "lock: $($o.lockForce)"
    Assert-True ($o.readMount -eq 'denied') 'B can read the unlocked vault'
    Assert-True ($o.readLink -eq 'denied') 'B can read through the link'
    'all refused'
}
Test-Case 'W24' 'Open file blocks a normal lock; forced lock works and purges the key' {
    $fs = [System.IO.File]::Open((Join-Path $folderA 'salaries.csv'), 'Open', 'ReadWrite', 'None')
    try {
        $r = Invoke-FVBroker -Request @{ op = 'Lock'; id = $vaultA; force = $false }
        Assert-Code $r 'FilesInUse'
        Assert-True ((Get-Vault $vaultA).state -eq 'Unlocked') 'state changed after refused lock'
        $r2 = Invoke-FVBroker -Request @{ op = 'Lock'; id = $vaultA; force = $true }
        Assert-True $r2.ok "forced lock: $($r2.code)"
    } finally { try { $fs.Dispose() } catch { } }
    Assert-True (-not (Get-DiskImage -ImagePath (Join-Path $DataDir "Vaults\$vaultA.vhdx")).Attached) 'still attached'
    'FilesInUse then forced'
}
Test-Case 'W25' 'Password guessing is throttled by the broker' {
    $codes = @()
    for ($i = 0; $i -lt 7; $i++) { $codes += (Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = "guess $i $Canary" }).code }
    Assert-True (@($codes[0..2] | Where-Object { $_ -ne 'BadPassword' }).Count -eq 0) ("first three: " + ($codes -join ','))
    Assert-True ($codes -contains 'Throttled') ("never throttled: " + ($codes -join ','))
    Start-Sleep -Seconds 65
    $ok = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $PwA }
    Assert-True $ok.ok "correct password after back-off: $($ok.code)"
    [void](Invoke-FVBroker -Request @{ op = 'Lock'; id = $vaultA; force = $true })
    ($codes -join ',')
}

# ------------------------------------------------------------------ adversarial requests
Test-Case 'W30' 'Raw pipe: confused-deputy paths refused server-side' {
    $bad = @("C:\Users\fvtest_b\Documents\X", 'C:\Windows\Temp\FV', "$DataDir\Mounts", "$env:USERPROFILE\AppData\Roaming\X", "$env:USERPROFILE\Documents", '\\127.0.0.1\c$\Users')
    $codes = foreach ($p in $bad) { (Invoke-FVBroker -Request @{ op = 'Create'; path = $p; name = 'evil'; password = $PwA; sizeGB = 1; contentBytes = 0 }).code }
    foreach ($c in $codes) { Assert-True (@('PathNotAllowed', 'PathInvalid') -contains $c) "accepted: $($codes -join ',')" }
    ($codes -join ',')
}
Test-Case 'W31' 'Raw pipe: malformed, oversized and slow requests do not crash the broker' {
    $send = {
        param([byte[]]$Bytes, [int]$Pause = 0)
        $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'FolderVaultBroker', 'InOut', 'None', 'Identification')
        try { $c.Connect(3000); if ($Bytes.Length) { $c.Write($Bytes, 0, $Bytes.Length) }; if ($Pause) { Start-Sleep -Seconds $Pause } } catch { } finally { $c.Dispose() }
    }
    & $send ([byte[]](0xFF, 0xFF, 0xFF, 0x7F))                                   # 2 GB length prefix
    & $send ([byte[]](10, 0, 0, 0) + [System.Text.Encoding]::UTF8.GetBytes('{bad json'))
    & $send ([byte[]](5, 0, 0, 0, 0xC3, 0x28, 0x7B, 0x7D, 0x00))                  # invalid UTF-8
    & $send ([byte[]](100, 0, 0, 0, 1, 2)) 12                                     # truncated + stall past timeout
    $json = [System.Text.Encoding]::UTF8.GetBytes('{"v":1,"op":"Unlock","id":"' + $vaultA + '","password":"x","sid":"S-1-5-18"}')
    & $send ([System.BitConverter]::GetBytes([int]$json.Length) + $json)        # extra field (identity spoof attempt)
    $r = Invoke-FVBroker -Request @{ op = 'Ping' }
    Assert-True $r.ok 'broker not answering after fuzzing'
    $proc = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*FolderVault.Broker.ps1*' })
    Assert-True ($proc.Count -eq 1) "broker processes: $($proc.Count)"
    'alive'
}
Test-Case 'W32' 'Client-side: folders containing junctions are refused' {
    $d = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ('FV-Junction-' + (Get-Random))
    New-Item -ItemType Directory $d | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $d 'sys') -Target 'C:\Windows\System32' | Out-Null
    try { $chk = Get-FVFolderCheck -Path $d -ProfilePath $env:USERPROFILE -Policy $null; Assert-True ($chk.Code -eq 'PathHasLinks') $chk.Code }
    finally { [System.IO.Directory]::Delete((Join-Path $d 'sys'), $false); Remove-Item $d -Force }
    'refused'
}
Test-Case 'W33' 'Pipe squatting: the client will not send a password to a fake broker' {
    Stop-Broker
    $log = Join-Path $Work 'squatter.log'
    $fake = @"
`$s = New-Object System.IO.Pipes.NamedPipeServerStream('FolderVaultBroker', 'InOut', 1, 'Byte', 'None')
`$s.WaitForConnection()
`$buf = New-Object byte[] 65536; `$n = 0
try { `$s.ReadTimeout = 5000 } catch { }
`$t = [datetime]::UtcNow.AddSeconds(8)
while ([datetime]::UtcNow -lt `$t) { if (`$s.IsConnected) { try { `$n += `$s.Read(`$buf, `$n, 65536 - `$n) } catch { break } } else { break } }
[System.IO.File]::WriteAllText('$log', [System.Text.Encoding]::UTF8.GetString(`$buf, 0, `$n))
"@
    $fakeFile = Join-Path $Work 'w33.ps1'
    Set-Content -Path $fakeFile -Value $fake -Encoding UTF8
    $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $credB -LoadUserProfile -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$fakeFile`"") -WorkingDirectory $Work -PassThru
    Start-Sleep -Seconds 6
    try {
        $r = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $Canary }
        Assert-Code $r 'BrokerUntrusted'
        Start-Sleep -Seconds 9
        if (Test-Path $log) { Assert-True (-not ((Get-Content $log -Raw) -like "*$Canary*")) 'password reached the fake broker' }
    } finally {
        try { if (-not $p.HasExited) { $p.Kill() } } catch { }
        Restart-Broker
    }
    'BrokerUntrusted, nothing sent'
}

# ------------------------------------------------------------------ automatic locking
Test-Case 'W40' 'Broker restart locks everything' {
    $u = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $PwA }
    Assert-True $u.ok $u.code
    Restart-Broker
    Assert-True ((Get-Vault $vaultA).state -eq 'Locked') 'not locked after restart'
    Assert-True (-not (Get-DiskImage -ImagePath (Join-Path $DataDir "Vaults\$vaultA.vhdx")).Attached) 'still attached'
    'locked'
}
Test-Case 'W41' 'Maximum unlock time (temporarily 1 minute) locks the vault' {
    Set-TestConfig -MaxUnlockMinutes 1
    try {
        $u = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $PwA }
        Assert-True $u.ok $u.code
        Start-Sleep -Seconds 80
        Assert-True ((Get-Vault $vaultA).state -eq 'Locked') 'still unlocked after timeout'
    } finally { Set-TestConfig -MaxUnlockMinutes $origMaxUnlock }
    'locked by timeout'
}
Test-Case 'W42' 'Shared vault unlocked by a signed-out user locks within seconds' {
    $sf = Join-Path $SharedRoot ('Team-' + (Get-Random))
    $o = Invoke-AsUser -Credential $credB -Name 'w42' -Script @"
New-Item -ItemType Directory -Path '$sf' | Out-Null
Set-Content -Path '$sf\minutes.txt' -Value 'board minutes'
`$b = { param([hashtable]`$r) Invoke-FVBroker -Request `$r -ResponseTimeoutMs 900000 }
`$p = Invoke-FVBroker -Request @{ op = 'GetPolicy' }
`$x = Invoke-FVProtectFolder -Path '$sf' -Name 'Team' -Password '$PwB' -SizeGB 1 -ProfilePath `$env:USERPROFILE -Policy `$p.data -Broker `$b
`$R['protect'] = `$x.Code; `$R['id'] = `$x.Data.id
`$u = Invoke-FVBroker -Request @{ op = 'Unlock'; id = `$x.Data.id; password = '$PwB' }
`$R['unlock'] = `$u.code
"@
    Assert-True ($o.protect -eq 'Ok') "protect as B: $($o.protect)"
    Assert-True ($o.unlock -eq 'Ok') "unlock as B: $($o.unlock)"
    Start-Sleep -Seconds 20
    $v = Get-Vault $o.id
    Assert-True ($v.state -eq 'Locked') "state $($v.state)"
    $script:sharedVault = $o.id
    $script:sharedFolder = $sf
    'locked (SignedOut)'
}
if ($IncludeScreenLockTest) {
    Test-Case 'W43' 'Screen lock locks the vault (you will need to sign back in)' {
        $u = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $PwA }
        Assert-True $u.ok $u.code
        Write-Host 'Locking the screen in 5 seconds. Sign back in after ~30 seconds.' -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        & "$env:SystemRoot\System32\rundll32.exe" user32.dll, LockWorkStation
        Start-Sleep -Seconds 25
        Assert-True ((Get-Vault $vaultA).state -eq 'Locked') 'still unlocked while the screen was locked'
        'locked (ScreenLocked)'
    }
}

# ------------------------------------------------------------------ passwords and recovery
Test-Case 'W50' 'Change password: old stops working, new works' {
    Start-Sleep -Seconds 2
    $c = Invoke-FVBroker -Request @{ op = 'ChangePassword'; id = $vaultA; password = $PwA; newPassword = $PwB }
    Assert-True $c.ok "change: $($c.code)"
    Assert-Code (Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $PwA }) 'BadPassword'
    Start-Sleep -Seconds 2
    $u = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $PwB }
    Assert-True $u.ok "new password: $($u.code)"
    [void](Invoke-FVBroker -Request @{ op = 'Lock'; id = $vaultA; force = $true })
    'changed'
}
Test-Case 'W51' 'Escrowed recovery key resets the password; the key is rotated afterwards' {
    $pfxPw = Read-Host 'Test PFX password' -AsSecureString
    $imp = Import-PfxCertificate -FilePath $TestPfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $pfxPw
    try {
        $key = (Unprotect-CmsMessage -Path $escrowCopy | ConvertFrom-Json).recoveryKey
        Assert-True (Test-FVRecoveryKeyFormat $key) 'escrow did not contain a recovery key'
        $newPw = 'Recovered passphrase for testing ' + (Get-Random)
        $r = Invoke-FVBroker -Request @{ op = 'AdminReset'; id = $vaultA; recoveryKey = $key; newPassword = $newPw } -ResponseTimeoutMs 300000
        Assert-True $r.ok "reset: $($r.code)"
        $u = Invoke-FVBroker -Request @{ op = 'Unlock'; id = $vaultA; password = $newPw }
        Assert-True $u.ok "unlock with reset password: $($u.code)"
        [void](Invoke-FVBroker -Request @{ op = 'Lock'; id = $vaultA; force = $true })
        $r2 = Invoke-FVBroker -Request @{ op = 'AdminReset'; id = $vaultA; recoveryKey = $key; newPassword = $PwA } -ResponseTimeoutMs 300000
        Assert-Code $r2 'BadRecoveryKey'
        $key2 = (Unprotect-CmsMessage -Path (Join-Path $DataDir "Escrow\$vaultA.cms") | ConvertFrom-Json).recoveryKey
        Assert-True ($key2 -ne $key) 'escrow not rotated'
        Start-Sleep -Seconds 3
        $r3 = Invoke-FVBroker -Request @{ op = 'AdminReset'; id = $vaultA; recoveryKey = $key2; newPassword = $PwA } -ResponseTimeoutMs 300000
        Assert-True $r3.ok "reset back: $($r3.code)"
    } finally { foreach ($c in @($imp)) { Remove-Item ("Cert:\CurrentUser\My\" + $c.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue } }
    'reset + rotated'
}
Test-Case 'W52' 'Non-elevated callers cannot use admin operations' {
    $o = Invoke-AsUser -Credential $credB -Name 'w52' -Script @"
`$R['list'] = (Invoke-FVBroker -Request @{ op = 'AdminList' }).code
`$R['reset'] = (Invoke-FVBroker -Request @{ op = 'AdminReset'; id = '$vaultA'; recoveryKey = '111111-111111-111111-111111-111111-111111-111111-111111'; newPassword = 'Bananas are yellow in 2029' }).code
"@
    Assert-True ($o.list -eq 'NotAuthorized') "AdminList: $($o.list)"
    Assert-True ($o.reset -eq 'NotAuthorized') "AdminReset: $($o.reset)"
    'refused'
}

# ------------------------------------------------------------------ 0.3.0: any folder of your own
function Test-ProtectRoundTrip {
    <# Protect, check the scope, lock, unlock, compare every file, remove protection, compare again. #>
    param([string]$Folder, [string]$ExpectScope)
    $before2 = Get-FVTreeManifest -Path $Folder -Mode Hash
    $policy = (Invoke-FVBroker -Request @{ op = 'GetPolicy' }).data
    $chk = Get-FVFolderCheck -Path $Folder -ProfilePath $env:USERPROFILE -Policy $policy
    Assert-True $chk.Ok "window check refused: $($chk.Code)"
    Assert-True ($chk.Scope -eq $ExpectScope) "window says scope $($chk.Scope)"
    $r = Invoke-FVProtectFolder -Path $Folder -Name ('FV ' + $ExpectScope) -Password $PwA -SizeGB 1 -ProfilePath $env:USERPROFILE -Policy $policy -Broker $broker -VerifyMode Hash
    Assert-True $r.Ok "$($r.Code): $($r.Message)"
    $id = $r.Data.id
    try {
        $mine = @((Invoke-FVBroker -Request @{ op = 'List' }).data.vaults | Where-Object { $_.id -eq $id })
        Assert-True ($mine.Count -eq 1 -and $mine[0].scope -eq $ExpectScope) "broker recorded scope $(@($mine | ForEach-Object { $_.scope }) -join ',')"
        Assert-True (Test-FVReparsePath -Path $Folder) 'folder is not a link after protecting'
        Assert-True (@(Get-ChildItem -Force $Folder).Count -eq 1) 'locked folder shows more than the unlock shortcut'
        Assert-Code (Invoke-FVBroker -Request @{ op = 'Unlock'; id = $id; password = $PwA }) 'Ok'
        $cmp = Compare-FVManifest -Source $before2 -Destination (Get-FVTreeManifest -Path $Folder -Mode Hash -ExcludeTopLevel (Get-FVVolumeSystemNames))
        Assert-True $cmp.Ok ("unlocked copy differs: " + ($cmp.Missing + $cmp.Mismatched -join ','))
        Assert-Code (Invoke-FVBroker -Request @{ op = 'Lock'; id = $id; force = $true }) 'Ok'
    } finally {
        $u = Invoke-FVUnprotectFolder -Vault ([pscustomobject]@{ id = $id; folderPath = $Folder }) -Password $PwA -Broker $broker -VerifyMode Hash
        Assert-True $u.Ok "remove protection: $($u.Code): $($u.Message)"
    }
    $cmp = Compare-FVManifest -Source $before2 -Destination (Get-FVTreeManifest -Path $Folder -Mode Hash)
    Assert-True $cmp.Ok ("restored copy differs: " + ($cmp.Missing + $cmp.Mismatched -join ','))
    return "vault $id ($ExpectScope), $($before2.Count) entries round-tripped"   # count-safe: manifest is a Dictionary
}
$localRoot = 'C:\FolderVaultTestLocal'
Test-Case 'W13' 'A folder outside the user folder (C:\FolderVaultTestLocal\Accounts) is protected as Local and comes back intact' {
    if (Test-Path $localRoot) { Remove-Item $localRoot -Recurse -Force }
    $f = Join-Path $localRoot 'Accounts'
    New-SampleTree -Path $f
    Test-ProtectRoundTrip -Folder $f -ExpectScope 'Local'
}
Test-Case 'W14' 'A OneDrive folder is protected (copied without robocopy) and comes back intact' {
    $od = $env:OneDrive
    if ([string]::IsNullOrEmpty($od) -or -not (Test-Path $od)) { throw 'SKIP: OneDrive is not set up for this account' }
    if (@(Get-Process -Name OneDrive -ErrorAction SilentlyContinue).Count -eq 0) { throw 'SKIP: OneDrive is not running' }
    $f = Join-Path $od ('FV-Test-' + (Get-Random -Maximum 99999))
    New-Item -ItemType Directory -Path $f | Out-Null
    Set-Content -LiteralPath (Join-Path $f 'budget.csv') -Value "line,amount`r`n1,100"
    New-Item -ItemType Directory -Path (Join-Path $f 'Q1') | Out-Null
    $big = New-Object byte[] (8MB); (New-Object System.Random 7).NextBytes($big)
    [System.IO.File]::WriteAllBytes((Join-Path $f 'Q1\scan.pdf'), $big)
    Start-Sleep -Seconds 60   # let OneDrive turn the new files into synced placeholders
    $tag = Get-FVReparseTag -Path (Join-Path $f 'budget.csv')
    try {
        $out = Test-ProtectRoundTrip -Folder $f -ExpectScope 'Profile'
    } finally { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue }
    return ('{0}; reparse tag of a synced file 0x{1:X8}' -f $out, $tag)
}
Test-Case 'W15' 'Other people''s folders, the Public folder and non-fixed drives are refused by the background service' {
    $other = Join-Path (Split-Path $env:USERPROFILE) 'fvtest_b\Documents\Taken'
    Assert-Code (Invoke-FVBroker -Request @{ op = 'Create'; path = $other; name = 'X'; password = $PwA; sizeGB = 1; contentBytes = 0 }) 'PathOtherUser'
    Assert-Code (Invoke-FVBroker -Request @{ op = 'Create'; path = 'C:\Users\Public\Documents\Taken'; name = 'X'; password = $PwA; sizeGB = 1; contentBytes = 0 }) 'PathOtherUser'
    $free = @([char[]](70..90) | ForEach-Object { [string]$_ } | Where-Object { -not (Test-Path "$($_):\") })[-1]
    Assert-Code (Invoke-FVBroker -Request @{ op = 'Create'; path = "$($free):\Payroll"; name = 'X'; password = $PwA; sizeGB = 1; contentBytes = 0 }) 'PathNotLocalDisk'
    Assert-Code (Invoke-FVBroker -Request @{ op = 'Create'; path = 'C:\Windows.old\x'; name = 'X'; password = $PwA; sizeGB = 1; contentBytes = 0 }) 'PathNotAllowed'
    Assert-Code (Invoke-FVBroker -Request @{ op = 'Create'; path = (Join-Path $env:USERPROFILE 'Documents'); name = 'X'; password = $PwA; sizeGB = 1; contentBytes = 0 }) 'PathWholeFolder'
    "refused as expected; unused drive letter $free tested"
}

# ------------------------------------------------------------------ remove protection
Test-Case 'W60' 'Remove protection restores identical files and deletes the container and escrow' {
    Start-Sleep -Seconds 2
    $r = Invoke-FVUnprotectFolder -Vault ([pscustomobject]@{ id = $vaultA; folderPath = $folderA }) -Password $PwA -Broker $broker -VerifyMode Hash
    Assert-True $r.Ok "$($r.Code): $($r.Message)"
    Assert-True (-not (Test-FVReparsePath -Path $folderA)) 'still a link'
    $attr = (Get-Item -Force -LiteralPath $folderA).Attributes
    Assert-True (($attr -band [System.IO.FileAttributes]'Hidden, System') -eq 0) "restored folder attributes: $attr (A-21)"
    $cmp = Compare-FVManifest -Source $before -Destination (Get-FVTreeManifest -Path $folderA -Mode Hash)
    Assert-True $cmp.Ok ("missing: " + ($cmp.Missing -join ',') + " mismatched: " + ($cmp.Mismatched -join ','))
    Assert-True (-not (Test-Path (Join-Path $DataDir "Vaults\$vaultA.vhdx"))) 'container left behind'
    Assert-True (-not (Test-Path (Join-Path $DataDir "Escrow\$vaultA.cms"))) 'escrow left behind'
    Assert-True (-not (Test-Path (Join-Path $DataDir "Mounts\$vaultA"))) 'mount folder left behind'
    $script:vaultA = $null
    'restored'
}

# ------------------------------------------------------------------ evidence
Test-Case 'W70' 'No test password appears in the event log or broker log' {
    $msgs = (Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'FolderVault'; StartTime = (Get-Date).AddHours(-3) } | ForEach-Object { $_.Message }) -join "`n"
    $msgs += Get-Content (Join-Path $DataDir 'Logs\broker.log') -Raw
    foreach ($s in @($PwA, $PwB, $Canary)) { Assert-True (-not $msgs.Contains($s)) 'secret found in logs' }
    'clean'
}
Test-Case 'W71' 'Health check reports no failures' {
    $h = & (Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'admin\Get-FolderVaultHealth.ps1') -Json | ConvertFrom-Json
    $fails = @($h | Where-Object { $_.Status -eq 'FAIL' -and $_.Check -ne 'C: drive BitLocker' })
    Assert-True ($fails.Count -eq 0) (($fails | ForEach-Object { "$($_.Check): $($_.Detail)" }) -join '; ')
    "$(@($h).Count) checks"
}

# ------------------------------------------------------------------ resource use
Test-Case 'W80' 'Resource use while every folder is locked (background service and tray icon)' {
    $locked = @((Invoke-FVBroker -Request @{ op = 'AdminList' }).data.vaults | Where-Object { $_.state -ne 'Locked' })
    Assert-True ($locked.Count -eq 0) 'a vault is still unlocked'
    Start-Sleep -Seconds 30
    $measure = {
        param([string]$Pattern)
        $c = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like $Pattern })
        if ($c.Count -eq 0) { return $null }   # count-safe: assigned with @( ) just above
        $p = Get-Process -Id $c[0].ProcessId
        $t0 = $p.TotalProcessorTime
        Start-Sleep -Seconds 120
        $p.Refresh()
        $cpu = ($p.TotalProcessorTime - $t0).TotalSeconds / 120 / [Environment]::ProcessorCount * 100
        return [pscustomobject]@{ MB = [math]::Round($p.WorkingSet64 / 1MB); Cpu = [math]::Round($cpu, 3) }
    }
    $b = & $measure '*FolderVault.Broker.ps1*'
    Assert-True ($null -ne $b) 'background service not running'
    $t = & $measure '*FolderVault.Tray.ps1*'
    $detail = "service $($b.MB) MB, $($b.Cpu)% CPU"
    if ($null -ne $t) { $detail += "; tray $($t.MB) MB, $($t.Cpu)% CPU" } else { $detail += '; tray not running in this session' }
    # Targets from docs\ARCHITECTURE.md section 7. Record the real figures in the test report either way.
    Assert-True ($b.Cpu -lt 0.2) "service CPU too high: $detail"
    Assert-True ($b.MB -lt 120) "service memory too high: $detail"
    if ($null -ne $t) { Assert-True ($t.Cpu -lt 0.2 -and $t.MB -lt 90) "tray too heavy: $detail" }
    $detail
}

} finally {
    # ------------------------------------------------------------------ cleanup
    Write-Host 'Cleaning up...' -ForegroundColor Cyan
    if (-not $KeepArtifacts) {
        try {
            if ($script:sharedVault) {
                $x = Invoke-FVUnprotectFolder -Vault ([pscustomobject]@{ id = $script:sharedVault; folderPath = $script:sharedFolder }) -Password $PwB -Broker $broker
                if ($x.Ok) { Remove-Item $script:sharedFolder -Recurse -Force -ErrorAction SilentlyContinue }
            }
            if ($script:vaultA) {
                [void](Invoke-FVBroker -Request @{ op = 'Lock'; id = $script:vaultA; force = $true })
                foreach ($pw in @($PwA, $PwB)) {
                    $x = Invoke-FVUnprotectFolder -Vault ([pscustomobject]@{ id = $script:vaultA; folderPath = $folderA }) -Password $pw -Broker $broker
                    if ($x.Ok) { break }
                }
            }
        } catch { Write-Warning "cleanup: $($_.Exception.Message)" }
        if (Test-Path $folderA) { if (-not (Test-FVReparsePath -Path $folderA)) { Remove-Item $folderA -Recurse -Force -ErrorAction SilentlyContinue } }
        $lf = Join-Path $localRoot 'Accounts'
        # Never delete through a link: if W13 left Accounts protected, leave it for a person to remove.
        if ((Test-Path $localRoot) -and -not (Test-FVReparsePath -Path $lf)) { Remove-Item $localRoot -Recurse -Force -ErrorAction SilentlyContinue }
        try {
            $all = @((Invoke-FVBroker -Request @{ op = 'AdminList' }).data.vaults)
            foreach ($v in $all) {
                if ($v.name -notlike 'FV *' -and $v.name -ne 'Team') { continue }
                Write-Host "  leftover vault $($v.name) ($($v.id)) - remove it with the Folder Vault window or by hand" -ForegroundColor Yellow
            }
        } catch { }
        Remove-LocalUser -Name 'fvtest_b' -ErrorAction SilentlyContinue
        Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sidB } | Remove-CimInstance -ErrorAction SilentlyContinue
    }
    Copy-Item $cfgBackup $cfgFile -Force
    try { Restart-Broker } catch { Write-Warning "Broker restart failed: $($_.Exception.Message)" }
    $results | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $Work 'results.json') -Encoding UTF8
    Write-Host ''
    $results | Format-Table Id, Result, Seconds, Title, Detail -AutoSize -Wrap
    $failed = @($results | Where-Object Result -eq 'FAIL').Count
    Write-Host ("{0} passed, {1} failed. Results: {2}" -f (@($results).Count - $failed), $failed, (Join-Path $Work 'results.json')) -ForegroundColor $(if ($failed) { 'Red' } else { 'Green' })
    Stop-Transcript | Out-Null
    exit $failed
}
