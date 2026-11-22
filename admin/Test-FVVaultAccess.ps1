<#
.SYNOPSIS
    Diagnostic for IT: can a standard user open a vault-style disk on this PC?

.DESCRIPTION
    Builds two small test disks (64 MB, no BitLocker, no real data) the way
    Folder Vault builds a vault, attached two different ways, and checks
    whether the person can list, read and write them through the hidden
    mount folder. It changes nothing in Folder Vault itself and removes
    everything again with -Cleanup.

    Run it in three steps:

      1. In PowerShell **as administrator**:
             .\Test-FVVaultAccess.ps1 -Setup
      2. In ordinary PowerShell (not as administrator), as the person:
             .\Test-FVVaultAccess.ps1 -Check
         It prints a table and saves it to the desktop as
         FolderVault-access-check.txt. Send that file to whoever supports you.
      3. In PowerShell as administrator again:
             .\Test-FVVaultAccess.ps1 -Cleanup

    Needs Folder Vault 0.4.4 or later installed (it borrows the background
    service's own code for the permissions).
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(ParameterSetName = 'Setup', Mandatory)][switch]$Setup,
    [Parameter(ParameterSetName = 'Check')][switch]$Check,
    [Parameter(ParameterSetName = 'Cleanup', Mandatory)][switch]$Cleanup,
    # The person who will run -Check. Default: whoever is signed in at the screen.
    [Parameter(ParameterSetName = 'Setup')][string]$UserName,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'FolderVault')
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'FolderVault-Diag'
$stateFile = Join-Path $root 'state.json'
$methods = @('MountDiskImage', 'Diskpart')

function Test-Admin {
    $p = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Diskpart {
    param([string[]]$Lines)
    $f = Join-Path $root ('dp-' + [guid]::NewGuid().ToString('N') + '.txt')
    [System.IO.File]::WriteAllText($f, (($Lines + 'exit') -join "`r`n") + "`r`n", [System.Text.Encoding]::ASCII)
    try {
        $ErrorActionPreference = 'Continue'
        $out = & "$env:SystemRoot\System32\diskpart.exe" /s $f 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "diskpart failed ($LASTEXITCODE): $out" }
    } finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
}

if ($Setup) {
    if (-not (Test-Admin)) { throw 'Run -Setup in PowerShell as administrator.' }
    Import-Module (Join-Path $InstallDir 'FolderVault.Common.psm1') -Force
    Import-Module (Join-Path $InstallDir 'FolderVault.Engine.psm1') -Force
    if (-not $UserName) { $UserName = [string](Get-CimInstance Win32_ComputerSystem).UserName }
    if (-not $UserName) { throw 'Nobody is signed in at the screen. Add -UserName PC\name.' }
    $sid = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    if (Test-Path $root) { throw "$root already exists. Run -Cleanup first." }
    [void](New-Item -ItemType Directory -Path $root)
    Set-FVSecurity -Path $root -Sddl 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    [void](New-Item -ItemType Directory -Path (Join-Path $root 'Mounts'))
    $state = [ordered]@{ user = $UserName; sid = $sid; disks = @() }
    foreach ($m in $methods) {
        $vhdx = Join-Path $root "$m.vhdx"
        $mount = Join-Path $root "Mounts\$m"
        Write-Host "Building test disk '$m'..."
        Invoke-Diskpart @("create vdisk file=`"$vhdx`" maximum=64 type=expandable")
        if ($m -eq 'MountDiskImage') { [void](Mount-DiskImage -ImagePath $vhdx -StorageType VHDX -NoDriveLetter -PassThru) }
        else { Invoke-Diskpart @("select vdisk file=`"$vhdx`"", 'attach vdisk') }
        $num = $null
        for ($i = 0; $i -lt 40 -and $null -eq $num; $i++) {
            $img = Get-DiskImage -ImagePath $vhdx
            if ($img.Attached -and $null -ne $img.Number) { $num = [int]$img.Number } else { Start-Sleep -Milliseconds 250 }
        }
        if ($null -eq $num) { throw "Test disk '$m' did not appear." }
        Initialize-Disk -Number $num -PartitionStyle GPT
        $part = New-Partition -DiskNumber $num -UseMaximumSize
        Set-Partition -DiskNumber $num -PartitionNumber $part.PartitionNumber -NoDefaultDriveLetter $true
        $vol = (Format-Volume -Partition $part -FileSystem NTFS -NewFileSystemLabel "FVDiag$m" -Confirm:$false).Path
        New-FVPrivateDirectory -Path $mount -Sddl ("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;$sid)")
        $ErrorActionPreference = 'Continue'
        & "$env:SystemRoot\System32\mountvol.exe" ($mount + '\') $vol 2>&1 | Out-Null
        $ErrorActionPreference = 'Stop'
        Set-FVVolumeRootSecurity -VolumePath $vol -Sddl ("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$sid)")
        [System.IO.File]::WriteAllText((Join-Path $mount 'hello.txt'), 'hello')
        $rootSddl = ('FolderVault.VolumeAcl' -as [type])::Get($vol.TrimEnd('\') + '\')
        $state.disks += [ordered]@{ method = $m; vhdx = $vhdx; mount = $mount; volume = $vol; disk = $num; rootSddl = $rootSddl
            vhdxSddl = (Get-Acl -LiteralPath $vhdx).Sddl; mountFolderSddl = (Get-Acl -LiteralPath $mount).Sddl }
    }
    [System.IO.File]::WriteAllText($stateFile, (ConvertTo-Json $state -Depth 4))
    # -Check runs without administrator rights, so leave it a readable copy of the state.
    Copy-Item -LiteralPath $stateFile -Destination (Join-Path $env:PUBLIC 'FolderVault-Diag-state.json') -Force
    Write-Host "Ready. Now, as $UserName, in ordinary PowerShell: .\Test-FVVaultAccess.ps1 -Check" -ForegroundColor Green
    return
}

if ($Cleanup) {
    if (-not (Test-Admin)) { throw 'Run -Cleanup in PowerShell as administrator.' }
    foreach ($m in $methods) {
        $vhdx = Join-Path $root "$m.vhdx"; $mount = Join-Path $root "Mounts\$m"
        if (Test-Path $mount) {
            $ErrorActionPreference = 'Continue'
            & "$env:SystemRoot\System32\mountvol.exe" ($mount + '\') /D 2>&1 | Out-Null
            $ErrorActionPreference = 'Stop'
        }
        if (Test-Path $vhdx) { try { Dismount-DiskImage -ImagePath $vhdx | Out-Null } catch { Write-Host "Detach ${m}: $($_.Exception.Message)" } }
    }
    Start-Sleep -Seconds 1
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $env:PUBLIC 'FolderVault-Diag-state.json') -Force -ErrorAction SilentlyContinue
    if (Test-Path $root) { Write-Host "Could not remove $root completely. Restart the PC and run -Cleanup again." -ForegroundColor Yellow }
    else { Write-Host 'Test disks removed.' -ForegroundColor Green }
    return
}

# -Check (the default): run as the person, without administrator rights.
$publicState = Join-Path $env:PUBLIC 'FolderVault-Diag-state.json'
if (-not (Test-Path $publicState)) { throw 'Run -Setup (as administrator) first.' }
$state = ConvertFrom-Json ([System.IO.File]::ReadAllText($publicState))
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("Folder Vault access check, $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
$lines.Add("Windows: $([System.Environment]::OSVersion.VersionString); PowerShell $($PSVersionTable.PSVersion)")
$lines.Add("Running as: $($me.Name) ($($me.User.Value)); set up for: $($state.user) ($($state.sid)); administrator now: $(Test-Admin)")
$lines.Add('')
foreach ($d in $state.disks) {
    $lines.Add("== Test disk attached with $($d.method) ==")
    $lines.Add("   .vhdx file permissions: $($d.vhdxSddl)")
    $lines.Add("   mount folder permissions: $($d.mountFolderSddl)")
    $lines.Add("   disk root permissions:    $($d.rootSddl)")
    $tests = [ordered]@{
        'List the folder (.NET)'   = { [void][System.IO.Directory]::GetFileSystemEntries($d.mount) }
        'List the folder (dir)'    = { $ErrorActionPreference = 'Continue'; $o = cmd.exe /c "dir `"$($d.mount)`"" 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o | Out-String) } }
        'Read a file'              = { [void][System.IO.File]::ReadAllText((Join-Path $d.mount 'hello.txt')) }
        'Write a file'             = { [System.IO.File]::WriteAllText((Join-Path $d.mount 'written-by-user.txt'), 'x') }
        'Copy with robocopy'       = {
            $src = Join-Path $env:TEMP ('fvdiag-' + [guid]::NewGuid().ToString('N')); [void](New-Item -ItemType Directory $src)
            Set-Content (Join-Path $src 'r.txt') 'r'
            $ErrorActionPreference = 'Continue'
            $null = robocopy.exe $src $d.mount /E /R:0 /W:0 /NP 2>&1; $rc = $LASTEXITCODE
            Remove-Item $src -Recurse -Force
            if ($rc -ge 8) { throw "robocopy exit $rc" }
            if (-not (Test-Path (Join-Path $d.mount 'r.txt'))) { throw "robocopy exit $rc but the file is not there" }
        }
    }
    foreach ($k in $tests.Keys) {
        try { & $tests[$k]; $lines.Add(('   {0,-26} OK' -f $k)) }
        catch { $lines.Add(('   {0,-26} FAILED: {1}' -f $k, ($_.Exception.Message -replace '\s+', ' ').Trim())) }
    }
    $lines.Add('')
}
$lines | ForEach-Object { Write-Host $_ }
$out = Join-Path ([System.Environment]::GetFolderPath('Desktop')) 'FolderVault-access-check.txt'
[System.IO.File]::WriteAllLines($out, $lines)
Write-Host "Saved to $out. Then run -Cleanup as administrator." -ForegroundColor Green
