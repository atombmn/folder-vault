#Requires -Version 5.1
<#
    Folder Vault - privileged vault engine. Runs ONLY inside the SYSTEM broker.

    Security rule for this module: it never reads, writes, creates or mounts
    anything in a user-controlled location. Every path it touches is built from
    the broker's own data directory and a GUID it generated itself:
        <DataDir>\Vaults\{id}.vhdx     encrypted container
        <DataDir>\Escrow\{id}.cms      recovery key, encrypted to the IT team's certificate
        <DataDir>\Mounts\{id}          mount point (users only reach it through
                                       the junction they create in their folder)

    Windows-specific calls are wrapped in small Invoke-FV*/Get-FV* functions so
    the orchestration logic can be unit-tested with mocks.
#>

Set-StrictMode -Version 3.0

$script:BdeNamespace = 'root/CIMV2/Security/MicrosoftVolumeEncryption'
$script:FVE_E_FAILED_AUTHENTICATION = [uint32]2150694951   # 0x80310027
$script:E_ACCESS_DENIED = [uint32]2147942405               # 0x80070005
$script:ProtectorPassphrase = [uint32]8
$script:ProtectorNumerical = [uint32]3
$script:GptBasicData = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
$script:EkuDocumentEncryption = '1.3.6.1.4.1.311.80.1'
# Shown inside a locked folder (lives in the broker's own Mounts\{id} folder,
# which a mounted volume covers while the vault is unlocked).
$script:UnlockShortcutName = 'Locked - double-click here to unlock.lnk'
$script:SidCache = @{}

# SDDL templates. SY = LocalSystem, BA = Administrators, BU = Users.
$script:SddlPrivate = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
# 0x1200a9 = read + execute on the directory itself only (empty placeholder when locked).
$script:SddlMountPlaceholderFmt = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;{0})'
$script:SddlVolumeRootProfileFmt = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})'
# 0x1301bf = Modify.
$script:SddlVolumeRootShared = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)'

function New-FVEngineResult {
    param([bool]$Ok, [string]$Code = 'Ok', [string]$Stage = '', $Data = $null, [string]$Detail = '')
    return [pscustomobject]@{ Ok = $Ok; Code = $Code; Stage = $Stage; Data = $Data; Detail = $Detail }
}

function Get-FolderVaultFiles {
    <# Derives every path for a vault id. Refuses anything that is not a GUID. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Paths)
    if ($Id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw [System.ArgumentException]::new('Vault id must be a GUID')
    }
    $id = $Id.ToLowerInvariant()
    return [pscustomobject]@{
        Vhdx   = Join-FVPath $Paths.VaultDir "$id.vhdx"
        Escrow = Join-FVPath $Paths.EscrowDir "$id.cms"
        Mount  = Join-FVPath $Paths.MountDir $id
        Shortcut = Join-FVPath (Join-FVPath $Paths.MountDir $id) $script:UnlockShortcutName
    }
}

# ---------------------------------------------------------------------------
# Thin wrappers around Windows (mocked in tests)
# ---------------------------------------------------------------------------
function Invoke-FVDiskpartCreate {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$VhdxPath, [Parameter(Mandatory)][int]$SizeGB, [Parameter(Mandatory)][string]$ScratchDir)
    if ($VhdxPath -notmatch '^[A-Za-z]:\\[^"\r\n]+\.vhdx$') { throw [System.ArgumentException]::new('Bad VHDX path') }
    if (-not $PSCmdlet.ShouldProcess($VhdxPath, 'Create VHDX')) { return }
    $script = Join-FVPath $ScratchDir ("dp-" + [guid]::NewGuid().ToString() + '.txt')
    $mb = [long]$SizeGB * 1024
    $content = "create vdisk file=`"$VhdxPath`" maximum=$mb type=expandable`r`nexit`r`n"
    [System.IO.File]::WriteAllText($script, $content, [System.Text.Encoding]::ASCII)
    try {
        $r = Invoke-FVNative -FilePath "$env:SystemRoot\System32\diskpart.exe" -ArgumentList @('/s', $script)
        if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $VhdxPath)) {
            throw [System.InvalidOperationException]::new("diskpart failed ($($r.ExitCode)): " + $r.Text)
        }
    } finally {
        Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
    }
}

function Mount-FVVhd {
    <# Attaches the VHDX without a drive letter and returns the disk number. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$VhdxPath)
    $img = Get-DiskImage -ImagePath $VhdxPath -ErrorAction Stop
    if (-not $img.Attached) {
        $img = Mount-DiskImage -ImagePath $VhdxPath -StorageType VHDX -NoDriveLetter -PassThru -ErrorAction Stop
    }
    for ($i = 0; $i -lt 20; $i++) {
        $img = Get-DiskImage -ImagePath $VhdxPath -ErrorAction SilentlyContinue
        if ($null -ne $img -and $img.Attached -and $null -ne $img.Number) {
            $disk = Get-Disk -Number ([int]$img.Number) -ErrorAction SilentlyContinue
            if ($null -ne $disk) {
                Assert-FolderVaultDisk -Disk $disk -Image $img -VhdxPath $VhdxPath
                return [int]$disk.Number
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw [System.InvalidOperationException]::new('Disk did not appear after attach')
}

function Assert-FolderVaultDisk {
    <#
        Throws unless $Disk is the disk Windows created for our own VHDX file.
        Guards every initialise / partition / format / unlock call.

        The link is made through the disk image: MSFT_DiskImage.Number is the
        disk number of the attached image. (MSFT_Disk.Location cannot be used:
        Microsoft documents it as NULL for VHD/VHDX disks. 0.2.4 relied on it,
        so every protection would have been refused; found in the 13 Nov 2026 audit.)
        BusType is checked as well: 15 = "File Backed Virtual". Get-Disk may
        report it as the number or as the text, so both are accepted.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Disk, [Parameter(Mandatory)]$Image, [Parameter(Mandatory)][string]$VhdxPath)
    $why = $null
    if (-not [string]::Equals([string]$Image.ImagePath, $VhdxPath, [System.StringComparison]::OrdinalIgnoreCase)) { $why = 'image path differs' }
    elseif (-not [bool]$Image.Attached -or $null -eq $Image.Number) { $why = 'image is not attached' }
    elseif ([int]$Image.Number -ne [int]$Disk.Number) { $why = "image is disk $($Image.Number)" }
    else {
        $bus = [string]$Disk.BusType
        if ($bus -ne '15' -and $bus -ne 'File Backed Virtual') { $why = "bus type is $bus" }
    }
    if ($null -ne $why) {
        throw [System.InvalidOperationException]::new("Refusing to use disk $($Disk.Number): it is not this vault's container ($why)")
    }
}

function Test-FVDiskIsBlank {
    <# A disk that has never been initialised reports PartitionStyle RAW (as text) or 0 (Unknown, as a number). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Disk)
    $ps = [string]$Disk.PartitionStyle
    return ($ps -eq 'RAW' -or $ps -eq '0' -or $ps -eq 'Unknown')
}

function Dismount-FVVhd {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$VhdxPath)
    if (-not (Test-Path -LiteralPath $VhdxPath)) { return }
    $img = Get-DiskImage -ImagePath $VhdxPath -ErrorAction SilentlyContinue
    if ($null -ne $img -and $img.Attached -and $PSCmdlet.ShouldProcess($VhdxPath, 'Detach')) {
        Dismount-DiskImage -ImagePath $VhdxPath -ErrorAction Stop | Out-Null
    }
}

function Test-FVVhdAttached {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$VhdxPath)
    if (-not (Test-Path -LiteralPath $VhdxPath)) { return $false }
    $img = Get-DiskImage -ImagePath $VhdxPath -ErrorAction SilentlyContinue
    return ($null -ne $img -and [bool]$img.Attached)
}

function Initialize-FolderVaultDisk {
    <# Fresh disk -> GPT -> one NTFS partition. Returns the volume path \\?\Volume{...}\ #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int]$DiskNumber, [Parameter(Mandatory)][string]$VhdxPath)
    $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
    $img = Get-DiskImage -ImagePath $VhdxPath -ErrorAction Stop
    Assert-FolderVaultDisk -Disk $disk -Image $img -VhdxPath $VhdxPath
    if (-not (Test-FVDiskIsBlank -Disk $disk)) { throw [System.InvalidOperationException]::new("Refusing to initialise disk ${DiskNumber}: it is not empty") }
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT -ErrorAction Stop | Out-Null
    $part = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -GptType $script:GptBasicData -ErrorAction Stop
    # Never give the vault a drive letter (it would show in "This PC" while unlocked),
    # now or on any later attach. Honoured on GPT disks, which this is.
    Set-Partition -DiskNumber $DiskNumber -PartitionNumber $part.PartitionNumber -NoDefaultDriveLetter $true -ErrorAction Stop
    Remove-FVDriveLetters -DiskNumber $DiskNumber
    $vol = Format-Volume -Partition $part -FileSystem NTFS -NewFileSystemLabel 'FolderVault' -Confirm:$false -Force -ErrorAction Stop
    Remove-FVDriveLetters -DiskNumber $DiskNumber
    if ($null -ne $vol -and $vol.Path) { return [string]$vol.Path }
    return (Get-FVVolumePath -DiskNumber $DiskNumber)
}

function Remove-FVDriveLetters {
    <# Removes any drive letter Windows assigned to a vault partition by itself. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][int]$DiskNumber)
    foreach ($p in @(Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue)) {
        $letter = [string]$p.DriveLetter
        if ($letter -match '^[A-Za-z]$' -and $PSCmdlet.ShouldProcess("${letter}:", 'Remove drive letter')) {
            Remove-PartitionAccessPath -DiskNumber $DiskNumber -PartitionNumber $p.PartitionNumber -AccessPath "${letter}:\" -ErrorAction SilentlyContinue
        }
    }
}

function Get-FVVolumePath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int]$DiskNumber)
    for ($i = 0; $i -lt 20; $i++) {
        $parts = @(Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue | Where-Object { $_.GptType -eq $script:GptBasicData })
        foreach ($p in $parts) {
            foreach ($ap in @($p.AccessPaths)) {
                if ($ap -like '\\?\Volume{*}\') { return [string]$ap }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw [System.InvalidOperationException]::new('Vault volume not found on disk')
}

function Get-FVBdeVolume {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath)
    for ($i = 0; $i -lt 40; $i++) {
        $v = Get-CimInstance -Namespace $script:BdeNamespace -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue |
            Where-Object { $_.DeviceID -eq $VolumePath }
        if ($null -ne $v) { return $v }
        Start-Sleep -Milliseconds 250
    }
    throw [System.InvalidOperationException]::new('BitLocker provider does not see the vault volume')
}

function Invoke-FVBde {
    <# Calls a Win32_EncryptableVolume method and returns the result object (never throws on non-zero ReturnValue). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][string]$Method, [hashtable]$Arguments = @{})
    $v = Get-FVBdeVolume -VolumePath $VolumePath
    return (Invoke-CimMethod -InputObject $v -MethodName $Method -Arguments $Arguments -ErrorAction Stop)
}

function Invoke-FVMountvol {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$MountPath, [string]$VolumePath, [switch]$Remove)
    $mp = $MountPath.TrimEnd('\') + '\'
    if (-not $PSCmdlet.ShouldProcess($mp, 'mountvol')) { return }
    $mv = "$env:SystemRoot\System32\mountvol.exe"
    if ($Remove) { $r = Invoke-FVNative -FilePath $mv -ArgumentList @($mp, '/D') }
    else { $r = Invoke-FVNative -FilePath $mv -ArgumentList @($mp, $VolumePath) }
    if ($r.ExitCode -ne 0) { throw [System.InvalidOperationException]::new("mountvol failed ($($r.ExitCode)): " + $r.Text) }
}

function Test-FVMounted {
    <# True when $MountPath is currently a volume mount point. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$MountPath)
    if (-not (Test-Path -LiteralPath $MountPath)) { return $false }
    $di = New-Object System.IO.DirectoryInfo($MountPath)
    return (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Set-FVSecurity {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sddl)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Set ACL')) { return }
    $ds = New-Object System.Security.AccessControl.DirectorySecurity
    $ds.SetSecurityDescriptorSddlForm($Sddl)
    $di = New-Object System.IO.DirectoryInfo($Path)
    $di.SetAccessControl($ds)
}

# The root folder of a mounted volume cannot be given permissions through its
# mount point folder: Windows applies them to the mount point folder itself and
# leaves the volume's own root as Format made it (Microsoft KB 237701 and
# 832234). The vault's root is therefore set through the volume's own path
# (\\?\Volume{GUID}\), with SetFileSecurity, and read back to check (A-33).
$script:FVVolumeAclSource = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace FolderVault {
  public static class VolumeAcl {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out uint size);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint revision, uint info, out IntPtr sddl, out uint length);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetFileSecurityW(string fileName, uint info, IntPtr sd);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetFileSecurityW(string fileName, uint info, IntPtr sd, uint length, out uint needed);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr p);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFileAttributesW(string fileName);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetFileAttributesW(string fileName, uint attributes);
    // Adds attribute bits (for example FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, 0x2000) to a file or folder.
    public static void AddAttributes(string path, uint add) {
      uint a = GetFileAttributesW(path);
      if (a == 0xFFFFFFFF) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
      if (!SetFileAttributesW(path, a | add)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
    // OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    const uint Info = 0x7;
    public static void Set(string path, string sddl) {
      IntPtr sd; uint size;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
      try {
        if (!SetFileSecurityW(path, Info, sd)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
      } finally { LocalFree(sd); }
    }
    public static string Get(string path) {
      uint needed;
      GetFileSecurityW(path, Info, IntPtr.Zero, 0, out needed);
      if (needed == 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
      IntPtr buf = Marshal.AllocHGlobal((int)needed);
      try {
        if (!GetFileSecurityW(path, Info, buf, needed, out needed)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
        IntPtr text; uint length;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(buf, 1, Info, out text, out length)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
        try { return Marshal.PtrToStringUni(text); } finally { LocalFree(text); }
      } finally { Marshal.FreeHGlobal(buf); }
    }
  }
}
"@

function Get-FVAceSet {
    <# The access entries of an SDDL string, upper case, sorted and without repeats, for comparing two descriptors. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Sddl)
    $d = $Sddl.IndexOf('D:')
    if ($d -lt 0) { return @() }
    $dacl = $Sddl.Substring($d)
    $s = $dacl.IndexOf('S:')
    if ($s -gt 0) { $dacl = $dacl.Substring(0, $s) }
    return @([regex]::Matches($dacl, '\([^)]*\)') | ForEach-Object { $_.Value.ToUpperInvariant() } | Sort-Object -Unique)
}

function Test-FVSddlMatches {
    <# True when $Actual has a protected DACL with exactly the access entries of $Expected. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Actual, [Parameter(Mandatory)][string]$Expected)
    if ($Actual -notmatch 'D:P') { return $false }
    $a = @(Get-FVAceSet -Sddl $Actual); $e = @(Get-FVAceSet -Sddl $Expected)
    if ($a.Count -ne $e.Count) { return $false }
    for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -ne $e[$i]) { return $false } }
    return $true
}

function Set-FVVolumeRootSecurity {
    <#
        Sets the permissions of a volume's root folder through the volume's own
        path (\\?\Volume{GUID}\), then reads them back and throws if they are
        not exactly what was asked for.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][string]$Sddl)
    if (-not $PSCmdlet.ShouldProcess($VolumePath, 'Set root ACL')) { return }
    if (-not ('FolderVault.VolumeAcl' -as [type])) { Add-Type -TypeDefinition $script:FVVolumeAclSource -ErrorAction Stop }
    $root = $VolumePath.TrimEnd('\') + '\'
    $t = 'FolderVault.VolumeAcl' -as [type]
    $t::Set($root, $Sddl)
    $got = $t::Get($root)
    if (-not (Test-FVSddlMatches -Actual $got -Expected $Sddl)) {
        throw [System.InvalidOperationException]::new("The vault's root permissions did not apply (wanted $Sddl, found $got)")
    }
    Set-FVVolumeRootNotIndexed -VolumePath $VolumePath
}

function Set-FVVolumeRootNotIndexed {
    <#
        Keeps Windows Search out of the vault by marking its root "not content
        indexed" (0x2000), through the volume's own path. Done when a vault is
        made and every time it is unlocked, because copying files in can clear it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$VolumePath)
    if (-not $PSCmdlet.ShouldProcess($VolumePath, 'Set NotContentIndexed')) { return }
    if (-not ('FolderVault.VolumeAcl' -as [type])) { Add-Type -TypeDefinition $script:FVVolumeAclSource -ErrorAction Stop }
    ('FolderVault.VolumeAcl' -as [type])::AddAttributes($VolumePath.TrimEnd('\') + '\', [uint32]8192)
}

function Set-FVNotIndexed {
    <# Asks Windows Search not to index the vault contents. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Set NotContentIndexed')) { return }
    $di = New-Object System.IO.DirectoryInfo($Path)
    $di.Attributes = $di.Attributes -bor [System.IO.FileAttributes]::NotContentIndexed
}

function New-FVPrivateDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path, [string]$Sddl = $script:SddlPrivate)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create directory')) { return }
    if (-not (Test-Path -LiteralPath $Path)) { [System.IO.Directory]::CreateDirectory($Path) | Out-Null }
    Set-FVSecurity -Path $Path -Sddl $Sddl
}

function Test-FVEscrowCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CertPath)
    if (-not (Test-Path -LiteralPath $CertPath)) { return [pscustomobject]@{ Ok = $false; Reason = 'Missing' } }
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    } catch { return [pscustomobject]@{ Ok = $false; Reason = 'Unreadable' } }
    if ($cert.HasPrivateKey) { return [pscustomobject]@{ Ok = $false; Reason = 'ContainsPrivateKey' } }
    if ($cert.NotAfter -lt [datetime]::Now -or $cert.NotBefore -gt [datetime]::Now) { return [pscustomobject]@{ Ok = $false; Reason = 'Expired' } }
    $eku = $false
    foreach ($ext in $cert.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($o in $ext.EnhancedKeyUsages) { if ($o.Value -eq $script:EkuDocumentEncryption) { $eku = $true } }
        }
    }
    if (-not $eku) { return [pscustomobject]@{ Ok = $false; Reason = 'WrongKeyUsage' } }
    $rsa = $cert.PublicKey.Key
    if ($null -eq $rsa -or $rsa.KeySize -lt 2048) { return [pscustomobject]@{ Ok = $false; Reason = 'WeakKey' } }
    return [pscustomobject]@{ Ok = $true; Reason = 'Ok'; Thumbprint = $cert.Thumbprint }
}

function Protect-FVRecoveryKey {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$RecoveryKey,
        [Parameter(Mandatory)][string]$CertPath,
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][hashtable]$Metadata
    )
    if (-not $PSCmdlet.ShouldProcess($OutFile, 'Escrow recovery key')) { return }
    $payload = [ordered]@{}
    foreach ($k in $Metadata.Keys) { $payload[$k] = $Metadata[$k] }
    $payload['recoveryKey'] = $RecoveryKey
    $json = ConvertTo-Json -InputObject $payload -Compress
    $tmp = "$OutFile.tmp"
    Protect-CmsMessage -To $CertPath -Content $json -OutFile $tmp -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $tmp) -or (Get-Item -LiteralPath $tmp).Length -lt 100) { throw [System.InvalidOperationException]::new('Escrow file not written') }
    Move-Item -LiteralPath $tmp -Destination $OutFile -Force
}

# ---------------------------------------------------------------------------
# "Double-click to unlock" shortcut shown inside a locked folder
# ---------------------------------------------------------------------------
function New-FVUnlockShortcut {
    <#
        Places the unlock shortcut in the vault's (unmounted, empty) mount folder.
        The user's folder link points there, so a locked folder shows one item:
        "Locked - double-click here to unlock". Its target is fixed: the
        installed Folder Vault window and the vault's GUID, nothing user-supplied.
        Best effort: returns $false instead of throwing.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$Paths)
    try {
        $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
        if (-not (Test-Path -LiteralPath $f.Mount) -or (Test-FVMounted -MountPath $f.Mount)) { return $false }
        if (Test-Path -LiteralPath $f.Shortcut) { return $true }
        if (-not $PSCmdlet.ShouldProcess($f.Shortcut, 'Create unlock shortcut')) { return $false }
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $ui = Join-FVPath $Paths.InstallDir 'FolderVault.UI.ps1'
        $wsh = New-Object -ComObject WScript.Shell
        $lnk = $wsh.CreateShortcut($f.Shortcut)
        $lnk.TargetPath = $ps
        $lnk.Arguments = '-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "' + $ui + '" -Action Unlock -Id ' + $Record.Id.ToLowerInvariant()
        $lnk.IconLocation = "$env:SystemRoot\System32\shell32.dll,47"
        $lnk.WindowStyle = 7
        $lnk.Description = 'Unlock this folder with Folder Vault'
        $lnk.Save()
        if ($Record.Scope -eq 'Shared') { $sid = 'BU' } else { $sid = $Record.OwnerSid }
        $fs = New-Object System.Security.AccessControl.FileSecurity
        $fs.SetSecurityDescriptorSddlForm(('O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{0})' -f $sid))
        (New-Object System.IO.FileInfo($f.Shortcut)).SetAccessControl($fs)
        return $true
    } catch {
        Write-Verbose "unlock shortcut not created: $($_.Exception.Message)"
        return $false
    }
}

function Remove-FVUnlockShortcut {
    <# Removes the unlock shortcut so the mount folder is empty again (a volume can only be mounted on an empty folder). #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Files)
    if ((Test-Path -LiteralPath $Files.Shortcut) -and $PSCmdlet.ShouldProcess($Files.Shortcut, 'Remove unlock shortcut')) {
        [System.IO.File]::Delete($Files.Shortcut)
    }
}

# ---------------------------------------------------------------------------
# BitLocker helpers
# ---------------------------------------------------------------------------
function Get-FVLockStatus {
    <# Returns 'Unlocked' or 'Locked'. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath)
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'GetLockStatus'
    if ([uint32]$r.ReturnValue -ne 0) { throw [System.InvalidOperationException]::new('GetLockStatus failed') }
    if ([int]$r.LockStatus -eq 0) { return 'Unlocked' }
    return 'Locked'
}

function Unlock-FVBdeWithPassword {
    <# Returns 'Ok', 'BadPassword' or 'Error'. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][string]$Password)
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'UnlockWithPassphrase' -Arguments @{ Passphrase = $Password }
    $rv = [uint32]$r.ReturnValue
    if ($rv -eq 0) { return 'Ok' }
    if ($rv -eq $script:FVE_E_FAILED_AUTHENTICATION) { return 'BadPassword' }
    return 'Error'
}

function Unlock-FVBdeWithRecovery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][string]$RecoveryKey)
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'UnlockWithNumericalPassword' -Arguments @{ NumericalPassword = $RecoveryKey }
    $rv = [uint32]$r.ReturnValue
    if ($rv -eq 0) { return 'Ok' }
    if ($rv -eq $script:FVE_E_FAILED_AUTHENTICATION) { return 'BadRecoveryKey' }
    return 'Error'
}

function Lock-FVBde {
    <# Returns 'Ok' or 'FilesInUse' / 'Error'. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath, [bool]$Force = $false)
    if ((Get-FVLockStatus -VolumePath $VolumePath) -eq 'Locked') { return 'Ok' }
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'Lock' -Arguments @{ ForceDismount = $Force }
    $rv = [uint32]$r.ReturnValue
    if ($rv -eq 0) { return 'Ok' }
    # Documented: E_ACCESS_DENIED (0x80070005) = "Applications are accessing this volume".
    if ($rv -eq $script:E_ACCESS_DENIED -and -not $Force) { return 'FilesInUse' }
    return 'Error'
}

function Get-FVProtectorIds {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][uint32]$Type)
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'GetKeyProtectors' -Arguments @{ KeyProtectorType = $Type }
    if ([uint32]$r.ReturnValue -ne 0) { throw [System.InvalidOperationException]::new('GetKeyProtectors failed') }
    return @($r.VolumeKeyProtectorID | Where-Object { $_ })
}

function Add-FVPassphraseProtector {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][string]$Password)
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'ProtectKeyWithPassphrase' -Arguments @{ FriendlyName = 'Folder Vault password'; Passphrase = $Password }
    if ([uint32]$r.ReturnValue -ne 0) { throw [System.InvalidOperationException]::new(('ProtectKeyWithPassphrase failed 0x{0:X8}' -f [uint32]$r.ReturnValue)) }
    return [string]$r.VolumeKeyProtectorID
}

function Add-FVRecoveryProtector {
    <# Adds a generated 48-digit recovery password and returns @{ Id; Key }. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath)
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'ProtectKeyWithNumericalPassword' -Arguments @{ FriendlyName = 'Folder Vault recovery' }
    if ([uint32]$r.ReturnValue -ne 0) { throw [System.InvalidOperationException]::new(('ProtectKeyWithNumericalPassword failed 0x{0:X8}' -f [uint32]$r.ReturnValue)) }
    $id = [string]$r.VolumeKeyProtectorID
    $k = Invoke-FVBde -VolumePath $VolumePath -Method 'GetKeyProtectorNumericalPassword' -Arguments @{ VolumeKeyProtectorID = $id }
    if ([uint32]$k.ReturnValue -ne 0) { throw [System.InvalidOperationException]::new('GetKeyProtectorNumericalPassword failed') }
    return [pscustomobject]@{ Id = $id; Key = [string]$k.NumericalPassword }
}

function Remove-FVProtector {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][string]$ProtectorId)
    if (-not $PSCmdlet.ShouldProcess($ProtectorId, 'Delete key protector')) { return }
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'DeleteKeyProtector' -Arguments @{ VolumeKeyProtectorID = $ProtectorId }
    if ([uint32]$r.ReturnValue -ne 0) { throw [System.InvalidOperationException]::new('DeleteKeyProtector failed') }
}

function Start-FVBdeEncryption {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VolumePath, [int]$Method = 7, [int]$TimeoutSeconds = 900)
    # EncryptionFlags 1 = used space only: safe here because the volume was formatted moments ago and holds no data.
    $r = Invoke-FVBde -VolumePath $VolumePath -Method 'Encrypt' -Arguments @{ EncryptionMethod = [uint32]$Method; EncryptionFlags = [uint32]1 }
    if ([uint32]$r.ReturnValue -ne 0) { throw [System.InvalidOperationException]::new(('Encrypt failed 0x{0:X8}' -f [uint32]$r.ReturnValue)) }
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([datetime]::UtcNow -lt $deadline) {
        $s = Invoke-FVBde -VolumePath $VolumePath -Method 'GetConversionStatus' -Arguments @{ PrecisionFactor = [uint32]0 }
        if ([uint32]$s.ReturnValue -eq 0 -and [int]$s.ConversionStatus -eq 1) { return }
        Start-Sleep -Milliseconds 500
    }
    throw [System.TimeoutException]::new('Encryption did not complete in time')
}

# ---------------------------------------------------------------------------
# Vault operations
# ---------------------------------------------------------------------------
function New-FolderVaultContainer {
    <#
        Creates the encrypted container for a new vault and leaves it UNLOCKED and
        mounted at <DataDir>\Mounts\{id}, ready for the user's session to copy
        their files in. Any failure rolls back completely.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)][string]$ComputerName
    )
    if (-not $PSCmdlet.ShouldProcess($Record.Id, 'Create vault container')) { return }
    $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
    $stage = 'Escrow'
    $created = $false
    try {
        $esc = Test-FVEscrowCertificate -CertPath $Paths.EscrowCert
        if (-not $esc.Ok) { return (New-FVEngineResult -Ok $false -Code 'EscrowMissing' -Stage $stage -Detail $esc.Reason) }
        if (Test-Path -LiteralPath $f.Vhdx) { return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage $stage -Detail 'VHDX exists') }

        $stage = 'CreateVhdx'
        Invoke-FVDiskpartCreate -VhdxPath $f.Vhdx -SizeGB $Record.SizeGB -ScratchDir $Paths.VaultDir
        $created = $true

        $stage = 'Attach'
        $disk = Mount-FVVhd -VhdxPath $f.Vhdx

        $stage = 'Format'
        $vol = Initialize-FolderVaultDisk -DiskNumber $disk -VhdxPath $f.Vhdx

        $stage = 'Protectors'
        [void](Add-FVPassphraseProtector -VolumePath $vol -Password $Password)
        $rec = Add-FVRecoveryProtector -VolumePath $vol

        $stage = 'EscrowWrite'
        Protect-FVRecoveryKey -RecoveryKey $rec.Key -CertPath $Paths.EscrowCert -OutFile $f.Escrow -Metadata @{
            vaultId = $Record.Id; computer = $ComputerName; name = $Record.Name; folder = $Record.FolderPath
            ownerSid = $Record.OwnerSid; protectorId = $rec.Id; createdUtc = $Record.CreatedUtc
        }
        $rec = $null

        $stage = 'Encrypt'
        Start-FVBdeEncryption -VolumePath $vol -Method $Config.EncryptionMethod

        $stage = 'Mount'
        if ($Record.Scope -eq 'Shared') { $sid = 'BU' } else { $sid = $Record.OwnerSid }
        New-FVPrivateDirectory -Path $f.Mount -Sddl ($script:SddlMountPlaceholderFmt -f $sid)
        Invoke-FVMountvol -MountPath $f.Mount -VolumePath $vol

        $stage = 'RootAcl'
        if ($Record.Scope -eq 'Shared') { $rootSddl = $script:SddlVolumeRootShared }
        else { $rootSddl = $script:SddlVolumeRootProfileFmt -f $Record.OwnerSid }
        # Through the volume's own path, never the mount point folder (A-33).
        Set-FVVolumeRootSecurity -VolumePath $vol -Sddl $rootSddl

        return (New-FVEngineResult -Ok $true -Code 'Ok' -Stage 'Done' -Data ([pscustomobject]@{ MountPath = $f.Mount }))
    } catch {
        $detail = "$stage : $($_.Exception.Message)"
        if ($created) { Remove-FolderVaultArtifacts -Files $f }
        else { Remove-Item -LiteralPath $f.Escrow -Force -ErrorAction SilentlyContinue }
        return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage $stage -Detail $detail)
    }
}

function Remove-FolderVaultArtifacts {
    <# Best-effort removal of a vault's container, escrow file and mount point. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Files)
    if (-not $PSCmdlet.ShouldProcess($Files.Vhdx, 'Remove vault artifacts')) { return }
    try { if (Test-FVMounted -MountPath $Files.Mount) { Invoke-FVMountvol -MountPath $Files.Mount -Remove } } catch { Write-Verbose $_.Exception.Message }
    try { Dismount-FVVhd -VhdxPath $Files.Vhdx } catch { Write-Verbose $_.Exception.Message }
    foreach ($p in @($Files.Vhdx, $Files.Escrow)) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
    try { Remove-FVUnlockShortcut -Files $Files } catch { Write-Verbose $_.Exception.Message }
    try {
        if ((Test-Path -LiteralPath $Files.Mount) -and -not (Test-FVMounted -MountPath $Files.Mount)) {
            [System.IO.Directory]::Delete($Files.Mount, $false)
        }
    } catch { Write-Verbose "mount folder not removed: $($_.Exception.Message)" }
}

function Get-FolderVaultRuntime {
    <# Attached / Unlocked / Mounted state of a vault, from Windows (not from the registry). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$Paths)
    $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
    $exists = Test-Path -LiteralPath $f.Vhdx
    $attached = $false; $unlocked = $false; $mounted = $false
    if ($exists) {
        $attached = Test-FVVhdAttached -VhdxPath $f.Vhdx
        $mounted = Test-FVMounted -MountPath $f.Mount
        if ($attached) {
            try {
                $disk = Mount-FVVhd -VhdxPath $f.Vhdx
                $vol = Get-FVVolumePath -DiskNumber $disk
                $unlocked = ((Get-FVLockStatus -VolumePath $vol) -eq 'Unlocked')
            } catch { $unlocked = $false }
        }
    }
    return [pscustomobject]@{ Exists = $exists; Attached = $attached; Unlocked = $unlocked; Mounted = $mounted; MountPath = $f.Mount }
}

function Open-FolderVaultContainer {
    <# Attach + unlock with the vault password + mount. Bad password leaves it detached. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Password, [Parameter(Mandatory)]$Paths)
    $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
    if (-not (Test-Path -LiteralPath $f.Vhdx)) { return (New-FVEngineResult -Ok $false -Code 'NeedsAttention' -Stage 'Exists' -Detail 'VHDX missing') }
    $wasAttached = Test-FVVhdAttached -VhdxPath $f.Vhdx
    $stage = 'Attach'
    try {
        $disk = Mount-FVVhd -VhdxPath $f.Vhdx
        $vol = Get-FVVolumePath -DiskNumber $disk
        $stage = 'Unlock'
        if ((Get-FVLockStatus -VolumePath $vol) -eq 'Locked') {
            $u = Unlock-FVBdeWithPassword -VolumePath $vol -Password $Password
            if ($u -ne 'Ok') {
                if (-not $wasAttached) { Dismount-FVVhd -VhdxPath $f.Vhdx }
                if ($u -eq 'BadPassword') { return (New-FVEngineResult -Ok $false -Code 'BadPassword' -Stage $stage) }
                return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage $stage -Detail 'unlock failed')
            }
        } else {
            return (New-FVEngineResult -Ok $false -Code 'AlreadyUnlocked' -Stage $stage)
        }
        $stage = 'Mount'
        if (-not (Test-Path -LiteralPath $f.Mount)) {
            $sid = $Record.OwnerSid
            if ($Record.Scope -eq 'Shared') { $sid = 'BU' }
            New-FVPrivateDirectory -Path $f.Mount -Sddl ($script:SddlMountPlaceholderFmt -f $sid)
        }
        if (-not (Test-FVMounted -MountPath $f.Mount)) {
            Remove-FVUnlockShortcut -Files $f
            Invoke-FVMountvol -MountPath $f.Mount -VolumePath $vol
        }
        # Best effort: a failure here must not stop the person opening their folder.
        try { Set-FVVolumeRootNotIndexed -VolumePath $vol } catch { Write-Verbose "not-indexed mark: $($_.Exception.Message)" }
        return (New-FVEngineResult -Ok $true -Code 'Ok' -Stage 'Done' -Data ([pscustomobject]@{ MountPath = $f.Mount }))
    } catch {
        $detail = "$stage : $($_.Exception.Message)"
        try { Close-FolderVaultContainer -Record $Record -Paths $Paths -Force $true | Out-Null } catch { Write-Verbose $_.Exception.Message }
        return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage $stage -Detail $detail)
    }
}

function Close-FolderVaultContainer {
    <#
        BitLocker-lock (purges the key from memory), remove the mount point, detach.
        Without -Force, open files make it fail cleanly with FilesInUse and nothing changes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$Paths, [bool]$Force = $false)
    $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
    if (-not (Test-FVVhdAttached -VhdxPath $f.Vhdx)) {
        if (Test-FVMounted -MountPath $f.Mount) { Invoke-FVMountvol -MountPath $f.Mount -Remove }
        [void](New-FVUnlockShortcut -Record $Record -Paths $Paths)
        return (New-FVEngineResult -Ok $true -Code 'AlreadyLocked' -Stage 'Done')
    }
    $stage = 'Lock'
    try {
        $disk = Mount-FVVhd -VhdxPath $f.Vhdx
        $vol = Get-FVVolumePath -DiskNumber $disk
        $l = Lock-FVBde -VolumePath $vol -Force $Force
        if ($l -eq 'FilesInUse') { return (New-FVEngineResult -Ok $false -Code 'FilesInUse' -Stage $stage) }
        if ($l -ne 'Ok') { return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage $stage -Detail 'BitLocker lock failed') }
        $stage = 'Unmount'
        if (Test-FVMounted -MountPath $f.Mount) { Invoke-FVMountvol -MountPath $f.Mount -Remove }
        $stage = 'Detach'
        Dismount-FVVhd -VhdxPath $f.Vhdx
        [void](New-FVUnlockShortcut -Record $Record -Paths $Paths)
        return (New-FVEngineResult -Ok $true -Code 'Ok' -Stage 'Done')
    } catch {
        return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage $stage -Detail $_.Exception.Message)
    }
}

function Confirm-FolderVaultPassword {
    <#
        Proves knowledge of the password with a fresh BitLocker unlock.
        The vault must be locked (detached) when called; it is left attached and
        unlocked (no mount point) on success, detached on failure.
        Returns result with Data = volume path.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [string]$Password, [string]$RecoveryKey, [Parameter(Mandatory)]$Paths)
    $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
    if (-not (Test-Path -LiteralPath $f.Vhdx)) { return (New-FVEngineResult -Ok $false -Code 'NeedsAttention' -Stage 'Exists') }
    if (Test-FVVhdAttached -VhdxPath $f.Vhdx) { return (New-FVEngineResult -Ok $false -Code 'NotLocked' -Stage 'State') }
    try {
        $disk = Mount-FVVhd -VhdxPath $f.Vhdx
        $vol = Get-FVVolumePath -DiskNumber $disk
        if ($PSBoundParameters.ContainsKey('RecoveryKey')) { $u = Unlock-FVBdeWithRecovery -VolumePath $vol -RecoveryKey $RecoveryKey }
        else { $u = Unlock-FVBdeWithPassword -VolumePath $vol -Password $Password }
        if ($u -ne 'Ok') {
            Dismount-FVVhd -VhdxPath $f.Vhdx
            if ($u -eq 'Error') { return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage 'Unlock') }
            return (New-FVEngineResult -Ok $false -Code $u -Stage 'Unlock')
        }
        return (New-FVEngineResult -Ok $true -Code 'Ok' -Stage 'Unlock' -Data $vol)
    } catch {
        try { Dismount-FVVhd -VhdxPath $f.Vhdx } catch { Write-Verbose $_.Exception.Message }
        return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage 'Unlock' -Detail $_.Exception.Message)
    }
}

function Set-FolderVaultPasswordCore {
    <#
        Changes the vault password. The new passphrase protector is added BEFORE
        the old ones are deleted, so a failure can never leave the vault without
        a password. Leaves the vault locked.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Record,
        [string]$OldPassword,
        [string]$RecoveryKey,
        [Parameter(Mandatory)][string]$NewPassword,
        [Parameter(Mandatory)]$Paths,
        [string]$ComputerName = $env:COMPUTERNAME
    )
    if (-not $PSCmdlet.ShouldProcess($Record.Id, 'Change vault password')) { return }
    $useRecovery = $PSBoundParameters.ContainsKey('RecoveryKey')
    if ($useRecovery) { $c = Confirm-FolderVaultPassword -Record $Record -RecoveryKey $RecoveryKey -Paths $Paths }
    else { $c = Confirm-FolderVaultPassword -Record $Record -Password $OldPassword -Paths $Paths }
    if (-not $c.Ok) { return $c }
    $vol = [string]$c.Data
    $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
    $stage = 'AddProtector'
    try {
        $old = @(Get-FVProtectorIds -VolumePath $vol -Type $script:ProtectorPassphrase)
        $newId = Add-FVPassphraseProtector -VolumePath $vol -Password $NewPassword
        $stage = 'DeleteOld'
        foreach ($id in $old) { if ($id -ne $newId) { Remove-FVProtector -VolumePath $vol -ProtectorId $id } }

        if ($useRecovery) {
            # The recovery key has now been seen by a person: rotate it.
            $stage = 'RotateRecovery'
            $oldRec = @(Get-FVProtectorIds -VolumePath $vol -Type $script:ProtectorNumerical)
            $rec = Add-FVRecoveryProtector -VolumePath $vol
            Protect-FVRecoveryKey -RecoveryKey $rec.Key -CertPath $Paths.EscrowCert -OutFile $f.Escrow -Metadata @{
                vaultId = $Record.Id; computer = $ComputerName; name = $Record.Name; folder = $Record.FolderPath
                ownerSid = $Record.OwnerSid; protectorId = $rec.Id; createdUtc = $Record.CreatedUtc; rotatedUtc = ([datetime]::UtcNow.ToString('o'))
            }
            $rec = $null
            foreach ($id in $oldRec) { Remove-FVProtector -VolumePath $vol -ProtectorId $id }
        }
        $stage = 'Lock'
        [void](Lock-FVBde -VolumePath $vol -Force $true)
        Dismount-FVVhd -VhdxPath $f.Vhdx
        return (New-FVEngineResult -Ok $true -Code 'Ok' -Stage 'Done')
    } catch {
        $detail = "$stage : $($_.Exception.Message)"
        try { [void](Lock-FVBde -VolumePath $vol -Force $true); Dismount-FVVhd -VhdxPath $f.Vhdx } catch { Write-Verbose $_.Exception.Message }
        return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage $stage -Detail $detail)
    }
}

function Remove-FolderVaultContainer {
    <#
        Deletes a vault after proving the password. The user's session has already
        copied the files out and verified them before calling this.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Password, [Parameter(Mandatory)]$Paths)
    if (-not $PSCmdlet.ShouldProcess($Record.Id, 'Delete vault')) { return }
    $c = Confirm-FolderVaultPassword -Record $Record -Password $Password -Paths $Paths
    if (-not $c.Ok) { return $c }
    $f = Get-FolderVaultFiles -Id $Record.Id -Paths $Paths
    try {
        [void](Lock-FVBde -VolumePath ([string]$c.Data) -Force $true)
        Remove-FolderVaultArtifacts -Files $f
        if (Test-Path -LiteralPath $f.Vhdx) { return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage 'Delete' -Detail 'VHDX still present') }
        return (New-FVEngineResult -Ok $true -Code 'Ok' -Stage 'Done')
    } catch {
        return (New-FVEngineResult -Ok $false -Code 'InternalError' -Stage 'Delete' -Detail $_.Exception.Message)
    }
}

function Get-FVProfilePath {
    <# Profile directory for a SID, from the machine's ProfileList (never from the client). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Sid)
    if ($Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { return $null }
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    try {
        $p = (Get-ItemProperty -LiteralPath $key -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
        return [System.Environment]::ExpandEnvironmentVariables([string]$p)
    } catch { return $null }
}

function Get-FVFreeBytes {
    [CmdletBinding()]
    [OutputType([long])]
    param([Parameter(Mandatory)][string]$Path)
    $drive = New-Object System.IO.DriveInfo($Path.Substring(0, 1))
    return [long]$drive.AvailableFreeSpace
}

function ConvertTo-FVSessionStates {
    <#
        Pure part of the session check, so it can be tested anywhere.
        $Explorers: objects with UserName ('PC\alice') and SessionId, one per signed-in desktop.
        $LockedSessionIds: session ids where LogonUI.exe is running (lock screen showing).
        $ResolveSid: scriptblock turning a user name into a SID string (or $null).
        Returns SID -> @{ Sessions; LockedSessions }.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Explorers = @(),
        [AllowEmptyCollection()][int[]]$LockedSessionIds = @(),
        [Parameter(Mandatory)][scriptblock]$ResolveSid
    )
    $result = @{}
    foreach ($p in $Explorers) {
        $name = [string]$p.UserName
        if ([string]::IsNullOrEmpty($name)) { continue }
        $sid = & $ResolveSid $name
        if ([string]::IsNullOrEmpty($sid)) { continue }
        if (-not $result.ContainsKey($sid)) { $result[$sid] = [pscustomobject]@{ Sessions = 0; LockedSessions = 0 } }
        $result[$sid].Sessions++
        if ($LockedSessionIds -contains [int]$p.SessionId) { $result[$sid].LockedSessions++ }
    }
    return $result
}

function Resolve-FVUserSid {
    <# User name -> SID, cached (the broker asks about the same few users all day). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$UserName)
    if ($script:SidCache.ContainsKey($UserName)) { return $script:SidCache[$UserName] }
    $sid = $null
    try { $sid = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null }
    if ($null -ne $sid) { $script:SidCache[$UserName] = $sid }
    return $sid
}

function Get-FVSessionStates {
    <#
        Which users are signed in, and whose screens are locked.
        Uses Get-Process -IncludeUserName (one quick call; the broker runs as
        SYSTEM so it may see owners). Falls back to the slower WMI method only
        if that fails. Only called while at least one vault is unlocked.
    #>
    [CmdletBinding()]
    param()
    try {
        $procs = @(Get-Process -Name 'explorer', 'LogonUI' -IncludeUserName -ErrorAction SilentlyContinue)
        $explorers = @($procs | Where-Object { $_.ProcessName -eq 'explorer' })
        $locked = @($procs | Where-Object { $_.ProcessName -eq 'LogonUI' } | ForEach-Object { [int]$_.SessionId })
        return (ConvertTo-FVSessionStates -Explorers $explorers -LockedSessionIds $locked -ResolveSid { param($n) Resolve-FVUserSid -UserName $n })
    } catch {
        Write-Verbose "fast session query failed, using WMI: $($_.Exception.Message)"
    }
    $result = @{}
    $logonUi = @{}
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='LogonUI.exe'" -ErrorAction SilentlyContinue)) { $logonUi[[int]$p.SessionId] = $true }
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
            $sid = [string]$o.Sid
        } catch { continue }
        if ([string]::IsNullOrEmpty($sid)) { continue }
        if (-not $result.ContainsKey($sid)) { $result[$sid] = [pscustomobject]@{ Sessions = 0; LockedSessions = 0 } }
        $result[$sid].Sessions++
        if ($logonUi.ContainsKey([int]$p.SessionId)) { $result[$sid].LockedSessions++ }
    }
    return $result
}

Export-ModuleMember -Function @(
    'Get-FolderVaultFiles', 'Invoke-FVDiskpartCreate', 'Mount-FVVhd', 'Assert-FolderVaultDisk', 'Test-FVDiskIsBlank', 'Remove-FVDriveLetters', 'Dismount-FVVhd', 'Test-FVVhdAttached',
    'Initialize-FolderVaultDisk', 'Get-FVVolumePath', 'Get-FVBdeVolume', 'Invoke-FVBde', 'Invoke-FVMountvol', 'Test-FVMounted',
    'Set-FVSecurity', 'Set-FVVolumeRootSecurity', 'Set-FVVolumeRootNotIndexed', 'Test-FVSddlMatches', 'Get-FVAceSet', 'Set-FVNotIndexed', 'New-FVPrivateDirectory', 'Test-FVEscrowCertificate', 'Protect-FVRecoveryKey',
    'Get-FVLockStatus', 'Unlock-FVBdeWithPassword', 'Unlock-FVBdeWithRecovery', 'Lock-FVBde',
    'Get-FVProtectorIds', 'Add-FVPassphraseProtector', 'Add-FVRecoveryProtector', 'Remove-FVProtector', 'Start-FVBdeEncryption',
    'New-FolderVaultContainer', 'Remove-FolderVaultArtifacts', 'Get-FolderVaultRuntime', 'Open-FolderVaultContainer', 'Close-FolderVaultContainer',
    'Confirm-FolderVaultPassword', 'Set-FolderVaultPasswordCore', 'Remove-FolderVaultContainer',
    'Get-FVProfilePath', 'Get-FVFreeBytes', 'Get-FVSessionStates', 'ConvertTo-FVSessionStates', 'Resolve-FVUserSid',
    'New-FVUnlockShortcut', 'Remove-FVUnlockShortcut'
)
