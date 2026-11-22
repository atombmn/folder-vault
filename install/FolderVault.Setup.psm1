#Requires -Version 5.1
<#
    Folder Vault - shared set-up helpers for Install, Uninstall and Check-ThisPC.

    Everything a person sees during set-up is written here in plain English,
    so the three tools speak the same way.
#>

Set-StrictMode -Version 3.0

# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------
function Test-FVElevated {
    [OutputType([bool])]
    param()
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-FVElevated {
    <#
        Re-runs a script with administrator rights (Windows shows its usual
        "Do you want to allow this app to make changes?" prompt).
        Returns $true if the elevated copy was started.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$ScriptPath, [string[]]$Arguments = @())
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $ScriptPath + '"')) + $Arguments
    try {
        Start-Process -FilePath $ps -ArgumentList $a -Verb RunAs | Out-Null
        return $true
    } catch {
        Write-FVProblem 'Windows did not give Folder Vault permission to make changes.' 'Run it again and click Yes when Windows asks. You need an administrator account (the IT account).'
        return $false
    }
}

# ---------------------------------------------------------------------------
# Plain-English output
# ---------------------------------------------------------------------------
function Write-FVTitle {
    param([string]$Text)
    Write-Host ''
    Write-Host ('  ' + $Text) -ForegroundColor White
    Write-Host ('  ' + ('-' * $Text.Length)) -ForegroundColor DarkGray
    Write-Host ''
}

function Write-FVStep {
    param([int]$Number, [int]$Total, [string]$Text)
    Write-Host ("  Step {0} of {1}: {2}" -f $Number, $Total, $Text) -ForegroundColor Cyan
}

function Write-FVOk { param([string]$Text) Write-Host "    [OK]      $Text" -ForegroundColor Green }
function Write-FVNote { param([string]$Text) Write-Host "    [NOTE]    $Text" -ForegroundColor Gray }

function Write-FVWarn {
    param([string]$Text, [string]$Fix)
    Write-Host "    [CHECK]   $Text" -ForegroundColor Yellow
    if ($Fix) { Write-Host "              What to do: $Fix" -ForegroundColor Yellow }
}

function Write-FVProblem {
    param([string]$Text, [string]$Fix)
    Write-Host "    [PROBLEM] $Text" -ForegroundColor Red
    if ($Fix) { Write-Host "              What to do: $Fix" -ForegroundColor Red }
}

function Wait-FVKey {
    param([string]$Text = 'Press Enter to close this window')
    Write-Host ''
    [void](Read-Host "  $Text")
}

function Read-FVYes {
    [OutputType([bool])]
    param([string]$Question)
    $a = Read-Host "  $Question (type Y for yes, N for no)"
    return ($a -match '^\s*(y|yes)\s*$')
}

# ---------------------------------------------------------------------------
# Readiness checks (used by Check-ThisPC and by the installer)
# ---------------------------------------------------------------------------
function New-FVCheck {
    param([string]$Name, [ValidateSet('OK', 'CHECK', 'PROBLEM', 'NOTE')][string]$Status, [string]$Text, [string]$Fix = '')
    return [pscustomobject]@{ Name = $Name; Status = $Status; Text = $Text; Fix = $Fix }
}

function Get-FVReadiness {
    <#
        Looks at this PC and says, in plain words, whether Folder Vault can be
        installed. Changes nothing. PROBLEM items block installation; CHECK
        items should be fixed but do not block.
    #>
    [CmdletBinding()]
    param()
    $out = New-Object System.Collections.Generic.List[object]

    $os = Get-CimInstance Win32_OperatingSystem
    $caption = [string]$os.Caption
    if ($caption -match 'Home') {
        $out.Add((New-FVCheck 'Edition' 'PROBLEM' "$caption cannot use Folder Vault." 'Folder Vault needs Windows Pro, Enterprise or Education. Upgrade this PC to Pro (Settings > System > Activation) or protect its folders another way.'))
    } else {
        $out.Add((New-FVCheck 'Edition' 'OK' "$caption"))
    }
    if ([int]$os.BuildNumber -lt 22000) {
        $out.Add((New-FVCheck 'Updates' 'NOTE' 'This is Windows 10. It only gets security updates if it is enrolled in Extended Security Updates (ESU).' 'Confirm the ESU licence is active, and plan the move to Windows 11.'))
    }

    $bdeOk = $true
    try { [void](Get-CimClass -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop) }
    catch { $bdeOk = $false }
    if (-not $bdeOk) {
        $out.Add((New-FVCheck 'BitLocker' 'PROBLEM' 'BitLocker is not available on this PC.' 'Check the Windows edition. Run this check from an administrator account.'))
    } else {
        $svc = Get-Service -Name BDESVC -ErrorAction SilentlyContinue
        if ($null -eq $svc -or [string]$svc.StartType -eq 'Disabled') {
            $out.Add((New-FVCheck 'BitLocker' 'PROBLEM' 'The BitLocker service is switched off.' 'Open Services, find "BitLocker Drive Encryption Service" and set it to Manual.'))
        } else {
            $out.Add((New-FVCheck 'BitLocker' 'OK' 'BitLocker is available.'))
        }
        $sys = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='C:'" -ErrorAction SilentlyContinue
        $prot = $false
        if ($null -ne $sys) { $prot = ([int](Invoke-CimMethod -InputObject $sys -MethodName GetProtectionStatus).ProtectionStatus -eq 1) }
        if ($prot) { $out.Add((New-FVCheck 'Drive C:' 'OK' 'Drive C: is encrypted with BitLocker.')) }
        else {
            $out.Add((New-FVCheck 'Drive C:' 'CHECK' 'Drive C: is not encrypted. Copies of files deleted when a folder is protected could be recovered by someone who takes the disk.' 'Turn on BitLocker for drive C: (Control Panel > BitLocker Drive Encryption) and keep its recovery key safe. Then install.'))
        }
        # From 0.3.0 folders on other fixed drives can be protected too; the same applies to them.
        $others = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.Name.Substring(0, 1) -ne 'C' } | ForEach-Object { $_.Name.Substring(0, 2) })
        $open = New-Object System.Collections.Generic.List[string]
        foreach ($d in $others) {
            $v = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$d'" -ErrorAction SilentlyContinue
            $on = $false
            if ($null -ne $v) { $on = ([int](Invoke-CimMethod -InputObject $v -MethodName GetProtectionStatus).ProtectionStatus -eq 1) }
            if (-not $on) { $open.Add($d) }
        }
        if ($open.Count -gt 0) {
            $out.Add((New-FVCheck 'Other drives' 'CHECK' "Not encrypted: $($open -join ', '). If staff protect folders on these drives, deleted copies of their files could be recovered from the disk." 'Turn on BitLocker for these drives too, or tell staff to keep protected folders on drive C:.'))
        }
    }

    $free = (New-Object System.IO.DriveInfo('C')).AvailableFreeSpace
    if ($free -lt 5GB) { $out.Add((New-FVCheck 'Space' 'CHECK' ("Only {0:N1} GB free on drive C:." -f ($free / 1GB)) 'Free some space. Protecting a folder briefly needs about twice its size.')) }
    else { $out.Add((New-FVCheck 'Space' 'OK' ("{0:N0} GB free on drive C:." -f ($free / 1GB)))) }

    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ([string]$_.Name) })
        $names = ($admins | ForEach-Object { $_.Substring($_.LastIndexOf('\') + 1) }) -join ', '
        $out.Add((New-FVCheck 'Administrators' 'CHECK' "These accounts are administrators: $names" 'Make sure only IT accounts are on this list. Staff accounts should be standard users, or they can get round any protection.'))
    } catch {
        $out.Add((New-FVCheck 'Administrators' 'NOTE' 'Could not list the administrator accounts.'))
    }
    return $out.ToArray()
}

function Write-FVReadiness {
    param([object[]]$Checks)
    foreach ($c in $Checks) {
        switch ($c.Status) {
            'OK' { Write-FVOk $c.Text }
            'NOTE' { Write-FVNote $c.Text; if ($c.Fix) { Write-Host "              $($c.Fix)" -ForegroundColor Gray } }
            'CHECK' { Write-FVWarn $c.Text $c.Fix }
            'PROBLEM' { Write-FVProblem $c.Text $c.Fix }
        }
    }
}

function Find-FVEscrowCertificate {
    <#
        Finds the client's recovery certificate next to Install.cmd, so nobody
        has to type a path. Looks in the package folder and an "escrow" folder in it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageRoot)
    $found = @()
    foreach ($d in @($PackageRoot, (Join-Path $PackageRoot 'escrow'))) {
        if (Test-Path -LiteralPath $d) { $found += @(Get-ChildItem -LiteralPath $d -Filter '*.cer' -File -ErrorAction SilentlyContinue) }
    }
    return @($found | Sort-Object FullName -Unique)
}

# ---------------------------------------------------------------------------
# Package checks (audit fix A-22): is the copy we are installing from the released package?
# ---------------------------------------------------------------------------
$script:TrustedWriterSids = @(
    'S-1-5-18',                                                       # SYSTEM
    'S-1-5-32-544',                                                   # Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', # TrustedInstaller
    'S-1-3-0'                                                         # CREATOR OWNER (applies only to the item's owner, checked separately)
)

function Read-FVChecksumFile {
    <# Reads SHA256SUMS.txt ("HASH  relative\path" per line) into a hashtable keyed by path, case-insensitive. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $map = @{}   # case-insensitive keys, like Windows paths
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $t = $line.Trim([char]0xFEFF, ' ', "`t")
        if ($t -match '^([0-9A-Fa-f]{64})\s+(.+)$') { $map[$Matches[2].Trim()] = $Matches[1].ToUpperInvariant() }
    }
    return $map
}

function Test-FVPackageIntegrity {
    <#
        Compares the files under $Root with the fingerprints the IT team recorded when it
        built the package. Only the parts the installer uses are checked
        ($Subtrees, plus any listed top-level file named in $TopFiles).
        Unlisted means a script or command file that is not part of the release.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][hashtable]$Expected,
        [string[]]$Subtrees = @('src', 'install'),
        [string[]]$TopFiles = @('Install.cmd', 'Uninstall.cmd')
    )
    $root = $Root.TrimEnd('\', '/')
    $missing = New-Object System.Collections.Generic.List[string]
    $modified = New-Object System.Collections.Generic.List[string]
    $unlisted = New-Object System.Collections.Generic.List[string]
    $wanted = @($Expected.Keys | Where-Object {
        $k = $_
        ($TopFiles -contains $k) -or @($Subtrees | Where-Object { $k.StartsWith("$_\", [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    } | Sort-Object)
    foreach ($rel in $wanted) {
        $f = Join-Path $root ($rel.Replace('\', [System.IO.Path]::DirectorySeparatorChar))
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { $missing.Add($rel); continue }
        if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $Expected[$rel]) { $modified.Add($rel) }
    }
    foreach ($sub in $Subtrees) {
        $d = Join-Path $root $sub
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Force)) {
            $rel = $sub + '\' + $f.FullName.Substring($d.Length + 1).Replace('/', '\')
            if (-not $Expected.ContainsKey($rel) -and $f.Extension -match '^\.(ps1|psm1|psd1|cmd|bat|dll|exe|vbs|js)$') { $unlisted.Add($rel) }
        }
    }
    return [pscustomobject]@{
        Ok = ($missing.Count -eq 0 -and $modified.Count -eq 0 -and $unlisted.Count -eq 0)
        Checked = $wanted.Count; Missing = @($missing); Modified = @($modified); Unlisted = @($unlisted)
    }
}

function Get-FVPackageFingerprint {
    <# The first 16 characters of SHA256SUMS.txt's own fingerprint, in groups of four, for reading out over the phone. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$ChecksumFile)
    $h = (Get-FileHash -LiteralPath $ChecksumFile -Algorithm SHA256).Hash
    return (($h.Substring(0, 16) -split '(.{4})' | Where-Object { $_ }) -join ' ')
}

function Get-FVUntrustedWriter {
    <#
        Pure decision: given an item's owner and access rules, lists the people
        other than SYSTEM, Administrators, TrustedInstaller and the given admin
        accounts who could change it. Rules are objects with Sid, Rights (number),
        Allow (bool) and InheritOnly (bool). Inherit-only rules do not apply to
        the item itself, so they are skipped. An untrusted owner can always
        change the permissions, so it counts as a writer.
    #>
    [CmdletBinding()]
    param(
        [string]$OwnerSid,
        [AllowEmptyCollection()][object[]]$Rules = @(),
        [AllowEmptyCollection()][string[]]$AdminSids = @()
    )
    $ok = @($script:TrustedWriterSids) + @($AdminSids)
    $out = New-Object System.Collections.Generic.List[string]
    if ($OwnerSid -and $ok -notcontains $OwnerSid) { $out.Add("owner $OwnerSid") }
    foreach ($r in $Rules) {
        if (-not [bool]$r.Allow -or [bool]$r.InheritOnly) { continue }
        if ($ok -contains [string]$r.Sid) { continue }
        if (Test-FVGrantsWrite -Rights ([long]$r.Rights)) { $out.Add([string]$r.Sid) }
    }
    return @($out | Select-Object -Unique)
}

function Get-FVLocalAdminSids {
    <# SIDs of the accounts in the local Administrators group (empty if they cannot be read). #>
    [CmdletBinding()]
    param()
    try { return @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.SID.Value }) } catch { Write-Verbose "Get-LocalGroupMember failed: $($_.Exception.Message)" }
    # Get-LocalGroupMember fails when the group holds a deleted account; ask the older interface instead.
    try {
        $name = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g = [ADSI]('WinNT://./' + $name + ',group')
        return @(@($g.Invoke('Members')) | ForEach-Object {
            $b = [byte[]]$_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
            (New-Object System.Security.Principal.SecurityIdentifier($b, 0)).Value })
    } catch { return @() }
}

function Get-FVPackageWriters {
    <#
        Lists who, apart from administrators, could have changed the package
        folder, its src and install folders, or any file in them. Returns
        readable names, one per person or group.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageRoot)
    $admins = @(Get-FVLocalAdminSids)
    $items = @((Get-Item -LiteralPath $PackageRoot -Force))
    foreach ($sub in @('src', 'install')) {
        $d = Join-Path $PackageRoot $sub
        if (Test-Path -LiteralPath $d) { $items += Get-Item -LiteralPath $d -Force; $items += @(Get-ChildItem -LiteralPath $d -Recurse -Force) }
    }
    $items += @(Get-ChildItem -LiteralPath $PackageRoot -File -Force | Where-Object { $_.Extension -in @('.cmd', '.txt', '.cer') })
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($i in $items) {
        $acl = Get-Acl -LiteralPath $i.FullName
        $owner = $acl.GetOwner($sidType).Value
        $rules = @($acl.GetAccessRules($true, $true, $sidType) | ForEach-Object {
            [pscustomobject]@{ Sid = $_.IdentityReference.Value; Rights = [long]$_.FileSystemRights; Allow = ($_.AccessControlType -eq 'Allow')
                InheritOnly = (($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) } })
        foreach ($w in @(Get-FVUntrustedWriter -OwnerSid $owner -Rules $rules -AdminSids $admins)) {
            $sid = $w -replace '^owner ', ''
            $n = $sid
            try { $n = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { Write-Verbose "No name for $sid" }
            if (-not $names.Contains($n)) { $names.Add($n) }
        }
    }
    return @($names)
}

function Stop-FVProcesses {
    <#
        Ends the Windows PowerShell processes whose command line matches any of
        $CommandLineLike (except this one) and waits for them to go. A process
        that ends by itself in the meantime is not an error: Stop-ScheduledTask
        ends the background service while this runs (fix for 0.4.1, seen on the
        first update). Returns the ids of any that are still running.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string[]]$CommandLineLike,
        [int]$ExceptProcessId = $PID,
        [int]$WaitSeconds = 10
    )
    $found = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
            $cl = [string]$_.CommandLine
            ([int]$_.ProcessId -ne $ExceptProcessId) -and (@($CommandLineLike | Where-Object { $cl -like $_ }).Count -gt 0)
        } | ForEach-Object { [int]$_.ProcessId })
    foreach ($id in $found) {
        if (-not $PSCmdlet.ShouldProcess("process $id", 'Stop')) { continue }
        try { Stop-Process -Id $id -Force -ErrorAction Stop }
        catch { Write-Verbose "Process ${id}: $($_.Exception.Message)" }   # usually: it has already ended
    }
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        $left = @($found | Where-Object { $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue) })
        if ($left.Count -eq 0) { return @() }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    return $left
}

$script:FVInactivityKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

function Test-FVScreenLockSetByUs {
    <#
        Pure decision: was this machine inactivity limit (InactivityTimeoutSecs,
        in seconds) set by a Folder Vault installer? From 0.4.5 the install
        record says so (screenLockMinutesSet). Earlier installers did not record
        it, but always set it, to a whole number of minutes from 1 to 60
        (10 by default), so for those records any such value counts.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$Value, [AllowNull()]$Manifest)
    if ($null -eq $Value -or $null -eq $Manifest) { return $false }
    $v = [long]$Value
    if ($null -ne $Manifest.PSObject.Properties['screenLockMinutesSet']) {
        $m = [long]$Manifest.screenLockMinutesSet
        return ($m -gt 0 -and $v -eq ($m * 60))
    }
    return ($v -ge 60 -and $v -le 3600 -and ($v % 60) -eq 0)
}

function Reset-FVScreenLock {
    <#
        Puts the screen lock back to Windows' own setting (no machine inactivity
        limit) if a Folder Vault installer set it. Returns a sentence saying
        what was done, or $null when nothing was changed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([AllowNull()]$Manifest)
    $v = $null
    try { $v = (Get-ItemProperty -Path $script:FVInactivityKey -Name 'InactivityTimeoutSecs' -ErrorAction Stop).InactivityTimeoutSecs } catch { return $null }
    if (-not (Test-FVScreenLockSetByUs -Value $v -Manifest $Manifest)) { return $null }
    if (-not $PSCmdlet.ShouldProcess('InactivityTimeoutSecs', 'Remove')) { return $null }
    Remove-ItemProperty -Path $script:FVInactivityKey -Name 'InactivityTimeoutSecs' -ErrorAction Stop
    return ("The screen lock time Folder Vault set ({0} minutes) was removed; Windows' own screen lock settings apply again." -f ([long]$v / 60))
}

function Read-FVInstallManifest {
    <# The install record (install-manifest.json) in $DataDir, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataDir)
    $p = Join-Path $DataDir 'install-manifest.json'
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { return (ConvertFrom-Json ([System.IO.File]::ReadAllText($p))) } catch { return $null }
}

function New-FVAdminOnlyFolder {
    <#
        Makes a new, empty folder under C:\Windows\Temp that only SYSTEM and
        Administrators can open, and returns its path. Used so the installer
        and uninstaller never run code from a folder staff could change.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Prefix, [string]$Parent = (Join-Path $env:SystemRoot 'Temp'))
    $ds = New-Object System.Security.AccessControl.DirectorySecurity
    $ds.SetSecurityDescriptorSddlForm('O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    for ($i = 0; $i -lt 5; $i++) {
        $p = Join-Path $Parent ($Prefix + [guid]::NewGuid().ToString('N'))
        if (Test-Path -LiteralPath $p) { continue }
        if (-not $PSCmdlet.ShouldProcess($p, 'Create folder')) { return $p }
        [void][System.IO.Directory]::CreateDirectory($p, $ds)
        # Apply again in case the folder appeared between the test and the create.
        [System.IO.Directory]::SetAccessControl($p, $ds)
        return $p
    }
    throw [System.InvalidOperationException]::new('Could not create a private folder for set-up')
}

function Remove-FVAdminOnlyFolder {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
    if ($PSCmdlet.ShouldProcess($Path, 'Remove folder')) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

Export-ModuleMember -Function @(
    'Test-FVElevated', 'Start-FVElevated', 'Write-FVTitle', 'Write-FVStep', 'Write-FVOk', 'Write-FVNote', 'Write-FVWarn', 'Write-FVProblem',
    'Wait-FVKey', 'Read-FVYes', 'Get-FVReadiness', 'Write-FVReadiness', 'Find-FVEscrowCertificate',
    'Read-FVChecksumFile', 'Test-FVPackageIntegrity', 'Get-FVPackageFingerprint', 'Get-FVUntrustedWriter', 'Get-FVLocalAdminSids',
    'Get-FVPackageWriters', 'Stop-FVProcesses', 'Test-FVScreenLockSetByUs', 'Reset-FVScreenLock', 'Read-FVInstallManifest', 'New-FVAdminOnlyFolder', 'Remove-FVAdminOnlyFolder'
)
