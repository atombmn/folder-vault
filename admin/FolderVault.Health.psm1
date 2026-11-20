#Requires -Version 5.1
<#
    Folder Vault - decision logic for Get-FolderVaultHealth.ps1, kept separate so it
    can be unit-tested.
#>

Set-StrictMode -Version 3.0

# Test-FVGrantsWrite lives in src\FolderVault.Common.psm1, shared with the installer.

function Compare-FVSignInItems {
    <#
        Compares a user's current sign-in programs with the recorded baseline.
        Items are strings such as "Run: OneDrive = C:\...\OneDrive.exe /background".
        A changed command shows as one removed and one added item.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$Current = @(),
        [AllowEmptyCollection()][string[]]$Baseline = @()
    )
    $added = @($Current | Where-Object { $Baseline -notcontains $_ })
    $removed = @($Baseline | Where-Object { $Current -notcontains $_ })
    return [pscustomobject]@{ Added = $added; Removed = $removed }
}

function Get-FVSignInVerdict {
    <#
        Turns one user's findings into a health-check line.
        $Baseline = $null means this user has no baseline yet.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$Current = @(),
        [AllowNull()][string[]]$Baseline,
        [AllowEmptyCollection()][string[]]$Overrides = @(),
        [string]$BaselineDate = ''
    )
    if ($Overrides.Count -gt 0) {
        return [pscustomobject]@{ Status = 'FAIL'; Detail = ('Folder Vault menu item replaced for this user (possible password phishing): ' + ($Overrides -join ', ')); Record = $false }
    }
    if ($null -eq $Baseline) {
        return [pscustomobject]@{ Status = 'INFO'; Detail = "baseline recorded: $($Current.Count) program(s) start at sign-in. Later checks warn only about new ones."; Record = $true }
    }
    $c = Compare-FVSignInItems -Current $Current -Baseline $Baseline
    if (@($c.Added).Count -gt 0) {
        $names = @($c.Added | ForEach-Object { ($_ -split ' = ', 2)[0] })
        return [pscustomobject]@{ Status = 'WARN'; Detail = ("new since $BaselineDate" + ': ' + ($names -join '; ') + '. Check each one; if all are expected, run with -ResetBaseline.'); Record = $false }
    }
    return [pscustomobject]@{ Status = 'PASS'; Detail = "no new sign-in programs since $BaselineDate ($($Current.Count) known)"; Record = $false }
}

function Get-FVCpuText {
    <# Plain description of CPU use: a live sample if there is one, plus the average since start. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([double]$SamplePercent = -1, [double]$AveragePercent, [double]$Minutes)
    $t = ''
    if ($SamplePercent -ge 0) { $t = ('{0:N2}% CPU now (10-second sample); ' -f $SamplePercent) }
    $t += ('{0:N2}% average over {1:N0} minute(s) since it started' -f $AveragePercent, $Minutes)
    if ($Minutes -lt 15) { $t += ', which still includes start-up' }
    return $t
}

# Event IDs the report counts, with plain names. Keys are strings on purpose:
# an [ordered] table with number keys treats $t[1003] as "item number 1003",
# not "the key 1003", and throws (bug in 0.2.3).
$script:EventNames = [ordered]@{
    '1003' = 'automatic locks'; '1010' = 'wrong passwords'; '1011' = 'lock-outs'; '1012' = 'attempts refused while locked out'
    '1040' = 'refused protect requests'; '1050' = 'refused admin requests'; '1051' = 'passwords reset by IT'
    '1060' = 'rejected callers'; '1061' = 'malformed requests'; '1062' = 'invalid requests'; '1900' = 'internal errors'; '1930' = 'failed service starts'
}
# Any of these happening at all deserves a look.
$script:EventWarnIds = @('1011', '1050', '1060', '1061', '1062', '1900', '1930')

function Test-FVRegistryKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)
    return (Test-Path -LiteralPath $Path)
}

function Get-FVUserRegistryItems {
    <#
        Reads one person's registry (already open under $HiveRoot): what their
        Run key starts at sign-in, and whether Folder Vault's right-click items have
        been replaced for them.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HiveRoot)
    $items = @(); $overrides = @()
    $run = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path -LiteralPath $run) {
        $key = Get-Item -LiteralPath $run
        try { foreach ($n in @($key.Property)) { $items += ('Run: {0} = {1}' -f $n, [string]$key.GetValue($n)) } }
        finally { $key.Close() }
    }
    foreach ($verb in @('FolderVault.Protect', 'FolderVault.Unlock', 'FolderVault.Lock')) {
        if (Test-Path -LiteralPath "$HiveRoot\Software\Classes\Directory\shell\$verb") { $overrides += $verb }
    }
    return [pscustomobject]@{ Items = $items; Overrides = $overrides }
}

function Get-FVShortcutTarget {
    <# What a .lnk file starts (program and arguments), or '' if it cannot be read. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $l = (New-Object -ComObject WScript.Shell).CreateShortcut($Path)
        return ([string]$l.TargetPath + ' ' + [string]$l.Arguments).Trim()
    } catch { return '' }
}

function Mount-FVUserHive {
    <# Opens a signed-out person's registry (NTUSER.DAT) under HKEY_USERS\<Name>. Returns $true on success. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$HiveFile)
    $r = Invoke-FVNative -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList @('load', "HKU\$Name", $HiveFile)
    return ($r.ExitCode -eq 0)
}

function Dismount-FVUserHive {
    <#
        Closes a registry opened by Mount-FVUserHive and returns $true once it is
        really closed. A registry left open stops that person signing in
        normally (Windows gives them a temporary profile), so this retries
        while PowerShell lets go of its handles, and checks (audit fix A-29).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name, [int]$Attempts = 5, [int]$WaitMs = 1000)
    for ($i = 0; $i -lt $Attempts; $i++) {
        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
        $null = Invoke-FVNative -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList @('unload', "HKU\$Name")
        if (-not (Test-FVRegistryKey -Path "Registry::HKEY_USERS\$Name")) { return $true }
        Start-Sleep -Milliseconds $WaitMs
    }
    return $false
}

function Get-FVEventSummary {
    <#
        One line per event type: how many in the period, and whether that is a warning.
        $Events: anything with an Id property (Get-WinEvent output, or test objects).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Events = @(), [int]$Days = 30)
    $counts = @{}
    foreach ($e in $Events) {
        if ($null -eq $e) { continue }
        $k = [string]$e.Id
        if ($counts.ContainsKey($k)) { $counts[$k]++ } else { $counts[$k] = 1 }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $script:EventNames.GetEnumerator()) {
        $id = [string]$entry.Key
        $n = 0
        if ($counts.ContainsKey($id)) { $n = [int]$counts[$id] }
        $status = 'INFO'
        if ($n -gt 0 -and $script:EventWarnIds -contains $id) { $status = 'WARN' }
        $out.Add([pscustomobject]@{ Check = "Events: $($entry.Value)"; Status = $status; Detail = "$n in the last $Days days" })
    }
    return $out.ToArray()
}

Export-ModuleMember -Function @('Compare-FVSignInItems', 'Get-FVSignInVerdict', 'Get-FVCpuText', 'Get-FVEventSummary', 'Mount-FVUserHive', 'Dismount-FVUserHive',
    'Test-FVRegistryKey', 'Get-FVUserRegistryItems', 'Get-FVShortcutTarget')
