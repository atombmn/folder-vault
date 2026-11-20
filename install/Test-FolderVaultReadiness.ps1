#Requires -Version 5.1
<#
.SYNOPSIS
    Checks whether this PC is ready for Folder Vault. Changes nothing.

.DESCRIPTION
    Double-click Check-ThisPC.cmd in the Folder Vault folder, or run this script.
    It asks for administrator permission (needed to read the BitLocker status),
    then lists what is fine and what needs doing, in plain words.
    Exit code: 0 ready, 1 something blocks installation.
#>
[CmdletBinding()]
param([switch]$NoPause)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'FolderVault.Setup.psm1') -Force

if (-not (Test-FVElevated)) {
    $a = @(); if ($NoPause) { $a += '-NoPause' }
    if (Start-FVElevated -ScriptPath $PSCommandPath -Arguments $a) { exit 0 }
    if (-not $NoPause) { Wait-FVKey }
    exit 1
}

Write-FVTitle "Is this PC ready for Folder Vault? ($env:COMPUTERNAME)"
$checks = @(Get-FVReadiness)
Write-FVReadiness -Checks $checks
$cer = @(Find-FVEscrowCertificate -PackageRoot (Split-Path -Parent $PSScriptRoot))
if ($cer.Count -eq 1) { Write-FVOk "Recovery certificate found: $($cer[0].Name)" }
elseif ($cer.Count -eq 0) { Write-FVWarn 'No recovery certificate (.cer file) in the Folder Vault folder.' 'Ask the IT team for the client''s recovery certificate and put it next to Install.cmd before installing.' }
else { Write-FVWarn "More than one recovery certificate in the folder ($($cer.Name -join ', '))." 'Keep only the one for this client.' }

$blocked = @($checks | Where-Object Status -eq 'PROBLEM').Count -gt 0
Write-Host ''
if ($blocked) { Write-Host '  Folder Vault cannot be installed on this PC until the PROBLEM items are fixed.' -ForegroundColor Red }
else { Write-Host '  This PC can run Folder Vault. Fix any CHECK items first if you can, then double-click Install.cmd.' -ForegroundColor Green }
if (-not $NoPause) { Wait-FVKey }
if ($blocked) { exit 1 }
exit 0
