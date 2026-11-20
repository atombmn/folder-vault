#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets a new password on a vault whose password was forgotten, using its recovery key.

.DESCRIPTION
    Run elevated on the client PC. Needs BOTH local administrator rights AND the
    vault's recovery key (from Get-FolderVaultRecoveryKey.ps1 on the IT admin machine).
    The recovery key is rotated afterwards, so the one you used stops working.
#>
[CmdletBinding()]
param([string]$VaultName)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$dir = 'C:\Program Files\FolderVault'
Import-Module (Join-Path $dir 'FolderVault.Common.psm1') -Force
Import-Module (Join-Path $dir 'FolderVault.Client.psm1') -Force

$list = Invoke-FVBroker -Request @{ op = 'AdminList' }
if (-not $list.ok) { throw "Broker refused: $($list.message)" }
$vaults = @($list.data.vaults)
if ($VaultName) { $vaults = @($vaults | Where-Object { $_.name -eq $VaultName }) }
if ($vaults.Count -eq 0) { throw 'No matching vaults.' }
for ($i = 0; $i -lt $vaults.Count; $i++) { Write-Host ("[{0}] {1,-25} {2,-10} {3}" -f $i, $vaults[$i].name, $vaults[$i].state, $vaults[$i].folderPath) }
$pick = 0
if ($vaults.Count -gt 1) { $pick = [int](Read-Host 'Number of the vault to reset') }
$v = $vaults[$pick]
Write-Host "Vault id: $($v.id)  (escrow file C:\ProgramData\FolderVault\Escrow\$($v.id).cms)"

function Read-Plain { param([string]$Prompt)
    $s = Read-Host $Prompt -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
$key = (Read-Plain 'Recovery key (48 digits, with dashes)').Trim()
$p1 = Read-Plain 'New vault password'
$p2 = Read-Plain 'Repeat new password'
if ($p1 -cne $p2) { throw 'Passwords do not match.' }

$r = Invoke-FVBroker -Request @{ op = 'AdminReset'; id = $v.id; recoveryKey = $key; newPassword = $p1 } -ResponseTimeoutMs 300000
$key = $null; $p1 = $null; $p2 = $null
if ($r.ok) { Write-Host 'Password reset. The recovery key has been rotated. Give the new password to the user in person.' -ForegroundColor Green }
else {
    $extra = ''
    if ($r.code -eq 'PasswordPolicy') { $extra = ' (' + (@($r.data.problems) -join ', ') + ')' }
    Write-Host "Failed: $($r.message)$extra" -ForegroundColor Red
}
