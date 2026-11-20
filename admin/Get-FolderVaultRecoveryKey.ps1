#Requires -Version 5.1
<#
.SYNOPSIS
    Decrypts a vault's escrowed recovery key with the IT team's offline private key.

.DESCRIPTION
    Copy the vault's .cms file from the client PC
    (C:\ProgramData\FolderVault\Escrow\<vault id>.cms, admin access needed), then
    run this on the IT admin machine that has the escrow PFX. The certificate
    is imported only for the duration of this script, as non-exportable, and
    removed afterwards.

    Use the 48-digit key with Reset-FolderVaultPassword.ps1 on the client PC. The IT team
    Vault rotates the recovery key after it has been used.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EscrowFile,
    [Parameter(Mandatory)][string]$PfxPath
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$pw = Read-Host 'PFX password' -AsSecureString
$imported = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $pw
try {
    $json = Unprotect-CmsMessage -Path $EscrowFile
    $info = ConvertFrom-Json $json
    Write-Host ''
    Write-Host "Vault       : $($info.name)  ($($info.vaultId))"
    Write-Host "Computer    : $($info.computer)"
    Write-Host "Folder      : $($info.folder)"
    Write-Host "Recovery key: $($info.recoveryKey)" -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Do not email or message this key. Read it out or type it in yourself.'
} finally {
    foreach ($c in @($imported)) { Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $c.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue }
}
