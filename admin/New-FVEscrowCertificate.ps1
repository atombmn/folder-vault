#Requires -Version 5.1
<#
.SYNOPSIS
    Creates the IT team's recovery (escrow) key pair. Run ONCE per client, on an IT admin
    machine, NOT on the client's PCs.

.DESCRIPTION
    Produces:
      <Name>.cer  public key  -> install on every client PC (Install-FolderVault -EscrowCertificate)
      <Name>.pfx  private key -> keep offline (encrypted USB in the IT team's safe + a second copy).
                                 Anyone with this file and its password can open every
                                 vault for this client.
    The private key is removed from this machine's certificate store afterwards.

.EXAMPLE
    .\New-FVEscrowCertificate.ps1 -ClientName 'Acme Ltd' -OutputDirectory E:\Escrow
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClientName,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [int]$Years = 10
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$safe = ($ClientName -replace '[^A-Za-z0-9\-]', '-').Trim('-')
if (-not (Test-Path -LiteralPath $OutputDirectory)) { [void](New-Item -ItemType Directory -Path $OutputDirectory) }
$cer = Join-Path $OutputDirectory "FolderVault-Escrow-$safe.cer"
$pfx = Join-Path $OutputDirectory "FolderVault-Escrow-$safe.pfx"
if ((Test-Path $cer) -or (Test-Path $pfx)) { throw "Files already exist in $OutputDirectory. Refusing to overwrite an escrow key." }

Write-Host 'Choose a strong password for the PFX (private key). Store it separately from the PFX file.' -ForegroundColor Yellow
$p1 = Read-Host 'PFX password' -AsSecureString
$p2 = Read-Host 'Repeat' -AsSecureString
$b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1); $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
try {
    $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1); $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
    if ($s1 -cne $s2) { throw 'Passwords do not match.' }
    if ($s1.Length -lt 16) { throw 'Use at least 16 characters for the PFX password.' }
} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1); [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2); $s1 = $null; $s2 = $null }

$cert = New-SelfSignedCertificate -Type DocumentEncryptionCert -Subject "CN=Folder Vault Escrow - $ClientName, O=Folder Vault" `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddYears($Years)
try {
    Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $p1 -CryptoAlgorithmOption AES256_SHA256 | Out-Null
} finally {
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
}
Write-Host "Public key  : $cer   (install on client PCs)" -ForegroundColor Green
Write-Host "Private key : $pfx   (keep OFFLINE)" -ForegroundColor Green
Write-Host "Thumbprint  : $($cert.Thumbprint)"
