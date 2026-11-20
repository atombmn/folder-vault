<#
    Downloads what Test-FVNetFrameworkApi.ps1 needs, from nuget.org, into
    tests/.refs (ignored by git):

      Microsoft.NETFramework.ReferenceAssemblies.net48 1.0.3
          the .NET Framework 4.8 reference assemblies (what Windows PowerShell 5.1 runs on)
      System.Reflection.MetadataLoadContext 8.0.0
          reads those assemblies without loading them

    Usage: pwsh -File tests/tools/Get-FVReferenceAssemblies.ps1
    Then:  Invoke-Pester ./tests/unit   (NetFrameworkApi.Tests.ps1 finds them)
#>
[CmdletBinding()]
param([string]$Destination = (Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) '.refs'))
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$packages = @(
    @{ Id = 'microsoft.netframework.referenceassemblies.net48'; Version = '1.0.3'; Folder = 'net48' }
    @{ Id = 'system.reflection.metadataloadcontext'; Version = '8.0.0'; Folder = 'mlc' }
)
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
foreach ($p in $packages) {
    $dir = Join-Path $Destination $p.Folder
    if (Test-Path $dir) { Write-Host "Already there: $dir"; continue }
    $nupkg = Join-Path $Destination "$($p.Folder).zip"
    $url = "https://api.nuget.org/v3-flatcontainer/$($p.Id)/$($p.Version)/$($p.Id).$($p.Version).nupkg"
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $nupkg -UseBasicParsing
    Expand-Archive -LiteralPath $nupkg -DestinationPath $dir
    Remove-Item -LiteralPath $nupkg
}
[pscustomobject]@{
    RefDir = Join-Path $Destination 'net48/build/.NETFramework/v4.8'
    MlcDll = Join-Path $Destination 'mlc/lib/net8.0/System.Reflection.MetadataLoadContext.dll'
}
