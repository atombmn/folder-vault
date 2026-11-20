<#
    Runs tests/tools/Test-FVNetFrameworkApi.ps1 over every script: each .NET
    type, method, constructor and XAML member must exist in .NET Framework 4.8.
    Skipped unless the reference assemblies are in tests/.refs
    (get them with tests/tools/Get-FVReferenceAssemblies.ps1).
#>
BeforeDiscovery {
    $refs = Join-Path $PSScriptRoot '../.refs'
    $script:haveRefs = (Test-Path (Join-Path $refs 'net48/build/.NETFramework/v4.8/mscorlib.dll')) -and
        (Test-Path (Join-Path $refs 'mlc/lib/net8.0/System.Reflection.MetadataLoadContext.dll')) -and
        ($PSVersionTable.PSVersion.Major -ge 7 -and $PSVersionTable.PSVersion.Minor -ge 4)
}

Describe '.NET Framework 4.8 API check' -Skip:(-not $haveRefs) {
    It 'finds no problems apart from the two known false positives' {
        $root = Join-Path $PSScriptRoot '../..'
        $refs = Join-Path $PSScriptRoot '../.refs'
        $files = @(Get-ChildItem -Recurse -Include *.ps1, *.psm1 -Path (Join-Path $root 'src'), (Join-Path $root 'install'), (Join-Path $root 'admin'), (Join-Path $root 'build') | ForEach-Object FullName)
        $out = @(& pwsh -NoProfile -Command {
                param($r, $m, $f, $tool) & $tool -RefDir $r -MlcDll $m -Path $f | ForEach-Object { "$($_.File):$($_.Problem)" }
            } -args (Join-Path $refs 'net48/build/.NETFramework/v4.8'), (Join-Path $refs 'mlc/lib/net8.0/System.Reflection.MetadataLoadContext.dll'), $files, (Join-Path $root 'tests/tools/Test-FVNetFrameworkApi.ps1'))
        # Known false positives, each checked by hand:
        #  - a variable enum name: [System.Diagnostics.EventLogEntryType]::$level
        #  - New-Object byte[] n: an array, not a constructor call
        $known = @(
            'FolderVault.Broker.ps1:[System.Diagnostics.EventLogEntryType]::$level : no such static property, field or enum value'
            'FolderVault.Common.psm1:New-Object byte[] with 1 argument(s): no such constructor'
        )
        @($out | Where-Object { $known -notcontains $_ }) | Should -BeNullOrEmpty
    }
}
