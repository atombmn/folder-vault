BeforeAll {
    $src = Join-Path $PSScriptRoot '..\..\src'
    Import-Module (Join-Path $src 'FolderVault.Common.psm1') -Force
    $script:cfg = (ConvertTo-FVConfig $null).Config
}

Describe 'Path normalisation (fails closed)' {
    It 'normalises a simple path' {
        (ConvertTo-FVNormalizedPath 'c:/Users/Alice/Documents/Finance/').Path | Should -Be 'C:\Users\Alice\Documents\Finance'
    }
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'empty'; P = '' }
        @{ Case = 'relative'; P = 'Users\Alice' }
        @{ Case = 'UNC'; P = '\\server\share\x' }
        @{ Case = 'device path'; P = '\\?\C:\Users\Alice' }
        @{ Case = 'dot-dot traversal'; P = 'C:\Users\Alice\..\Bob\Docs' }
        @{ Case = 'single dot'; P = 'C:\Users\.\Alice' }
        @{ Case = 'alternate data stream'; P = 'C:\Users\Alice\Docs:secret' }
        @{ Case = 'wildcard'; P = 'C:\Users\Alice\Do*' }
        @{ Case = 'trailing dot'; P = 'C:\Users\Alice\Docs.' }
        @{ Case = 'trailing space'; P = 'C:\Users\Alice\Docs ' }
        @{ Case = 'leading space'; P = ' C:\Users\Alice' }
        @{ Case = '8.3 short name'; P = 'C:\Users\ALICE~1\Docs' }
        @{ Case = 'reserved device'; P = 'C:\Users\Alice\CON' }
        @{ Case = 'reserved device with ext'; P = 'C:\Users\Alice\nul.txt' }
        @{ Case = 'double separator'; P = 'C:\Users\\Alice' }
        @{ Case = 'drive root'; P = 'C:\' }
        @{ Case = 'control char'; P = "C:\Users\Al`tice" }
        @{ Case = 'too long'; P = ('C:\' + ('a' * 250)) }
    ) {
        (ConvertTo-FVNormalizedPath $P).Ok | Should -BeFalse
    }
}

Describe 'Path containment' {
    It 'is strict about prefixes' {
        Test-FVPathUnder -Path 'C:\Users\Alicea\x' -Root 'C:\Users\Alice' | Should -BeFalse
        Test-FVPathUnder -Path 'C:\Users\Alice\x' -Root 'C:\Users\Alice' | Should -BeTrue
        Test-FVPathUnder -Path 'C:\Users\Alice' -Root 'C:\Users\Alice' | Should -BeFalse
        Test-FVPathUnder -Path 'c:\users\alice\X' -Root 'C:\Users\Alice' | Should -BeTrue
    }
}

Describe 'Who may protect which folder' {
    BeforeAll { $script:prof = 'C:\Users\Alice' }
    It 'allows a sub-folder of Documents' {
        (Get-FVPathScope -Path 'C:\Users\Alice\Documents\Payroll' -ProfilePath $prof).Scope | Should -Be 'Profile'
    }
    It 'allows a custom folder directly in the profile' {
        (Get-FVPathScope -Path 'C:\Users\Alice\Payroll' -ProfilePath $prof).Ok | Should -BeTrue
    }
    It 'refuses <Case>' -ForEach @(
        @{ Case = 'whole Documents'; P = 'C:\Users\Alice\Documents' }
        @{ Case = 'whole Desktop (any case)'; P = 'C:\Users\Alice\desktop' }
        @{ Case = 'AppData'; P = 'C:\Users\Alice\AppData\Local\Thing' }
        @{ Case = 'AppData deep'; P = 'C:\Users\Alice\Documents\x\AppData\y' }
        @{ Case = 'whole OneDrive'; P = 'C:\Users\Alice\OneDrive - Contoso' }
        @{ Case = 'whole OneDrive Documents'; P = 'C:\Users\Alice\OneDrive\Documents' }
        @{ Case = 'another user'; P = 'C:\Users\Bob\Documents\Secret' }
        @{ Case = 'Windows'; P = 'C:\Windows\System32\drivers' }
        @{ Case = 'Program Files'; P = 'C:\Program Files\FolderVault\x' }
        @{ Case = 'ProgramData'; P = 'C:\ProgramData\FolderVault\Vaults' }
        @{ Case = 'recycle bin on another drive'; P = 'D:\$Recycle.Bin\S-1-5-21-1\x' }
        @{ Case = 'System Volume Information on another drive'; P = 'D:\System Volume Information\x' }
        @{ Case = 'old Windows'; P = 'C:\Windows.old\Users\x' }
        @{ Case = 'AppData copied elsewhere'; P = 'D:\Backup\AppData\x' }
        @{ Case = 'the whole profile'; P = 'C:\Users\Alice' }
        @{ Case = 'Public folder shared by everyone'; P = 'C:\Users\Public\Documents\x' }
        @{ Case = 'hidden dot-folder at profile root'; P = 'C:\Users\Alice\.ssh' }
    ) {
        (Get-FVPathScope -Path $P -ProfilePath $prof).Ok | Should -BeFalse
    }
    It 'refuses everything when the profile is unknown' {
        (Get-FVPathScope -Path 'C:\Users\Alice\Documents\X' -ProfilePath $null).Ok | Should -BeFalse
    }
    It 'allows shared roots and reports Shared' {
        (Get-FVPathScope -Path 'D:\Shared\Finance' -ProfilePath $prof -SharedRoots @('D:\Shared')).Scope | Should -Be 'Shared'
    }
    It 'refuses shared roots when disabled' {
        (Get-FVPathScope -Path 'D:\Shared\Finance' -ProfilePath $prof -SharedRoots @('D:\Shared') -AllowShared $false).Ok | Should -BeFalse
    }
    It 'refuses the shared root itself' {
        (Get-FVPathScope -Path 'D:\Shared' -ProfilePath $prof -SharedRoots @('D:\Shared')).Ok | Should -BeFalse
    }
    It 'refuses extra blocked roots' {
        (Get-FVPathScope -Path 'D:\FV\x' -ProfilePath $prof -SharedRoots @('D:\') -ExtraBlockedRoots @('D:\FV')).Ok | Should -BeFalse
    }
}

Describe 'Shared root validation' {
    It 'rejects dangerous roots: <P>' -ForEach @(
        @{ P = 'C:\Windows' }, @{ P = 'C:\Users' }, @{ P = 'C:\Users\Public' }, @{ P = 'C:\ProgramData\X' }, @{ P = 'C:\' }
    ) {
        (Test-FVSharedRoot $P).Ok | Should -BeFalse
    }
    It 'accepts D:\Shared and C:\Shared' {
        (Test-FVSharedRoot 'D:\Shared').Ok | Should -BeTrue
        (Test-FVSharedRoot 'C:\Shared').Ok | Should -BeTrue
    }
    It 'config drops bad shared roots' {
        $c = ConvertTo-FVConfig ([pscustomobject]@{ SharedRoots = @('C:\Windows', 'D:\Team') })
        @($c.Config.SharedRoots) | Should -Be @('D:\Team')
        $c.Warnings.Count | Should -BeGreaterThan 0
    }
}

Describe 'Overlap detection' {
    It 'detects equal, nested and containing' {
        $e = @('C:\Users\A\Documents\Fin')
        Test-FolderVaultOverlap -Path 'C:\Users\A\Documents\Fin' -ExistingPaths $e | Should -BeTrue
        Test-FolderVaultOverlap -Path 'C:\Users\A\Documents\Fin\Q1' -ExistingPaths $e | Should -BeTrue
        Test-FolderVaultOverlap -Path 'C:\Users\A\Documents' -ExistingPaths $e | Should -BeTrue
        Test-FolderVaultOverlap -Path 'C:\Users\A\Documents\Finance' -ExistingPaths $e | Should -BeFalse
    }
}

Describe 'Password policy' {
    It 'accepts a passphrase' {
        (Test-FVPassword -Password 'Mangoes ripen in March 2027' -UserName 'PC\alice' -Config $cfg).Ok | Should -BeTrue
    }
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'too short'; P = 'Ab1!xyz'; Code = 'TooShort' }
        @{ Case = 'common word + digits'; P = 'Password2026!'; Code = 'Common' }
        @{ Case = 'product name'; P = 'FolderVault@2026'; Code = 'Common' }
        @{ Case = 'repetitive'; P = 'aaaaaaaaaaaaaaab'; Code = 'TooRepetitive' }
        @{ Case = 'sequential'; P = 'abcdefghijklm'; Code = 'Sequential' }
        @{ Case = 'username'; P = 'alice-loves-mangoes'; Code = 'ContainsUserName' }
        @{ Case = 'non-ascii'; P = 'Mangoes ripen in März 2027'; Code = 'InvalidCharacters' }
        @{ Case = 'leading space'; P = ' Mangoes ripen in March'; Code = 'EdgeWhitespace' }
        @{ Case = 'empty'; P = ''; Code = 'Empty' }
    ) {
        $r = Test-FVPassword -Password $P -UserName 'PC\alice' -Config $cfg
        $r.Ok | Should -BeFalse
        $r.Problems | Should -Contain $Code
    }
    It 'rejects over 256 characters' {
        (Test-FVPassword -Password ('Mango ripe ' * 30) -UserName 'x' -Config $cfg).Problems | Should -Contain 'TooLong'
    }
    It 'scores passphrases higher than short passwords' {
        Get-FVPasswordScore 'Mangoes ripen in March 2027' | Should -BeGreaterThan (Get-FVPasswordScore 'Ab1!')
    }
}

Describe 'Throttling and lockout' {
    BeforeAll { $script:now = [datetime]::new(2026, 10, 29, 12, 0, 0, [System.DateTimeKind]::Utc) }
    It 'allows first attempts' {
        (Get-FVThrottle -FailedCount 2 -LastFailureUtc $now -NowUtc $now -Config $cfg).Allowed | Should -BeTrue
    }
    It 'backs off after BackoffStartAfter failures' {
        $t = Get-FVThrottle -FailedCount 5 -LastFailureUtc (ConvertTo-FVIso $now) -NowUtc $now.AddSeconds(1) -Config $cfg
        $t.Allowed | Should -BeFalse
        $t.Code | Should -Be 'Throttled'
        (Get-FVThrottle -FailedCount 5 -LastFailureUtc (ConvertTo-FVIso $now) -NowUtc $now.AddSeconds(5) -Config $cfg).Allowed | Should -BeTrue
    }
    It 'caps the back-off at 60 seconds' {
        (Get-FVThrottle -FailedCount 50 -LastFailureUtc $now -NowUtc $now.AddSeconds(61) -Config $cfg).Allowed | Should -BeTrue
    }
    It 'locks out at MaxFailedAttempts and persists as ISO string' {
        $u = Get-FVFailureUpdate -FailedCount 9 -Success $false -NowUtc $now -Config $cfg
        $u.LockedOutNow | Should -BeTrue
        $u.LockoutUntilUtc | Should -BeOfType [string]
        $t = Get-FVThrottle -FailedCount $u.FailedCount -LastFailureUtc $u.LastFailureUtc -LockoutUntilUtc $u.LockoutUntilUtc -NowUtc $now.AddMinutes(14) -Config $cfg
        $t.Code | Should -Be 'LockedOut'
        (Get-FVThrottle -FailedCount $u.FailedCount -LastFailureUtc $u.LastFailureUtc -LockoutUntilUtc $u.LockoutUntilUtc -NowUtc $now.AddMinutes(16) -Config $cfg).Allowed | Should -BeTrue
    }
    It 'resets on success' {
        (Get-FVFailureUpdate -FailedCount 7 -Success $true -NowUtc $now -Config $cfg).FailedCount | Should -Be 0
    }
    It 'handles DateTime values (PowerShell 7 JSON auto-conversion)' {
        (Get-FVThrottle -FailedCount 10 -LockoutUntilUtc $now.AddMinutes(5) -NowUtc $now -Config $cfg).Code | Should -Be 'LockedOut'
    }
}

Describe 'Request validation' {
    It 'accepts a valid unlock' {
        $r = Test-FVRequest ([pscustomobject]@{ v = 1; op = 'Unlock'; id = [guid]::NewGuid().ToString(); password = 'x' })
        $r.Ok | Should -BeTrue
        $r.Request.op | Should -Be 'Unlock'
    }
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'null'; R = $null }
        @{ Case = 'no version'; R = [pscustomobject]@{ op = 'Ping' } }
        @{ Case = 'wrong version'; R = [pscustomobject]@{ v = 2; op = 'Ping' } }
        @{ Case = 'string version'; R = [pscustomobject]@{ v = '1'; op = 'Ping' } }
        @{ Case = 'unknown op'; R = [pscustomobject]@{ v = 1; op = 'Format' } }
        @{ Case = 'op wrong case'; R = [pscustomobject]@{ v = 1; op = 'unlock'; id = [guid]::NewGuid().ToString(); password = 'x' } }
        @{ Case = 'extra field'; R = [pscustomobject]@{ v = 1; op = 'Ping'; sid = 'S-1-5-18' } }
        @{ Case = 'field wrong case'; R = [pscustomobject]@{ v = 1; op = 'Unlock'; Id = [guid]::NewGuid().ToString(); password = 'x' } }
        @{ Case = 'missing field'; R = [pscustomobject]@{ v = 1; op = 'Unlock'; id = [guid]::NewGuid().ToString() } }
        @{ Case = 'bad guid'; R = [pscustomobject]@{ v = 1; op = 'Unlock'; id = '..\..\Windows'; password = 'x' } }
        @{ Case = 'numeric password'; R = [pscustomobject]@{ v = 1; op = 'Unlock'; id = [guid]::NewGuid().ToString(); password = 123 } }
        @{ Case = 'oversized password'; R = [pscustomobject]@{ v = 1; op = 'Unlock'; id = [guid]::NewGuid().ToString(); password = ('x' * 600) } }
        @{ Case = 'string bool'; R = [pscustomobject]@{ v = 1; op = 'LockAll'; force = 'true' } }
        @{ Case = 'negative size'; R = [pscustomobject]@{ v = 1; op = 'Create'; path = 'C:\x'; name = 'x'; password = 'x'; sizeGB = -1; contentBytes = 0 } }
        @{ Case = 'double size'; R = [pscustomobject]@{ v = 1; op = 'Create'; path = 'C:\x'; name = 'x'; password = 'x'; sizeGB = 1.5; contentBytes = 0 } }
    ) {
        (Test-FVRequest $R).Ok | Should -BeFalse
    }
}

Describe 'Framing' {
    It 'round-trips' {
        $ms = New-Object System.IO.MemoryStream
        Write-FVFrame -Stream $ms -Object @{ v = 1; op = 'Ping' }
        $ms.Position = 0
        (Read-FVFrame -Stream $ms -TimeoutMs 1000).op | Should -Be 'Ping'
    }
    It 'rejects an oversized length prefix' {
        $ms = New-Object System.IO.MemoryStream
        $ms.Write([System.BitConverter]::GetBytes([int]1000000), 0, 4)
        $ms.Position = 0
        { Read-FVFrame -Stream $ms -TimeoutMs 1000 } | Should -Throw
    }
    It 'rejects zero and negative lengths' {
        foreach ($n in @(0, -5)) {
            $ms = New-Object System.IO.MemoryStream
            $ms.Write([System.BitConverter]::GetBytes([int]$n), 0, 4)
            $ms.Position = 0
            { Read-FVFrame -Stream $ms -TimeoutMs 1000 } | Should -Throw
        }
    }
    It 'rejects truncated frames' {
        $ms = New-Object System.IO.MemoryStream
        $ms.Write([System.BitConverter]::GetBytes([int]50), 0, 4)
        $ms.Write([byte[]](1..10), 0, 10)
        $ms.Position = 0
        { Read-FVFrame -Stream $ms -TimeoutMs 1000 } | Should -Throw
    }
    It 'rejects invalid UTF-8' {
        $ms = New-Object System.IO.MemoryStream
        $body = [byte[]](0xC3, 0x28, 0x7B, 0x7D)
        $ms.Write([System.BitConverter]::GetBytes([int]$body.Length), 0, 4)
        $ms.Write($body, 0, $body.Length)
        $ms.Position = 0
        { Read-FVFrame -Stream $ms -TimeoutMs 1000 } | Should -Throw
    }
    It 'refuses to write an oversized frame' {
        $ms = New-Object System.IO.MemoryStream
        { Write-FVFrame -Stream $ms -Object @{ x = ('a' * 70000) } } | Should -Throw
    }
}

Describe 'Logging cannot leak secrets' {
    It 'drops fields that are not on the allow-list' {
        $script:lines = New-Object System.Collections.Generic.List[string]
        Set-FVLogSink -Sink { param($l, $e, $m) $script:lines.Add($m) }
        Write-FVLog -Name 'Test' -Fields @{ vaultId = 'abc'; password = 'SuperSecret123!'; newPassword = 'Other'; recoveryKey = '111111-222222' }
        Set-FVLogSink -Sink $null
        $lines[0] | Should -Match 'vaultId=abc'
        $lines[0] | Should -Not -Match 'SuperSecret'
        $lines[0] | Should -Not -Match 'Other'
        $lines[0] | Should -Not -Match '111111'
    }
    It 'strips newlines (no log injection)' {
        $script:lines = New-Object System.Collections.Generic.List[string]
        Set-FVLogSink -Sink { param($l, $e, $m) $script:lines.Add($m) }
        Write-FVLog -Name 'Test' -Fields @{ detail = "a`r`nevent=Forged" }
        Set-FVLogSink -Sink $null
        $lines[0] | Should -Not -Match "`n"
    }
}

Describe 'Registry' {
    BeforeEach { $script:file = Join-Path ([System.IO.Path]::GetTempPath()) ("fvreg-" + [guid]::NewGuid() + '.json') }
    AfterEach { Remove-Item "$file*" -Force -ErrorAction SilentlyContinue }
    It 'treats a missing file as empty' {
        $r = Read-FVRegistry -Path $file
        $r.Ok | Should -BeTrue
        @($r.Vaults).Count | Should -Be 0
    }
    It 'round-trips and keeps a backup' {
        $v = New-FolderVaultRecord -Id ([guid]::NewGuid().ToString()) -Name 'Fin' -FolderPath 'C:\Users\A\Documents\Fin' -Scope Profile -OwnerSid 'S-1-5-21-1-2-3-1001' -VhdxPath 'C:\x.vhdx' -SizeGB 5
        Save-FVRegistry -Path $file -Vaults @($v)
        Save-FVRegistry -Path $file -Vaults @($v)
        Test-Path "$file.bak" | Should -BeTrue
        $r = Read-FVRegistry -Path $file
        $r.Ok | Should -BeTrue
        $r.Vaults[0].Name | Should -Be 'Fin'
        $r.Vaults[0].CreatedUtc | Should -BeOfType [string]
    }
    It 'reports corruption instead of returning empty' {
        Set-Content -Path $file -Value '{ not json'
        $r = Read-FVRegistry -Path $file
        $r.Ok | Should -BeFalse
        $r.Code | Should -Be 'RegistryCorrupt'
    }
    It 'reports a registry with a non-GUID id as corrupt' {
        Set-Content -Path $file -Value '{"version":1,"vaults":[{"Id":"..\\..\\x"}]}'
        (Read-FVRegistry -Path $file).Ok | Should -BeFalse
    }
}

Describe 'Sizes' {
    It 'suggests 3x content, at least the default' {
        Get-FVSuggestedSizeGB -ContentBytes 100MB -Config $cfg | Should -Be 5
        Get-FVSuggestedSizeGB -ContentBytes 4GB -Config $cfg | Should -Be 12
    }
    It 'refuses content that will not fit, and low disk space' {
        (Test-FVSizeRequest -SizeGB 1 -ContentBytes 2GB -FreeBytes 100GB -Config $cfg).Code | Should -Be 'SizeInvalid'
        (Test-FVSizeRequest -SizeGB 10 -ContentBytes 5GB -FreeBytes 5GB -Config $cfg).Code | Should -Be 'InsufficientSpace'
        (Test-FVSizeRequest -SizeGB 10 -ContentBytes 5GB -FreeBytes 50GB -Config $cfg).Ok | Should -BeTrue
        (Test-FVSizeRequest -SizeGB 0 -ContentBytes 0 -FreeBytes 50GB -Config $cfg).Code | Should -Be 'SizeInvalid'
    }
}

Describe 'Vault names' {
    It 'accepts normal names' { Test-FolderVaultName 'Payroll 2026 (HR)' | Should -BeTrue }
    It 'rejects <N>' -ForEach @(@{ N = '' }, @{ N = ' x' }, @{ N = 'a/b' }, @{ N = 'a\b' }, @{ N = ('x' * 41) }, @{ N = 'x<script>' }) {
        Test-FolderVaultName $N | Should -BeFalse
    }
}

Describe 'Tree walking never follows links' -Skip:($IsWindows) {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("fvtree-" + [guid]::NewGuid())
        $script:outside = Join-Path ([System.IO.Path]::GetTempPath()) ("fvout-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path (Join-Path $root 'a/b') -Force | Out-Null
        New-Item -ItemType Directory -Path $outside -Force | Out-Null
        Set-Content -Path (Join-Path $root 'a/b/f.txt') -Value 'hello'
        Set-Content -Path (Join-Path $outside 'canary.txt') -Value 'must survive'
    }
    AfterEach { Remove-Item $root, $outside -Recurse -Force -ErrorAction SilentlyContinue }

    It 'reports links in a tree' {
        New-Item -ItemType SymbolicLink -Path (Join-Path $root 'a/link') -Target $outside | Out-Null
        $i = Get-FVTreeInfo -Path $root
        @($i.ReparsePoints).Count | Should -Be 1
        $i.Files | Should -Be 1
    }
    It 'deletes a tree without touching link targets' {
        New-Item -ItemType SymbolicLink -Path (Join-Path $root 'a/link') -Target $outside | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $root 'filelink') -Target (Join-Path $outside 'canary.txt') | Out-Null
        Remove-FVTreeContents -Path $root
        @(Get-ChildItem -Force $root).Count | Should -Be 0
        Get-Content (Join-Path $outside 'canary.txt') | Should -Be 'must survive'
    }
    It 'refuses to empty a link' {
        $l = Join-Path ([System.IO.Path]::GetTempPath()) ("fvlink-" + [guid]::NewGuid())
        New-Item -ItemType SymbolicLink -Path $l -Target $outside | Out-Null
        try { { Remove-FVTreeContents -Path $l } | Should -Throw }
        finally { Remove-Item $l -Force }
        Test-Path (Join-Path $outside 'canary.txt') | Should -BeTrue
    }
    It 'manifests detect changed content of equal size' {
        $m1 = Get-FVTreeManifest -Path $root -Mode Hash
        Set-Content -Path (Join-Path $root 'a/b/f.txt') -Value 'jello'
        $m2 = Get-FVTreeManifest -Path $root -Mode Hash
        (Compare-FVManifest -Source $m1 -Destination $m2).Ok | Should -BeFalse
    }
    It 'manifests mark links so verification fails' {
        New-Item -ItemType SymbolicLink -Path (Join-Path $root 'link') -Target $outside | Out-Null
        $m = Get-FVTreeManifest -Path $root -Mode Size
        (Compare-FVManifest -Source $m -Destination $m).Ok | Should -BeFalse
    }
}

Describe 'Audit fix A-01: secrets are redacted even inside free-text details' {
    It 'replaces the current request secrets anywhere in a line' {
        $script:lines = New-Object System.Collections.Generic.List[string]
        Set-FVLogSink -Sink { param($l, $e, $m) $script:lines.Add($m) }
        Set-FVLogRedaction -Secrets @('Mangoes ripen in March 2027', '111111-222222-333333-444444-555555-666666-777777-888888')
        Write-FVLog -Name 'Test' -Fields @{ detail = "Cannot convert value 'Mangoes ripen in March 2027' to type X" }
        Write-FVLog -Name 'Test' -Fields @{ detail = 'key 111111-222222-333333-444444-555555-666666-777777-888888 bad' }
        Set-FVLogRedaction -Secrets @()
        Set-FVLogSink -Sink $null
        ($lines -join "`n") | Should -Not -Match 'Mangoes'
        ($lines -join "`n") | Should -Not -Match '111111'
        ($lines -join "`n") | Should -Match '\*\*\*'
    }
}

Describe 'Audit fix A-28: Invoke-FVNative' -Skip:($IsWindows) {
    It 'returns the exit code and both outputs, even when the caller stops on errors' {
        # Modules take preference variables from the global scope, so set it there.
        $old = $global:ErrorActionPreference
        $global:ErrorActionPreference = 'Stop'
        try { $r = Invoke-FVNative -FilePath '/bin/sh' -ArgumentList @('-c', 'echo out; echo err 1>&2; exit 3') }
        finally { $global:ErrorActionPreference = $old }
        $r.ExitCode | Should -Be 3
        $r.Output | Should -Contain 'out'
        $r.Output | Should -Contain 'err'
        $r.Text | Should -Match 'out'
    }
    It 'works for a program that prints nothing' {
        (Invoke-FVNative -FilePath '/bin/true').ExitCode | Should -Be 0
    }
}

Describe '0.3.0: protecting any of your own folders' {
    BeforeAll { $script:prof = 'C:\Users\Alice' }
    It 'allows a folder in OneDrive (the folder refused by 0.2.5 on the first test PC)' {
        $r = Get-FVPathScope -Path 'C:\Users\jsmith\OneDrive\Documents\VaultTest' -ProfilePath 'C:\Users\jsmith'
        $r.Ok | Should -BeTrue
        $r.Scope | Should -Be 'Profile'
    }
    It 'allows a folder in a work OneDrive' {
        (Get-FVPathScope -Path 'C:\Users\Alice\OneDrive - Contoso\Finance' -ProfilePath $prof).Scope | Should -Be 'Profile'
    }
    It 'says why a whole OneDrive, Documents or Desktop folder is refused' {
        foreach ($p in @('C:\Users\Alice\OneDrive', 'C:\Users\Alice\OneDrive\Desktop', 'C:\Users\Alice\Documents', 'C:\Users\Alice')) {
            (Get-FVPathScope -Path $p -ProfilePath $prof).Code | Should -Be 'PathWholeFolder'
        }
    }
    It 'allows <P> as a personal folder outside the profile' -ForEach @(
        @{ P = 'D:\Accounts' }, @{ P = 'D:\Data\Payroll 2026' }, @{ P = 'C:\Data\HR' }, @{ P = 'C:\Shared-but-not-configured\x' }
    ) {
        $r = Get-FVPathScope -Path $P -ProfilePath $prof -FixedDrives @('C', 'D')
        $r.Ok | Should -BeTrue
        $r.Scope | Should -Be 'Local'
    }
    It 'refuses outside the profile when IT has switched that off' {
        (Get-FVPathScope -Path 'D:\Accounts' -ProfilePath $prof -AllowOutsideProfile $false).Code | Should -Be 'PathOutsideProfile'
        (Get-FVPathScope -Path 'C:\Users\Alice\Documents\X' -ProfilePath $prof -AllowOutsideProfile $false).Ok | Should -BeTrue
    }
    It 'refuses USB sticks, DVDs and network drives' {
        (Get-FVPathScope -Path 'E:\Payroll' -ProfilePath $prof -FixedDrives @('C', 'D')).Code | Should -Be 'PathNotLocalDisk'
        (Get-FVPathScope -Path 'e:\Payroll' -ProfilePath $prof -FixedDrives @('C', 'E')).Ok | Should -BeTrue
    }
    It 'refuses other people''s folders, wherever their profile is' {
        (Get-FVPathScope -Path 'C:\Users\Bob\Documents\Secret' -ProfilePath $prof).Code | Should -Be 'PathOtherUser'
        (Get-FVPathScope -Path 'D:\Profiles\bob\Docs' -ProfilePath $prof -OtherProfiles @('D:\Profiles\bob')).Code | Should -Be 'PathOtherUser'
        (Get-FVPathScope -Path 'D:\Users\x' -ProfilePath 'D:\Users\Alice' -ProfilesDirectory 'D:\Users').Code | Should -Be 'PathOtherUser'
    }
    It 'still allows the caller''s own profile when profiles live on another drive' {
        (Get-FVPathScope -Path 'D:\Users\Alice\Payroll' -ProfilePath 'D:\Users\Alice' -ProfilesDirectory 'D:\Users').Scope | Should -Be 'Profile'
    }
    It 'refuses everything but shared areas when the caller has no profile' {
        (Get-FVPathScope -Path 'D:\Accounts' -ProfilePath $null).Ok | Should -BeFalse
        (Get-FVPathScope -Path 'D:\Shared\Fin' -ProfilePath $null -SharedRoots @('D:\Shared')).Scope | Should -Be 'Shared'
    }
    It 'Resolve-FVPathScope does not treat the caller''s own profile as someone else''s' {
        $layout = [pscustomobject]@{ ProfilesDirectory = 'C:\Users'; Profiles = @('C:\Users\Alice', 'C:\Users\bob', 'D:\Profiles\carol'); FixedDrives = @('C', 'D') }
        (Resolve-FVPathScope -Path 'C:\Users\alice\Documents\Fin' -ProfilePath 'C:\Users\Alice' -Layout $layout).Scope | Should -Be 'Profile'
        (Resolve-FVPathScope -Path 'D:\Profiles\carol\x' -ProfilePath 'C:\Users\Alice' -Layout $layout).Code | Should -Be 'PathOtherUser'
        (Resolve-FVPathScope -Path 'D:\Accounts' -ProfilePath 'C:\Users\Alice' -Layout $layout).Scope | Should -Be 'Local'
        (Resolve-FVPathScope -Path 'F:\Accounts' -ProfilePath 'C:\Users\Alice' -Layout $layout).Code | Should -Be 'PathNotLocalDisk'
        (Resolve-FVPathScope -Path 'D:\Accounts' -ProfilePath 'C:\Users\Alice' -AllowOutsideProfile $false -Layout $layout).Code | Should -Be 'PathOutsideProfile'
    }
    It 'has a plain message for every new refusal' {
        foreach ($code in @('PathWholeFolder', 'PathOtherUser', 'PathNotLocalDisk', 'PathOutsideProfile', 'PathOnlineOnly')) {
            Get-FVMessage $code | Should -Not -BeNullOrEmpty
            Get-FVMessage $code | Should -Not -Match ([char]0x2014)
        }
    }
    It 'keeps the new setting on by default and accepts false' {
        (ConvertTo-FVConfig ([pscustomobject]@{})).Config.AllowFoldersOutsideProfile | Should -BeTrue
        (ConvertTo-FVConfig ([pscustomobject]@{ AllowFoldersOutsideProfile = $false })).Config.AllowFoldersOutsideProfile | Should -BeFalse
        $c = ConvertTo-FVConfig ([pscustomobject]@{ AllowFoldersOutsideProfile = 'yes' })
        $c.Config.AllowFoldersOutsideProfile | Should -BeTrue
        @($c.Warnings).Count | Should -Be 1
    }
}

Describe '0.3.0: OneDrive placeholders are not links' {
    It 'recognises every cloud tag variant and nothing else' {
        $u = { param($h) [Convert]::ToUInt32($h, 16) }
        foreach ($t in @('9000001A', '9000101A', '9000701A', '9000F01A')) { Test-FVCloudTag -Tag (& $u $t) | Should -BeTrue }
        foreach ($t in @('A0000003', 'A000000C', '80000013', '80000017', '8000001B', '0', 'FFFFFFFF', '9000001B')) { Test-FVCloudTag -Tag (& $u $t) | Should -BeFalse }
    }
    It 'treats a reparse point as a link unless its tag is a cloud tag' -Skip:($IsWindows) {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('fvrp-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path "$d/real")
        [void](New-Item -ItemType SymbolicLink -Path "$d/link" -Target "$d/real")
        try {
            $item = Get-Item -Force "$d/link"
            Mock -ModuleName FolderVault.Common Get-FVReparseTag { [Convert]::ToUInt32('A000000C', 16) }
            Test-FVIsReparse $item | Should -BeTrue
            Mock -ModuleName FolderVault.Common Get-FVReparseTag { [Convert]::ToUInt32('9000001A', 16) }
            Test-FVIsReparse $item | Should -BeFalse
            Test-FVIsCloudFile $item | Should -BeTrue
            Mock -ModuleName FolderVault.Common Get-FVReparseTag { [uint32]4294967295 }
            Test-FVIsReparse $item | Should -BeTrue -Because 'an unknown tag must be treated as a link'
            Test-FVIsReparse (Get-Item -Force "$d/real") | Should -BeFalse
        } finally { Remove-Item -Recurse -Force $d }
    }
    It 'gives "unknown" off Windows, never "not a link"' -Skip:($IsWindows) {
        Get-FVReparseTag -Path '/' | Should -Be ([uint32]4294967295)
    }
}

Describe '0.3.0: warnings before protecting' {
    It 'warns about OneDrive and about folders outside the user folder, and nothing otherwise' {
        @(Get-FVProtectWarnings -Check ([pscustomobject]@{ Scope = 'Profile'; Synced = $false })).Count | Should -Be 0
        $w = @(Get-FVProtectWarnings -Check ([pscustomobject]@{ Scope = 'Profile'; Synced = $true }))
        $w.Count | Should -Be 1
        $w[0] | Should -Match 'OneDrive stops syncing'
        $w[0] | Should -Match '93 days'
        $w = @(Get-FVProtectWarnings -Check ([pscustomobject]@{ Scope = 'Local'; Synced = $false }))
        $w[0] | Should -Match 'only you can open it'
        @(Get-FVProtectWarnings -Check ([pscustomobject]@{ Scope = 'Local'; Synced = $true })).Count | Should -Be 2
        @(Get-FVProtectWarnings -Check ([pscustomobject]@{ Ok = $true })).Count | Should -Be 0
    }
}

Describe '0.3.0: the reparse tag helper matches Windows'' WIN32_FIND_DATAW layout' {
    It 'compiles, and puts dwReserved0 at byte 36 and cFileName at byte 44' {
        $src = & (Get-Module FolderVault.Common) { $script:FVNativeReparseSource }
        $src = $src.Replace('namespace FolderVault', 'namespace FolderVaultLayoutTest')
        Add-Type -TypeDefinition $src
        $t = [FolderVaultLayoutTest.ReparseTag].GetNestedType('WIN32_FIND_DATAW', [System.Reflection.BindingFlags]::NonPublic)
        [int][System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'ftCreationLow') | Should -Be 4
        [int][System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'nFileSizeHigh') | Should -Be 28
        [int][System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'dwReserved0') | Should -Be 36
        [int][System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'cFileName') | Should -Be 44
        [int][System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'cAlternateFileName') | Should -Be 564
    }
}

Describe 'Local weak words (LocalWeakWords setting)' {
    It 'refuses a password made mostly of a word the IT team added' {
        $cfg = (ConvertTo-FVConfig ([pscustomobject]@{ LocalWeakWords = @('Springfield', 'acme') })).Config
        $cfg.LocalWeakWords | Should -Be @('springfield', 'acme')
        (Test-FVPassword -Password 'Springfield@2026' -UserName 'bob' -Config $cfg).Problems | Should -Contain 'Common'
        (Test-FVPassword -Password 'Springfield@2026' -UserName 'bob' -Config (Get-FVDefaultConfig)).Ok | Should -BeTrue
    }
    It 'still accepts a long sentence that contains the word' {
        $cfg = (ConvertTo-FVConfig ([pscustomobject]@{ LocalWeakWords = @('acme') })).Config
        (Test-FVPassword -Password 'Acme lorries leave at dawn 2027' -UserName 'bob' -Config $cfg).Ok | Should -BeTrue
    }
    It 'ignores bad entries with a warning, removes duplicates, and keeps at most 200' {
        $r = ConvertTo-FVConfig ([pscustomobject]@{ LocalWeakWords = @('ok1', 'OK1', 'no', 'has space', $null, ('x' * 41)) })
        $r.Config.LocalWeakWords | Should -Be @('ok1')
        @($r.Warnings).Count | Should -Be 4
        $many = 1..250 | ForEach-Object { "word$_" }
        @((ConvertTo-FVConfig ([pscustomobject]@{ LocalWeakWords = $many })).Config.LocalWeakWords).Count | Should -Be 200
    }
    It 'works with a config object that has no LocalWeakWords (the window before it has the policy)' {
        (Test-FVPassword -Password 'Password2026!' -UserName 'bob' -Config ([pscustomobject]@{ MinPasswordLength = 12 })).Problems | Should -Contain 'Common'
    }
    It 'has no place names built in' {
        $words = & (Get-Module FolderVault.Common) { $script:FVCommonWords }
        $words | Should -Not -Contain 'london'
        @($words).Count | Should -BeGreaterThan 30
    }
}
