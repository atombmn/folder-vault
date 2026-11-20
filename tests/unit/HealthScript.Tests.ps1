<#
    Runs the WHOLE health check script, as Windows would, with Windows' answers
    simulated (scheduled task, WMI, ACLs, event log, registry, shortcuts).
    The three health-check crashes found on the first real PC were all in glue
    code that only ran on Windows; this exercises every line of it.
#>
BeforeAll {
    $global:FVHT = @{}
    $global:FVHT.repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $global:FVHT.healthScript = Join-Path $global:FVHT.repo 'admin/Get-FolderVaultHealth.ps1'
    $global:FVHT.userSid = 'S-1-5-21-111-222-333-1001'
    # The script imports these itself; load them first so Pester can replace their functions.
    Import-Module (Join-Path $global:FVHT.repo 'src/FolderVault.Common.psm1') -Force
    Import-Module (Join-Path $global:FVHT.repo 'src/FolderVault.Client.psm1') -Force
    Import-Module (Join-Path $global:FVHT.repo 'admin/FolderVault.Health.psm1') -Force
    # Windows-only commands do not exist here; give Pester something to replace.
    $stubs = @{
        'Get-Acl'           = { [CmdletBinding()] param([string]$LiteralPath, [string]$Path) throw 'not mocked' }
        'Get-ScheduledTask' = { [CmdletBinding()] param([string]$TaskName, [string]$TaskPath) throw 'not mocked' }
        'Get-CimInstance'   = { [CmdletBinding()] param([string]$ClassName, [string]$Namespace, [string]$Filter) throw 'not mocked' }
        'Invoke-CimMethod'  = { [CmdletBinding()] param($InputObject, [string]$MethodName, [hashtable]$Arguments) throw 'not mocked' }
        'Get-WinEvent'      = { [CmdletBinding()] param([hashtable]$FilterHashtable, [int]$MaxEvents) throw 'not mocked' }
    }
    foreach ($n in $stubs.Keys) {
        if (-not (Get-Command $n -ErrorAction SilentlyContinue)) { Set-Item -Path "function:global:$n" -Value $stubs[$n] }
    }

    function New-Ace { param([string]$Sid, [long]$Rights, [string]$Type = 'Allow')
        # SecurityIdentifier is Windows-only: a stand-in with the same Translate() and Value.
        $id = [pscustomobject]@{ Value = $Sid }
        $id | Add-Member -MemberType ScriptMethod -Name Translate -Value { param($t) [pscustomobject]@{ Value = $this.Value } }
        $id | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.Value } -Force
        [pscustomobject]@{ IdentityReference = $id; FileSystemRights = [System.Security.AccessControl.FileSystemRights]$Rights; AccessControlType = $Type }
    }
    function New-Event { param([int]$Id) [pscustomobject]@{ Id = $Id } }

    function Invoke-Health {
        param([switch]$Reset)
        $out = & $global:FVHT.healthScript -Json -InstallDir $global:FVHT.inst -DataDir $global:FVHT.data -ResetBaseline:$Reset
        return @(($out -join "`n") | ConvertFrom-Json)
    }
    function Get-Line { param($Results, [string]$Like) @($Results | Where-Object { $_.Check -like $Like }) }
}

Describe 'Get-FolderVaultHealth.ps1 runs end to end' -Skip:($IsWindows) {
    BeforeEach {
        $global:FVHT.root = Join-Path ([System.IO.Path]::GetTempPath()) ('fvhealth-' + [guid]::NewGuid().ToString('N'))
        $global:FVHT.inst = Join-Path $global:FVHT.root 'Program Files/FolderVault'
        $global:FVHT.data = Join-Path $global:FVHT.root 'ProgramData/FolderVault'
        $global:FVHT.home1 = Join-Path $global:FVHT.root 'Users/alice'
        New-Item -ItemType Directory -Path $global:FVHT.inst, (Join-Path $global:FVHT.data 'Logs'), (Join-Path $global:FVHT.data 'Vaults'), (Join-Path $global:FVHT.data 'Escrow'), (Join-Path $global:FVHT.home1 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup') -Force | Out-Null
        foreach ($f in @('FolderVault.Common.psm1', 'FolderVault.Client.psm1')) { Copy-Item (Join-Path $global:FVHT.repo "src/$f") $global:FVHT.inst }
        $files = [ordered]@{}
        foreach ($f in Get-ChildItem $global:FVHT.inst -File) { $files[$f.Name] = (Get-FileHash $f.FullName -Algorithm SHA256).Hash }
        @{ version = '0.2.4'; files = $files } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $global:FVHT.data 'install-manifest.json')
        New-Item -ItemType File -Path (Join-Path $global:FVHT.home1 'NTUSER.DAT') | Out-Null

        $global:FVHT.programRights = [long]0x1200a9      # Users: read and run (what the installer sets)
        $global:FVHT.events = @()
        $global:FVHT.runValues = [ordered]@{ OneDrive = 'C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background' }
        $global:FVHT.hiveLoaded = $false
        Set-Content -Path (Join-Path $global:FVHT.home1 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Messages.lnk') -Value 'x'

        Mock Get-Acl {
            if ($LiteralPath -eq $global:FVHT.inst) {
                return [pscustomobject]@{ Access = @((New-Ace 'S-1-5-18' 0x1F01FF), (New-Ace 'S-1-5-32-544' 0x1F01FF), (New-Ace 'S-1-5-32-545' $global:FVHT.programRights)) }
            }
            return [pscustomobject]@{ Access = @((New-Ace 'S-1-5-18' 0x1F01FF), (New-Ace 'S-1-5-32-544' 0x1F01FF)) }
        }
        Mock Get-ScheduledTask {
            [pscustomobject]@{ State = 'Running'; Principal = [pscustomobject]@{ UserId = 'SYSTEM' }; Actions = @([pscustomobject]@{ Arguments = "-File `"$($global:FVHT.inst)\FolderVault.Broker.ps1`"" }) }
        }
        Mock Invoke-FVBroker {
            if ($Request.op -eq 'Ping') { return [pscustomobject]@{ ok = $true; code = 'Ok'; data = [pscustomobject]@{ version = '0.2.4' } } }
            if ($Request.op -eq 'AdminList') { return [pscustomobject]@{ ok = $true; code = 'Ok'; data = [pscustomobject]@{ vaults = @() } } }
        }
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_Process' { return @() }
                'Win32_EncryptableVolume' { return [pscustomobject]@{ DriveLetter = 'C:' } }
                'Win32_ShadowCopy' { return @() }
                'Win32_UserProfile' {
                    return @(
                        [pscustomobject]@{ Special = $false; SID = $global:FVHT.userSid; LocalPath = $global:FVHT.home1 },
                        [pscustomobject]@{ Special = $false; SID = 'S-1-5-82-271721585'; LocalPath = (Join-Path $global:FVHT.root 'Users/.NET v4.5') }
                    )
                }
            }
        }
        Mock Invoke-CimMethod { [pscustomobject]@{ ProtectionStatus = 1 } }
        Mock Get-WinEvent { $global:FVHT.events }
        Mock Test-FVRegistryKey { $false }                     # alice is signed out
        Mock Mount-FVUserHive { $global:FVHT.hiveLoaded = $true; $true }
        Mock Dismount-FVUserHive { $global:FVHT.hiveLoaded = $false; $true }
        Mock Get-FVUserRegistryItems {
            $over = @(); if ($global:FVHT.override) { $over = @('FolderVault.Unlock') }
            [pscustomobject]@{ Items = @($global:FVHT.runValues.Keys | ForEach-Object { "Run: $_ = $($($global:FVHT.runValues)[$_])" }); Overrides = $over }
        }
        Mock Get-FVShortcutTarget { 'C:\x.exe' }
        $global:FVHT.override = $false
    }
    AfterEach { Remove-Item -Recurse -Force $global:FVHT.root -ErrorAction SilentlyContinue }
    AfterAll { Remove-Variable -Name FVHT -Scope Global -ErrorAction SilentlyContinue }

    It 'completes without throwing and reports no failures on a healthy PC' {
        $r = Invoke-Health
        @($r | Where-Object Status -eq 'FAIL') | Should -BeNullOrEmpty
        (Get-Line $r 'Program folder permissions').Status | Should -Be 'PASS'
        (Get-Line $r 'Background service answering').Status | Should -Be 'PASS'
        @($r).Count | Should -BeGreaterThan 15
    }
    It 'counts events by number, including the ones added in 0.2.1 (bug in 0.2.3)' {
        $global:FVHT.events = @((New-Event 1010), (New-Event 1010), (New-Event 1011), (New-Event 1930))
        $r = Invoke-Health
        (Get-Line $r 'Events: wrong passwords').Detail | Should -Be '2 in the last 30 days'
        (Get-Line $r 'Events: lock-outs').Status | Should -Be 'WARN'
        (Get-Line $r 'Events: failed service starts').Status | Should -Be 'WARN'
        (Get-Line $r 'Events: automatic locks').Detail | Should -Be '0 in the last 30 days'
    }
    It 'still flags real write access to the program folder' {
        $global:FVHT.programRights = [long][System.Security.AccessControl.FileSystemRights]'Modify'
        (Get-Line (Invoke-Health) 'Program folder permissions').Status | Should -Be 'FAIL'
    }
    It 'records a sign-in baseline, then passes, then warns about a new program, then accepts it' {
        $first = Invoke-Health
        (Get-Line $first 'Sign-in programs (alice)').Status | Should -Be 'INFO'
        @(Get-Line $first 'Sign-in programs (.NET*') | Should -BeNullOrEmpty
        Test-Path (Join-Path $global:FVHT.data 'signin-baseline.json') | Should -BeTrue
        Should -Invoke Mount-FVUserHive -Times 1
        Should -Invoke Dismount-FVUserHive -Times 1

        (Get-Line (Invoke-Health) 'Sign-in programs (alice)').Status | Should -Be 'PASS'

        $global:FVHT.runValues['Updater'] = 'C:\Users\alice\AppData\Local\Temp\u.exe'
        $warn = Get-Line (Invoke-Health) 'Sign-in programs (alice)'
        $warn.Status | Should -Be 'WARN'
        $warn.Detail | Should -Match 'Run: Updater'

        [void](Invoke-Health -Reset)
        (Get-Line (Invoke-Health) 'Sign-in programs (alice)').Status | Should -Be 'PASS'
    }
    It 'fails at once on a replaced Folder Vault menu item' {
        $global:FVHT.override = $true
        (Get-Line (Invoke-Health) 'Sign-in programs (alice)').Status | Should -Be 'FAIL'
    }
    It 'reports an earlier failed start with its reason' {
        Set-Content (Join-Path $global:FVHT.data 'Logs/broker-startup.log') '2026-11-12T14:06:31Z Folder Vault background service failed to start: test (script line 9)'
        (Get-Line (Invoke-Health) 'Background service start-up failures').Detail | Should -Match 'failed to start: test'
    }
}
