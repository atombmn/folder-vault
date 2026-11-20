#Requires -Version 5.1
<#
    Folder Vault - client side of the broker pipe (runs as the signed-in user).

    Before any request is sent, the client checks that the pipe it reached is
    owned by SYSTEM or Administrators. A standard user who creates a fake
    "FolderVaultBroker" pipe to harvest passwords owns that pipe themselves and
    cannot set its owner to SYSTEM, so the check fails and nothing is sent.
#>

Set-StrictMode -Version 3.0

$script:TrustedPipeOwners = @('S-1-5-18', 'S-1-5-32-544')

function Test-FVPipeOwnerTrusted {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$OwnerSid)
    return ($script:TrustedPipeOwners -contains $OwnerSid)
}

function Get-FVPipeOwnerSid {
    param([System.IO.Pipes.PipeStream]$Pipe)
    $acl = $Pipe.GetAccessControl()
    return $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
}

function Invoke-FVBroker {
    <#
        Sends one request and returns the broker's response as a PSCustomObject
        with .ok .code .message .data. Never throws: connection problems become
        BrokerUnavailable / BrokerUntrusted responses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Request,
        [int]$ConnectTimeoutMs = 5000,
        [int]$ResponseTimeoutMs = 120000
    )
    $Request['v'] = Get-FVProtocolVersion
    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', (Get-FVPipeName), [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::Asynchronous,
            [System.Security.Principal.TokenImpersonationLevel]::Identification)
        try { $pipe.Connect($ConnectTimeoutMs) }
        catch { return [pscustomobject](New-FVResponse -Ok $false -Code 'BrokerUnavailable') }

        $owner = $null
        try { $owner = Get-FVPipeOwnerSid -Pipe $pipe } catch { $owner = $null }
        if ($null -eq $owner -or -not (Test-FVPipeOwnerTrusted -OwnerSid $owner)) {
            return [pscustomobject](New-FVResponse -Ok $false -Code 'BrokerUntrusted')
        }

        Write-FVFrame -Stream $pipe -Object $Request
        $resp = Read-FVFrame -Stream $pipe -TimeoutMs $ResponseTimeoutMs
        if ($null -eq $resp -or $null -eq $resp.PSObject.Properties['ok']) {
            return [pscustomobject](New-FVResponse -Ok $false -Code 'InternalError')
        }
        return $resp
    } catch {
        return [pscustomobject](New-FVResponse -Ok $false -Code 'BrokerUnavailable')
    } finally {
        foreach ($k in @('password', 'newPassword', 'recoveryKey')) { if ($Request.ContainsKey($k)) { $Request[$k] = $null } }
        if ($null -ne $pipe) { $pipe.Dispose() }
    }
}

Export-ModuleMember -Function @('Invoke-FVBroker', 'Test-FVPipeOwnerTrusted')
