@{
    Severity     = @('Error', 'Warning', 'Information')
    ExcludeRules = @(
        # Interactive console output in installer/admin scripts is intentional.
        'PSAvoidUsingWriteHost',
        # Plain-text passwords must cross the pipe and reach BitLocker's WMI API, which only accepts strings.
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        # Internal helper functions use short names; exported names follow Verb-Noun.
        'PSUseSingularNouns',
        'PSProvideCommentHelp',
        'PSUseOutputTypeCorrectly',
        # Positional arguments are used for short internal helpers only.
        'PSAvoidUsingPositionalParameters',
        # Internal state-changing helpers are not user-facing cmdlets; -WhatIf would be noise.
        'PSUseShouldProcessForStateChangingFunctions',
        # Test-FVPassword/Get-FVPolicyFailure take a user NAME to reject passwords containing it, not a credential.
        'PSAvoidUsingUsernameAndPasswordParams',
        # WPF/WinForms handler signatures (sender, args) are fixed by .NET.
        'PSReviewUnusedParameter'
    )
    Rules        = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework') }
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework') }
    }
}
