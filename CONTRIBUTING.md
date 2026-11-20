# Contributing

Thank you for helping. A few rules keep Folder Vault safe and working on
Windows PowerShell 5.1.

1. **Run the tests** before you open a pull request:

   ```powershell
   pwsh -File tests/tools/Get-FVReferenceAssemblies.ps1   # once, for the .NET Framework 4.8 check
   Invoke-Pester ./tests/unit
   Invoke-ScriptAnalyzer -Path src, install, admin -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
   ```

2. **Windows PowerShell 5.1 only.** No PowerShell 7 syntax (`??`, `?.`,
   ternaries, `-Parallel`) or .NET Core-only APIs. `Static.Tests.ps1` checks
   for the pitfalls found so far; add a rule when you find a new one.
3. **Every fix gets a test**, and the test must fail without the fix. Undo the
   fix once to prove it.
4. **The background service never opens a path a user sends.** Keep file work
   in the user's own process (`FolderVault.UserOps.psm1`).
5. **Never log a password,** not even in an error message.
6. **Plain English for everything a person reads**: say what happened and
   what to do. British spelling. Messages live in one table in
   `FolderVault.Common.psm1`.
7. Code that only Windows can test needs a Windows test in
   `tests/windows/Invoke-FolderVaultIntegrationTests.ps1`.
8. Update `CHANGELOG.md` and, if behaviour changes, the guides in `docs/`.
