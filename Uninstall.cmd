@echo off
rem Folder Vault: double-click to remove Folder Vault from this PC. Settings, Apps uses this too.
set "FV_SCRIPT=%~dp0Uninstall-FolderVault.ps1"
if exist "%~dp0install\Uninstall-FolderVault.ps1" set "FV_SCRIPT=%~dp0install\Uninstall-FolderVault.ps1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%FV_SCRIPT%" -Interactive
