@echo off
rem Folder Vault: double-click to install or update Folder Vault on this PC.
rem Put the client's recovery certificate (.cer) in this folder first.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\Install-FolderVault.ps1" -Interactive
