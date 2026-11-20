@echo off
rem Folder Vault: double-click to check whether this PC is ready. Changes nothing.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\Test-FolderVaultReadiness.ps1"
