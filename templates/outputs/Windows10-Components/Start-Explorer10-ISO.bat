@echo off
setlocal
echo Start the signed Windows 10 Explorer extracted from D:.
echo Current Explorer windows will close. UAC is needed for a temporary restart guard.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Explorer10-ISO.ps1"
if errorlevel 1 pause
