@echo off
setlocal
chcp 65001 >nul
echo Возврат штатной оболочки Windows 11.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Stop-Windows10-Maximum.ps1"
if errorlevel 1 pause
