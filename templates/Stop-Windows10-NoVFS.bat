@echo off

setlocal

chcp 65001 >nul

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0outputs\Windows10-Components\Windows10-DirectOneClick.ps1" -Mode Restore

if errorlevel 1 (

 echo Error. See the log path above.

 pause

 exit /b 1

)

