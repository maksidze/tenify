@echo off

chcp 65001 >nul

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Settings10.ps1" -Seconds 300

pause

