@echo off
setlocal
rem Snapshot entrypoint guard
if exist "%~dp0Start-Build.ps1" (
 "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Build.ps1"
 if errorlevel 1 (
  pause
  exit /b 1
 )
 exit /b 0
)
chcp 65001 >nul
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0outputs\Windows10-Components\Windows10-DirectOneClick.ps1" -Mode Start
if errorlevel 1 (
 echo.
 echo Some components failed. See the log path above.
 pause
 exit /b 1
)
