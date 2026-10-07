@echo off
setlocal
echo EXPERIMENTAL: this profile still requires an interactive Alt+Tab / Win+Tab test.
echo Uses the signed Windows 10 EXE, private PCS copy and a scoped XAML memory adapter.
echo Includes the verified language-indicator ABI fix (InputSwitchCompat).
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Explorer10-VFS.ps1" -Profile host-dcomp-resource -XamlQuirk %*
if errorlevel 1 pause
