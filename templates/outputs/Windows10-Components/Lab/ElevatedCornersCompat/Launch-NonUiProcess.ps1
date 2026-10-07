# Dot-source this file. Every launch bypasses ShellExecute and uses CREATE_NO_WINDOW.
# Arguments are a literal string array, never a prequoted command-line string.
if(-not ('Explorer10Tools.NonUiProcess' -as [type])){
 Add-Type -Path (Join-Path $PSScriptRoot 'NonUiProcess.cs')
}
function Start-NonUiProcess {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory=$true)][string]$FilePath,
  [string[]]$ArgumentList=@(),
  [string]$RedirectStandardOutput,
  [string]$RedirectStandardError,
  [string]$WorkingDirectory=(Get-Location).Path
 )
 [Explorer10Tools.NonUiProcess]::Start($FilePath,$ArgumentList,$RedirectStandardOutput,$RedirectStandardError,$WorkingDirectory)
}
