param([Parameter(Mandatory=$true)][uint32]$TargetPid,[Parameter(Mandatory=$true)][uint64]$TargetBorn,[ValidateRange(15,3600)][int]$Seconds=3600)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Windows PowerShell 5 Desktop required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
. (Join-Path $PSScriptRoot 'NetworkTrayState.ps1')
. (Join-Path $PSScriptRoot '..\..\Launch-NonUiProcess.ps1')
$owned=Read-OwnedNetworkState ''
if($owned -and $owned.Process){
 try{
  if($owned.State.TargetPid -ne $TargetPid -or [uint64]$owned.State.TargetBorn -ne $TargetBorn){throw 'An owned network session belongs to a different shell. Stop it first.'}
  if(!$owned.Ready -or $owned.StopRequested){throw 'The existing network session is not ready.'}
  Write-Output ('Network handler reused, PID '+$owned.State.ChildPid+'. Its existing deadline is unchanged.');return
 }finally{$owned.Process.Dispose()}
}
$id=[guid]::NewGuid().ToString('N')
$controller=Start-NonUiProcess -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'Start-NetworkTray.ps1'),'-Execute','-TargetPid',[string]$TargetPid,'-TargetBorn',[string]$TargetBorn,'-Seconds',[string]$Seconds) -RedirectStandardOutput (Join-Path $PSScriptRoot ($id+'.stdout.log')) -RedirectStandardError (Join-Path $PSScriptRoot ($id+'.stderr.log'))
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(20)
 do{
  Start-Sleep -Milliseconds 150
  $current=Read-OwnedNetworkState ''
  if($current -and $current.Process){
   try{if($current.State.TargetPid -eq $TargetPid -and [uint64]$current.State.TargetBorn -eq $TargetBorn -and $current.Ready -and !$current.StopRequested){Write-Output ('Network handler initialized, PID '+$current.State.ChildPid+'. Icon appearance requires visible confirmation.');return}}finally{$current.Process.Dispose()}
  }
  if($controller.HasExited){throw ('Network controller exited; see '+$id+'.stderr.log')}
 }while([DateTime]::UtcNow -lt $deadline)
 & (Join-Path $PSScriptRoot 'Stop-NetworkTray.ps1') | Out-Null
 throw 'Network handler readiness timed out.'
}finally{$controller.Dispose()}
