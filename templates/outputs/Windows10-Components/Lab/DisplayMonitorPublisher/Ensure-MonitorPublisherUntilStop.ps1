param([Parameter(Mandatory=$true)][uint32]$TargetPid,[Parameter(Mandatory=$true)][uint64]$TargetBorn)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Windows PowerShell 5 required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
. (Join-Path $PSScriptRoot '..\..\Launch-NonUiProcess.ps1')
function Find-Publisher {
 $pointer=Join-Path $PSScriptRoot 'untilstop-current-state.txt'
 if(!(Test-Path -LiteralPath $pointer)){return $null}
 try{
  $path=[IO.Path]::GetFullPath([IO.File]::ReadAllText($pointer).Trim())
  if([IO.Path]::GetDirectoryName($path) -ine [IO.Path]::GetFullPath($PSScriptRoot) -or [IO.Path]::GetFileName($path) -notmatch '^publisher-untilstop-[0-9a-f]{32}\.log\.state\.json$'){throw 'Unexpected publisher state path.'}
  $s=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
  if($s.Mode -ne 'UntilStop' -or $s.Status -ne 'running' -or $s.TargetPid -ne $TargetPid -or [uint64]$s.TargetBorn -ne $TargetBorn -or (Test-Path -LiteralPath $s.CancelFile)){return $null}
  $p=Get-Process -Id $s.PublisherPid -ErrorAction SilentlyContinue
  $owner=Get-Process -Id $s.ControllerPid -ErrorAction SilentlyContinue
  if(!$p -or !$owner){return $null}
  try{
   if($p.Path -ine (Join-Path $PSScriptRoot 'MonitorPublisherUntilStop.exe') -or $p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$s.PublisherBorn){return $null}
   if($owner.Path -ine (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -or $owner.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$s.ControllerBorn){return $null}
   return $s
  }finally{$p.Dispose();$owner.Dispose()}
 }catch{return $null}
}
$existing=Find-Publisher
if($existing){Write-Output ('Monitor publisher already works UntilStop, PID '+$existing.PublisherPid);return}
# An explicitly started bounded diagnostic must not race a second server.
foreach($p in @(Get-Process MonitorPublisher -ErrorAction SilentlyContinue)){
 try{if($p.Path -ieq (Join-Path $PSScriptRoot 'MonitorPublisher.exe')){throw 'A bounded publisher test is still active. End that test or restore the shell before switching modes.'}}finally{$p.Dispose()}
}
$nonce=[guid]::NewGuid().ToString('N')
$child=Start-NonUiProcess -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'Start-MonitorPublisherUntilStop.ps1'),'-Execute','-TargetPid',[string]$TargetPid,'-TargetBorn',[string]$TargetBorn) -RedirectStandardOutput (Join-Path $PSScriptRoot ('untilstop-'+$nonce+'.stdout.log')) -RedirectStandardError (Join-Path $PSScriptRoot ('untilstop-'+$nonce+'.stderr.log'))
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(40)
 do{
  Start-Sleep -Milliseconds 150
  $ready=Find-Publisher
  if($ready){Write-Output ('Monitor publisher works UntilStop, PID '+$ready.PublisherPid);return}
  if($child.HasExited){throw ('Publisher controller exited; see untilstop-'+$nonce+'.stderr.log')}
 }while([DateTime]::UtcNow -lt $deadline)
 & (Join-Path $PSScriptRoot 'Stop-MonitorPublisherUntilStop.ps1')|Out-Null
 throw 'Persistent monitor publisher did not become ready.'
}finally{$child.Dispose()}
