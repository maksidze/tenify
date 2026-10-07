param([switch]$Execute,[uint32]$TargetPid,[uint64]$TargetBorn,[ValidateRange(15,90)][int]$BootstrapSeconds=30)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Windows PowerShell 5 Desktop required.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
$startup=New-Object Threading.Mutex($false,'Local\NetworkTrayUntilStopStartup')
$held=$false
try{
 try{$held=$startup.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another network helper startup is active.'}
$manifestPath=Join-Path $PSScriptRoot 'manifest.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
foreach($item in $manifest.Files){if((Get-FileHash -LiteralPath $item.Path).Hash.ToLowerInvariant() -ne $item.SHA256){throw ('Build changed: '+$item.Path)}}
. (Join-Path $PSScriptRoot 'NetworkTrayState.ps1')
$owned=Read-OwnedNetworkState ''
if($owned -and $owned.Process){
 try{
  $state=$owned.State
  if($state.TargetPid -ne $TargetPid -or [uint64]$state.TargetBorn -ne $TargetBorn -or $state.ManifestSHA256 -ne (Get-FileHash -LiteralPath $manifestPath).Hash){throw 'Existing persistent helper configuration differs; stop explicitly before replacement.'}
  $controller=[Diagnostics.Process]::GetProcessById([int]$state.ControllerPid)
  try{$handle=$controller.Handle;if([uint64]$controller.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [uint64]$state.ControllerBorn -or $controller.MainModule.FileName -ne $state.ControllerPath){throw 'Controller identity differs.'}}finally{$controller.Dispose()}
  if(!$owned.Ready -or $owned.StopRequested){throw 'Existing network helper is starting/stopping, not ready.'}
  if($Execute){& (Join-Path $PSScriptRoot '..\NetworkTrayVisibilityCompat\Set-NetworkVisibility.ps1') -Action Promote}
  Write-Output ('Reused UntilStop network helper PID '+$state.ChildPid+'; visual status unverified');return
 }finally{$owned.Process.Dispose()}
}
if(!$Execute){Write-Output 'UntilStop preflight passed. No icon/component was started.';return}
# Refuse concurrent old bounded host; never silently replace an existing helper.
$bounded=Join-Path $PSScriptRoot '..\NetworkTrayCompat\active-network-session.txt'
if(Test-Path -LiteralPath $bounded){$record=[IO.File]::ReadAllText($bounded).Trim();$oldLab=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\NetworkTrayCompat'));if([IO.Path]::GetDirectoryName($record) -ne $oldLab){throw 'Old bounded record is outside its directory.'};$old=Get-Content -LiteralPath $record -Raw|ConvertFrom-Json;$p=$null;try{$p=[Diagnostics.Process]::GetProcessById([int]$old.ChildPid);if([uint64]$p.StartTime.ToUniversalTime().ToFileTimeUtc() -eq [uint64]$old.ChildBorn -and $p.MainModule.FileName -eq (Join-Path $oldLab 'NetworkTrayHost.exe')){throw 'Bounded network helper still active; stop it explicitly first.'}}catch [ArgumentException]{}finally{if($p){$p.Dispose()}}}
$pointer=Join-Path $PSScriptRoot 'active-network-session.txt'
if(Test-Path -LiteralPath $pointer){Remove-Item -LiteralPath $pointer} # Verified prior record has no live child.
$controllerInfo=New-Object Diagnostics.ProcessStartInfo
$controllerInfo.FileName=Join-Path $PSHOME 'powershell.exe'
$script=Join-Path $PSScriptRoot 'Run-NetworkTrayUntilStop.ps1'
$controllerInfo.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$script+'" -Execute -TargetPid '+$TargetPid+' -TargetBorn '+$TargetBorn+' -BootstrapSeconds '+$BootstrapSeconds
$controllerInfo.UseShellExecute=$false;$controllerInfo.CreateNoWindow=$true
$controller=[Diagnostics.Process]::Start($controllerInfo)
try{
 $deadline=[DateTime]::UtcNow.AddSeconds($BootstrapSeconds+12)
 while([DateTime]::UtcNow -lt $deadline){
  if($controller.HasExited){throw ('Owned network controller exited '+$controller.ExitCode)}
  if(Test-Path -LiteralPath $pointer){$now=Read-OwnedNetworkState '';if($now){try{if($now.Process -and $now.Ready){& (Join-Path $PSScriptRoot '..\NetworkTrayVisibilityCompat\Set-NetworkVisibility.ps1') -Action Promote;Write-Output ('UntilStop network lifecycle ready PID '+$now.State.ChildPid+'; visual icon unverified');return}}finally{if($now.Process){$now.Process.Dispose()}}}}
  Start-Sleep -Milliseconds 100
 }
 throw 'Finite network bootstrap deadline elapsed.'
}catch{
 # Only the process we just created is stopped; closing its job stops its own child.
 if(!$controller.HasExited){$controller.Kill();$controller.WaitForExit(5000)|Out-Null}
 throw
}finally{$controller.Dispose()}

}finally{if($held){$startup.ReleaseMutex()};$startup.Dispose()}
