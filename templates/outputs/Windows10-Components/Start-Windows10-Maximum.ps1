param([ValidateRange(60,3600)][int]$Seconds=3600,[switch]$IncludeSettings10)
$ErrorActionPreference='Stop'
if(!$PSBoundParameters.ContainsKey('Seconds')){& (Join-Path $PSScriptRoot 'Start-Windows10-Persistent.ps1');return}
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
. (Join-Path $PSScriptRoot 'Launch-NonUiProcess.ps1')
if(-not ('MaximumShell.Native' -as [type])){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
namespace MaximumShell { public static class Native {
 [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 public static uint Owner(){uint p;GetWindowThreadProcessId(GetShellWindow(),out p);return p;}
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CheckRemoteDebuggerPresent(IntPtr p,out bool present);
 [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
}}
'@
}
$ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$expected=Join-Path $PSScriptRoot 'Runtime\Explorer10\explorer.exe'
$stateRoot=Join-Path $PSScriptRoot 'state-maximum'
[IO.Directory]::CreateDirectory($stateRoot)|Out-Null
$id=[guid]::NewGuid().ToString('N')
$run=Join-Path $stateRoot $id
[IO.Directory]::CreateDirectory($run)|Out-Null
$state=[ordered]@{Format=1;StartedUtc=[DateTime]::UtcNow.ToString('o');Seconds=$Seconds;Status='starting';Explorer=$null;PublisherController=$null;StartController=$null;SettingsIncluded=$false;SettingsRequested=[bool]$IncludeSettings10;Settings=$null;SettingsController=$null;Logs=$run}
function Save-State {$state|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $run 'status.json') -Encoding UTF8}
function Launch-Controller([string]$script,[string[]]$extra,[string]$name){
 $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$script)+$extra
 $p=Start-NonUiProcess -FilePath $ps -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -RedirectStandardOutput (Join-Path $run ($name+'.stdout.log')) -RedirectStandardError (Join-Path $run ($name+'.stderr.log'))
 $result=@{Pid=$p.Id;BirthFileTime=[string]$p.BirthFileTime;Script=$script}
 $p.Dispose();return $result
}
function Find-Explorer {
 $owner=[MaximumShell.Native]::Owner();if(!$owner){return $null}
 $p=Get-Process -Id $owner -ErrorAction SilentlyContinue
 if(!$p -or $p.Path -ine $expected){return $null}
 foreach($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'state-vfs') -Filter status.json -Recurse){
  $s=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json
  if($s.status -eq 'running' -and !$s.preflight -and $s.pid -eq $owner -and $s.profile -eq 'host-dcomp-resource' -and $s.xamlQuirk -and $s.inputSwitchHook.stats.installed -eq 1){
   $recorded=[DateTime]::Parse($s.createdAt).ToUniversalTime()
   if([Math]::Abs(($p.StartTime.ToUniversalTime()-$recorded).TotalSeconds) -lt 10){
    $debug=$false;if(![MaximumShell.Native]::CheckRemoteDebuggerPresent($p.Handle,[ref]$debug) -or $debug){throw 'Explorer still has a debugger attached.'}
    return @{Pid=$owner;BirthFileTime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();Path=$expected;VfsRun=$file.DirectoryName}
   }
  }
 }
 return $null
}
function Find-OldStart {
 $oldDll=Join-Path $PSScriptRoot 'Lab\StartCompat\StartUI_.dll'
 foreach($p in @(Get-Process StartMenuExperienceHost -ErrorAction SilentlyContinue)){
  try {
   if(@($p.Modules|Where-Object {$_.FileName -ieq $oldDll}).Count){
    $debug=$false;if([MaximumShell.Native]::CheckRemoteDebuggerPresent($p.Handle,[ref]$debug) -and !$debug){return @{Pid=$p.Id;BirthFileTime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();OldStartUI=$oldDll;DebuggerPresent=$false}}
   }
  }catch{continue}
 }
 return $null
}
function Find-SettingsSession {
 $lab=Join-Path $PSScriptRoot 'Lab\SettingsSessionCompat'
 $marker=Join-Path $lab 'active-session.txt'
 if(!(Test-Path -LiteralPath $marker)){return $null}
 try {
  $path=[IO.Path]::GetFullPath([IO.File]::ReadAllText($marker).Trim())
  $allowed=[IO.Path]::GetFullPath((Join-Path $lab 'sessions'))+'\'
  if(!$path.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){return $null}
  $s=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
  if(!$s.NavigationCompat -or !$s.ContentCompat -or $s.Bootstrap -ine (Join-Path $PSScriptRoot 'Lab\SettingsContentCompat\SettingsContentCompat.dll') -or $s.NativePath -ine (Join-Path $env:WINDIR 'ImmersiveControlPanel\SystemSettings.exe')){return $null}
  if((Test-Path -LiteralPath $s.CancelFile) -or (Test-Path -LiteralPath (Join-Path $s.Directory 'restored.json')) -or !(Test-Path -LiteralPath (Join-Path $s.Directory 'enabled.json')) -or [uint64]$s.DeadlineTick -le [MaximumShell.Native]::GetTickCount64()){return $null}
  $p=Get-Process -Id $s.Controller.Pid -ErrorAction SilentlyContinue
  if(!$p -or $p.Path -ine $s.Controller.Path -or $p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$s.Controller.Birth){return $null}
  return @{Status='enabled';StatePath=$path;Controller=$s.Controller;DeadlineTick=[string]$s.DeadlineTick;NavigationCompat=$s.NavigationCompat;ActivationPerformed=$false}
 }catch{return $null}
}
$mutex=New-Object Threading.Mutex($false,'Local\Windows10MaximumLaunch');$held=$false
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another maximum-profile startup is still in progress.'}
 Save-State
 $state.Explorer=Find-Explorer
 if(!$state.Explorer){
  $state.ExplorerController=Launch-Controller (Join-Path $PSScriptRoot 'Start-Explorer10-VFS.ps1') @('-Profile','host-dcomp-resource','-XamlQuirk') 'explorer'
  Save-State;$until=[DateTime]::UtcNow.AddSeconds(60)
  do {Start-Sleep -Milliseconds 250;$state.Explorer=Find-Explorer}while(!$state.Explorer -and [DateTime]::UtcNow -lt $until)
  if(!$state.Explorer){throw 'Compatible Explorer readiness was not confirmed. See run logs.'}
 }
 # Reuse a currently running, exact laboratory publisher only for this shell.
 $publisherPath=Join-Path $PSScriptRoot 'Lab\DisplayMonitorPublisher\MonitorPublisher.exe'
 $publisherIdentityPattern='(?:^|\s)"?'+$state.Explorer.Pid+'"?\s+"?'+$state.Explorer.BirthFileTime+'"?(?:\s|$)'
 $existing=@(Get-CimInstance Win32_Process -Filter "Name='MonitorPublisher.exe'"|Where-Object {$_.ExecutablePath -ieq $publisherPath -and $_.CommandLine -match $publisherIdentityPattern})
 if(!$existing.Count){
  $state.PublisherController=Launch-Controller (Join-Path $PSScriptRoot 'Lab\DisplayMonitorPublisher\Start-MonitorPublisher.ps1') @('-Execute','-TargetPid',[string]$state.Explorer.Pid,'-TargetBorn',$state.Explorer.BirthFileTime,'-Seconds',[string]$Seconds) 'monitors'
 }else{$state.PublisherReused=@($existing.ProcessId)}
 $state.Start=Find-OldStart
 if(!$state.Start){$state.StartController=Launch-Controller (Join-Path $PSScriptRoot 'Lab\StartCompat\Test-BrokerStartCompat.ps1') @('-Seconds',[string]$Seconds,'-DetachAfterBootstrap') 'start'}
 Save-State
 $until=[DateTime]::UtcNow.AddSeconds(70)
 do {
  $state.Start=Find-OldStart
  $publisher=@(Get-CimInstance Win32_Process -Filter "Name='MonitorPublisher.exe'"|Where-Object {$_.ExecutablePath -ieq $publisherPath -and $_.CommandLine -match $publisherIdentityPattern})
  if($state.Start -and $publisher.Count){break}
  Start-Sleep -Milliseconds 500
 }while([DateTime]::UtcNow -lt $until)
 if(!$state.Start){throw 'Old Start UI was not confirmed. Explorer remains active; inspect start logs.'}
 if(!$publisher.Count){throw 'Monitor publisher did not remain active; inspect monitor logs.'}
 $state.PublisherPid=@($publisher.ProcessId);$state.Status='running';Save-State
 if($IncludeSettings10){
  # Settings is opt-in and cannot roll back an already working shell.
  try {
   $state.Settings=Find-SettingsSession
   if($state.Settings){$state.Settings.Status='enabled-reused'}else{
    $state.SettingsController=Launch-Controller (Join-Path $PSScriptRoot 'Enable-Settings10-VFS.ps1') @('-Seconds',[string]$Seconds) 'settings'
    $until=[DateTime]::UtcNow.AddSeconds(25)
    do {
     $state.Settings=Find-SettingsSession
     if($state.Settings){break}
     $helper=Get-Process -Id $state.SettingsController.Pid -ErrorAction SilentlyContinue
     if(!$helper -or $helper.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$state.SettingsController.BirthFileTime){break}
     Start-Sleep -Milliseconds 200
    }while([DateTime]::UtcNow -lt $until)
    if(!$state.Settings){throw 'Settings10 session was not enabled. Close native Settings and retry Enable-Settings10-VFS; see settings.stderr.log.'}
   }
   $state.SettingsIncluded=$true
  }catch{
   $state.Settings=@{Status='partial-settings-not-enabled';Error=$_.Exception.Message}
   $state.Status='running-with-settings-partial'
   Write-Warning ($state.Settings.Error+' Explorer/Start remain active; no Settings process was killed.')
  }
  Save-State
 }
 Write-Host ('Explorer10 PID '+$state.Explorer.Pid+'; old Start UI PID '+$state.Start.Pid+'. Monitor publisher active.')
 Write-Host ('Guarded Start and monitor session: up to '+$Seconds+' seconds.')
 if($state.SettingsIncluded){Write-Host ('Repeat Settings10 VFS mode: '+$state.Settings.Status+'. No Settings window was opened by this launcher.')}elseif(!$IncludeSettings10){Write-Host 'Settings10 VFS remains a separate opt-in experiment.'}
 Write-Host ('Logs: '+$run)
}catch{$state.Status='partial-or-failed';$state.Error=$_.Exception.Message;Save-State;throw}
finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
