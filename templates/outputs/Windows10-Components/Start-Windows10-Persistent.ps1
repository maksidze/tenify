param()
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
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

$expected=Join-Path $PSScriptRoot 'Runtime\Explorer10\explorer.exe'
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
    $current=($s.shellUXRevision -eq 11 -and $s.themeMenuHook.Installed -and $s.hybridTheme10 -and $s.hybridTheme10Hook.Installed -and $s.hybridTheme10Hook.OldCurrentVerified -and $s.icons10 -and $s.classicContextHook.Installed -and $s.winXHook.stats.installed -eq 1 -and $s.menuSquareHook.installed -eq 1 -and $s.menuSquareHook.result -eq 0 -and $s.icons10Validation.stockOnly -eq $false -and $s.iconResourceHook.result -eq 0 -and $s.iconResourceHook.patches -gt 0)
    if($current){
     $current=($s.menuSquareHook.helperSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\MenuAppearanceCompatV2\MenuSquareV2.dll')).Hash)
    }
    if($current){
     $current=($s.classicContextHook.ManifestSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\ClassicContextMenuCompat\manifest.json')).Hash -and $s.winXHook.manifestSha256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\WinXCompat\manifest.json')).Hash -and $s.icons10Validation.manifestSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\IconResourceMaximum\manifest.json')).Hash -and $s.iconResourceHook.helperSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\IconResourceMaximum\IconRoutes.ChildSafe.dll')).Hash)
    }
    if($current){
     $current=($s.hybridTheme10Hook.helperSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\ThemeFolderHybridCompat\ThemeFolderHybrid.dll')).Hash -and $s.hybridTheme10Hook.manifestSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\HybridThemeBootstrap\manifest.json')).Hash)
    }
    if($current){
     $current=($s.themeMenuHook.helperSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\ThemeMenuCompat\ThemeMenuCompat.dll')).Hash -and $s.themeMenuHook.manifestSHA256 -ieq (Get-FileHash (Join-Path $PSScriptRoot 'Lab\ThemeMenuBootstrap\manifest.json')).Hash)
    }
    return @{Pid=$owner;BirthFileTime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();Path=$expected;VfsRun=$file.DirectoryName;Icons10=[bool]$s.icons10;CurrentShellUX=[bool]$current}
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

function Exact-Controller($identity){
 $p=Get-Process -Id $identity.Pid -ErrorAction SilentlyContinue
 if(!$p){return $false}
 try{return ($p.Path -ieq $identity.Path -and $p.StartTime.ToUniversalTime().ToFileTimeUtc() -eq [long]$identity.Birth)}finally{$p.Dispose()}
}
function Read-Session([string]$name){
 $lab=Join-Path $PSScriptRoot ('Lab\'+$name)
 $marker=Join-Path $lab 'active-session.txt'
 if(!(Test-Path -LiteralPath $marker)){return $null}
 $path=[IO.Path]::GetFullPath([IO.File]::ReadAllText($marker).Trim())
 if(!$path.StartsWith(([IO.Path]::GetFullPath((Join-Path $lab 'sessions'))+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Session pointer escaped owned directory.'}
 $s=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 if((Test-Path -LiteralPath $s.CancelFile) -or (Test-Path -LiteralPath (Join-Path $s.Directory 'restored.json'))){return $null}
 if(!(Exact-Controller $s.Controller)){return $null}
 if($name -eq 'StartSessionCompat'){
  if(!$s.UntilStop -or $s.Explorer.Pid -ne $state.Explorer.Pid -or [long]$s.Explorer.Birth -ne [long]$state.Explorer.BirthFileTime){throw 'Live Start session differs from required UntilStop shell.'}
  $status=Get-Content -LiteralPath (Join-Path $s.Directory 'status.json') -Raw|ConvertFrom-Json
  $tick=[MaximumShell.Native]::GetTickCount64()
  if(!$status.UntilStop -or [uint64]$status.Tick -gt $tick -or $tick-[uint64]$status.Tick -gt 10000){throw 'Start controller status is stale.'}
  $old=Find-OldStart
  if(!$old -or !@($status.Instances|Where-Object {$_.Ready -and $_.Pid -eq $old.Pid -and [long]$_.Birth -eq [long]$old.BirthFileTime}).Count){throw 'Start session has no detached, ready old StartUI instance.'}
 }else{
  if($s.Mode -ne 'UntilStop' -or !$s.ContentCompat -or !$s.NavigationCompat -or $s.Bootstrap -ine (Join-Path $PSScriptRoot 'Lab\SettingsContentCompat\SettingsContentCompat.dll')){throw 'Live Settings session configuration differs.'}
  $lease=[IO.File]::ReadAllBytes($s.LeaseFile)
  if($lease.Length -ne 16){throw 'Malformed Settings lease.'}
  $expires=[BitConverter]::ToUInt64($lease,0);$born=[BitConverter]::ToUInt64($lease,8);$tick=[MaximumShell.Native]::GetTickCount64()
  if($born -ne [uint64]$s.Controller.Birth -or $expires -le $tick -or $expires -gt ($tick+20000)){throw 'Settings controller lease expired.'}
  if(!(Test-Path -LiteralPath (Join-Path $s.Directory 'enabled.json'))){throw 'Settings registration is not enabled.'}
 }
 return @{StatePath=$path;Controller=$s.Controller;Mode='UntilStop'}
}
$run=Join-Path $PSScriptRoot ('state-persistent\'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($run)|Out-Null
$state=[ordered]@{Format=1;Mode='UntilStop';StartedUtc=[DateTime]::UtcNow.ToString('o');Status='starting';Explorer=$null;Stages=@();SettingsIncluded=$false;SessionDeadline=$null;SystemFilesModified=$false;Logs=$run}
function Save-State {$state|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $run 'status.json') -Encoding UTF8}
function Stage([string]$name,[scriptblock]$action){
 $entry=[ordered]@{Name=$name;Status='running'}
 try{& $action|Out-Host;$entry.Status='ready'}catch{$entry.Status='failed';$entry.Error=$_.Exception.Message;Write-Warning ($name+': '+$entry.Error)}
 $script:state.Stages+=@($entry);Save-State
}
$mutex=New-Object Threading.Mutex($false,'Local\Windows10MaximumLaunch');$held=$false
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another bundle launch is active.'}
 Save-State
 $state.Explorer=Find-Explorer
 if($state.Explorer -and !$state.Explorer.CurrentShellUX){
  Write-Host 'Restarting the verified laboratory Explorer to load the repaired private Windows 10 theme and existing shell components.'
  & (Join-Path $PSScriptRoot 'Stop-Windows10-Persistent.ps1')|Out-Host
  [IO.File]::WriteAllText((Join-Path $state.Explorer.VfsRun 'stop'),'Restart with shell UX revision 11 requested by persistent bundle')
  $until=[DateTime]::UtcNow.AddSeconds(40)
  do{
   Start-Sleep -Milliseconds 200
   $owner=[MaximumShell.Native]::Owner();$native=Get-Process -Id $owner -ErrorAction SilentlyContinue
   if($native -and $native.Path -ieq (Join-Path $env:WINDIR 'explorer.exe')){break}
  }while([DateTime]::UtcNow -lt $until)
  if(!$native -or $native.Path -ine (Join-Path $env:WINDIR 'explorer.exe')){throw 'Native Explorer recovery not confirmed before shell UX migration.'}
  $state.Explorer=$null
 }
 if(!$state.Explorer){
  $p=Start-NonUiProcess -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'Start-Explorer10-VFS.ps1'),'-Profile','host-dcomp-resource','-XamlQuirk','-Icons10','-HybridTheme10') -WorkingDirectory $PSScriptRoot -RedirectStandardOutput (Join-Path $run 'explorer.log') -RedirectStandardError (Join-Path $run 'explorer.err')
  $p.Dispose();$until=[DateTime]::UtcNow.AddSeconds(60)
  do{Start-Sleep -Milliseconds 250;$state.Explorer=Find-Explorer}while(!$state.Explorer -and [DateTime]::UtcNow -lt $until)
  if(!$state.Explorer -or !$state.Explorer.CurrentShellUX){throw 'Current compatible Explorer readiness was not confirmed.'}
 }
 Save-State
 Stage 'Task View monitor publisher' {& (Join-Path $PSScriptRoot 'Lab\DisplayMonitorPublisher\Ensure-MonitorPublisherUntilStop.ps1') -TargetPid $state.Explorer.Pid -TargetBorn ([uint64]$state.Explorer.BirthFileTime)}
 Stage 'Repeatable Start 10' {
  $s=Read-Session 'StartSessionCompat'
  if(!$s){& (Join-Path $PSScriptRoot 'Lab\StartSessionCompat\Enable-Start10-Session.ps1') -UntilStop -TargetPid $state.Explorer.Pid|Out-Host;$s=Read-Session 'StartSessionCompat'}
  if(!$s){throw 'Start UntilStop readiness missing.'};$script:state.Start=$s
 }
 Stage 'Repeatable Settings 10 with content adapters' {
  $s=Read-Session 'SettingsUntilStopCompat'
  if(!$s){& (Join-Path $PSScriptRoot 'Lab\SettingsUntilStopCompat\Enable-Settings10-UntilStop.ps1')|Out-Host;$s=Read-Session 'SettingsUntilStopCompat'}
  if(!$s){throw 'Settings UntilStop readiness missing.'};$script:state.Settings=$s;$script:state.SettingsIncluded=$true
 }
 Stage 'Windows 10 network tray handler' {& (Join-Path $PSScriptRoot 'Lab\NetworkTrayUntilStopCompat\Ensure-NetworkTrayUntilStop.ps1') -Execute -TargetPid $state.Explorer.Pid -TargetBorn ([uint64]$state.Explorer.BirthFileTime)}
 $state.Status=if(@($state.Stages|Where-Object Status -eq 'failed').Count){'partial-or-failed'}else{'running'}
 Save-State
 Write-Host ('UntilStop bundle: '+$state.Status+'; logs: '+$run)
 if($state.Status -ne 'running'){throw 'Some persistent components failed; working components remain active. See status.json.'}
}catch{$state.Status='partial-or-failed';$state.Error=$_.Exception.Message;Save-State;throw}
finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
