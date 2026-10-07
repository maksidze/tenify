param()
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
. (Join-Path $PSScriptRoot 'Launch-NonUiProcess.ps1')
. (Join-Path $PSScriptRoot 'Lab/DirectLaunchLifecycle/Lifecycle.ps1')
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
 foreach($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'state-direct') -Filter status.json -Recurse){
  if($file.Directory.Name -like 'preflight-*'){continue}
  $s=Read-DirectSharedJson $file.FullName
  if($s.status -eq 'running' -and !$s.preflight -and $s.pid -eq $owner -and $s.profile -eq 'host-dcomp-resource' -and $s.xamlQuirk -and $s.inputSwitchHook.stats.installed -eq 1){
   if($s.birthFileTime -and $p.StartTime.ToUniversalTime().ToFileTimeUtc() -eq [long]$s.birthFileTime){
    $debug=$false;if(![MaximumShell.Native]::CheckRemoteDebuggerPresent($p.Handle,[ref]$debug) -or $debug){throw 'Explorer still has a debugger attached.'}
    $current=($s.shellUXRevision -eq 12 -and $s.VFS -eq $false -and $s.directModuleGateVerified -and $s.pcsImageCount -eq 1 -and $s.usvfsModuleCount -eq 0 -and $s.themeMenuHook.Installed -and $s.hybridTheme10Hook.OldCurrentVerified -and $s.iconResourceHook.NoVFS -and $s.iconResourceHook.cacheKeyReadback -and $s.iconResourceHook.result -eq 0 -and $s.iconResourceHook.patches -gt 0)
    foreach($pair in @(@('NativeMenuSquareV2/MenuSquareV2.dll',$s.menuSquareHook.helperSHA256),@('IconRoutesNoVfsCompat/IconRoutes.NoVfs.dll',$s.iconResourceHook.helperSHA256),@('NativeThemeMenuCompat/ThemeMenuCompat.dll',$s.themeMenuHook.helperSHA256))){
     if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ('Lab/'+$pair[0]))).Hash -ine $pair[1]){$current=$false}
    }
    $pin=Join-Path $env:APPDATA 'Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/File Explorer.lnk'
    if((Test-Path -LiteralPath $pin) -and $s.taskbarPinSHA256 -ine (Get-FileHash -LiteralPath $pin).Hash){$current=$false}
    return @{Pid=$owner;BirthFileTime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();Path=$expected;DirectRun=$file.DirectoryName;Icons10=[bool]$s.icons10;CurrentShellUX=[bool]$current}
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
  $status=Read-DirectSharedJson (Join-Path $s.Directory 'status.json')
  $tick=[MaximumShell.Native]::GetTickCount64()
  if(!$status.UntilStop -or [uint64]$status.Tick -gt $tick -or $tick-[uint64]$status.Tick -gt 10000){throw 'Start controller status is stale.'}
  $old=Find-OldStart
  if(!$old -or !@($status.Instances|Where-Object {$_.Ready -and $_.Pid -eq $old.Pid -and [long]$_.Birth -eq [long]$old.BirthFileTime}).Count){throw 'Start session has no detached, ready old StartUI instance.'}
 }else{
  if($s.Mode -ne 'UntilStop' -or !$s.ContentCompat -or !$s.NavigationCompat -or $s.NoVFS -ne $true -or $s.XamlFactory -ne $true){throw 'Live Settings session configuration differs.'}
  $profileManifest=Join-Path $PSScriptRoot 'Lab/SettingsNoVfsXamlCompat/manifest.json'
  if(!$s.CurrentProfileManifest -or [IO.Path]::GetFullPath($s.CurrentProfileManifest) -ine [IO.Path]::GetFullPath($profileManifest)){throw 'Settings XAML profile differs.'}
  $recorded=@{};foreach($f in $s.Files){if($recorded.ContainsKey($f.Path) -and $recorded[$f.Path] -ine $f.SHA256){throw 'Conflicting Settings dependency pins.'};$recorded[$f.Path]=$f.SHA256}
  foreach($mf in @((Join-Path $lab 'manifest.json'),$profileManifest)){
   $m=Read-DirectSharedJson $mf
   foreach($f in $m.Files){if(!$recorded.ContainsKey($f.Path) -or $recorded[$f.Path] -ine $f.SHA256 -or (Get-FileHash -LiteralPath $f.Path).Hash -ine $f.SHA256){throw ('Current Settings dependency differs: '+$f.Path)}}
  }
  $selector=Join-Path $PSScriptRoot 'Lab/SettingsNoVfsXamlCompat/SettingsFactorySelectorXaml.dll'
  if(!$s.FactorySelector -or [IO.Path]::GetFullPath($s.FactorySelector) -ine [IO.Path]::GetFullPath($selector) -or (Get-FileHash -LiteralPath $selector).Hash -ine $s.FactorySelectorSHA256){throw 'Settings factory selector differs.'}
  $lease=Read-DirectSharedBytes -Path $s.LeaseFile -ExpectedLength 16
  if($lease.Length -ne 16){throw 'Malformed Settings lease.'}
  $expires=[BitConverter]::ToUInt64($lease,0);$born=[BitConverter]::ToUInt64($lease,8);$tick=[MaximumShell.Native]::GetTickCount64()
  if($born -ne [uint64]$s.Controller.Birth -or $expires -le $tick -or $expires -gt ($tick+20000)){throw 'Settings controller lease expired.'}
  if(!(Test-Path -LiteralPath (Join-Path $s.Directory 'enabled.json'))){throw 'Settings registration is not enabled.'}
 }
 return @{StatePath=$path;Controller=$s.Controller;Mode='UntilStop'}
}
$run=Join-Path $PSScriptRoot ('state-persistent-direct\'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($run)|Out-Null
$state=[ordered]@{Format=1;Mode='UntilStop';StartedUtc=[DateTime]::UtcNow.ToString('o');Status='starting';Explorer=$null;Stages=@();SettingsIncluded=$false;NoVFS=$true;SessionDeadline=$null;SystemFilesModified=$false;Logs=$run}
function Save-State {$state|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $run 'status.json') -Encoding UTF8}
function Stage([string]$name,[scriptblock]$action){
 $entry=[ordered]@{Name=$name;Status='running'}
 try{& $action|Out-Host;$entry.Status='ready'}catch{$entry.Status='failed';$entry.Error=$_.Exception.Message;Write-Warning ($name+': '+$entry.Error)}
 $script:state.Stages+=@($entry);Save-State
}
$mutex=New-Object Threading.Mutex($false,'Local\Windows10MaximumLaunch');$held=$false;$launchController=$null;$startup=$null;$launchCommitted=$false
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another bundle launch is active.'}
 Save-State
 $state.Explorer=Find-Explorer
 if(!$state.Explorer -or !$state.Explorer.CurrentShellUX){
  $startupPath=New-DirectStartup -Seconds 180;$startup=Open-DirectStartup $startupPath
  $state.StartupState=$startupPath;Save-State
  $launchController=Start-NonUiProcess -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'Start-Explorer10-Direct.ps1'),'-StartupState',$startupPath,'-Profile','host-dcomp-resource','-XamlQuirk','-Icons10','-HybridTheme10') -WorkingDirectory $PSScriptRoot -RedirectStandardOutput (Join-Path $run 'explorer.log') -RedirectStandardError (Join-Path $run 'explorer.err')
  $state.LaunchController=@{Pid=$launchController.Id;Birth=[string]$launchController.BirthFileTime};Save-State
  while(!(Test-Path -LiteralPath $startup.State.PreflightFile)){
   Assert-DirectStartup $startup
   if($launchController.HasExited){throw 'Direct launch controller ended before hidden preflight readiness.'}
   Start-Sleep -Milliseconds 100
  }
  Assert-DirectStartup $startup
  $preflight=Read-DirectSharedJson $startup.State.PreflightFile
  if($preflight.Version -ne 1 -or $preflight.Launcher.Pid -ne $launchController.Id -or [uint64]$preflight.Launcher.Birth -ne [uint64]$launchController.BirthFileTime -or $preflight.Launcher.Path -ine (Join-Path $PSHOME 'powershell.exe') -or !$preflight.OwnedJobDrained){throw 'Preflight came from a different launcher identity.'}
  $proofPath=[IO.Path]::GetFullPath($preflight.StatusFile);$proofDirectory=[IO.Path]::GetDirectoryName($proofPath)
  if([IO.Path]::GetFileName($proofPath) -ine 'status.json' -or [IO.Path]::GetDirectoryName($proofDirectory) -ine (Join-Path $PSScriptRoot 'state-direct') -or [IO.Path]::GetFileName($proofDirectory) -notlike 'preflight-*' -or (Get-FileHash -LiteralPath $proofPath).Hash -ine $preflight.StatusSHA256){throw 'Hidden preflight evidence path or hash differs.'}
  $proof=Read-DirectSharedJson $proofPath
  if($proof.status -ne 'preflight-pass' -or !$proof.preflight -or !$proof.ownedJobDrained -or $proof.VFS -ne $false -or $proof.pcsImageCount -ne 1 -or $proof.usvfsModuleCount -ne 0 -or $proof.pid -ne $preflight.PreflightPid -or [uint64]$proof.birthFileTime -ne [uint64]$preflight.PreflightBirth){throw 'Hidden preflight evidence is not a complete drained success.'}
  $state.Preflight=$preflight;Save-State
  Assert-DirectStartup $startup
  if($launchController.HasExited){throw 'Direct launch controller ended before companion cleanup.'}
  Write-Host 'Hidden preflight passed; stopping owned companion sessions before the shell transition.'
  # The parent owns MaximumLaunch; wrapper never calls this recursively.
  & (Join-Path $PSScriptRoot 'Stop-Windows10-DirectPersistent.ps1') -PreserveStartupState $startupPath|Out-Host
  # Optional migration of the old VFS Settings session only; no VFS dependency
  # is loaded or required for a native/direct session.
  $legacyMarker=Join-Path $PSScriptRoot 'Lab/SettingsUntilStopCompat/active-session.txt'
  if(Test-Path -LiteralPath $legacyMarker){
   $legacyPath=[IO.File]::ReadAllText($legacyMarker).Trim()
   if((Test-Path -LiteralPath $legacyPath) -and !(Test-Path -LiteralPath (Join-Path (Split-Path $legacyPath) 'restored.json'))){& (Join-Path $PSScriptRoot 'Lab/SettingsUntilStopCompat/Disable-Settings10-UntilStop.ps1')|Out-Host}
  }
  Assert-DirectStartup $startup
  if($launchController.HasExited){throw 'Direct launch controller ended before transition approval.'}
  Approve-DirectTransition $startup
  do{
   Assert-DirectStartup $startup
   if($launchController.HasExited){throw 'Direct launch controller ended before readiness.'}
   Start-Sleep -Milliseconds 150;$state.Explorer=Find-Explorer
  }while(!$state.Explorer -or !$state.Explorer.CurrentShellUX -or !(Test-Path -LiteralPath $startup.State.ReadyFile))
  $ready=Read-DirectSharedJson $startup.State.ReadyFile
  if($ready.Pid -ne $state.Explorer.Pid -or [long]$ready.Birth -ne [long]$state.Explorer.BirthFileTime -or $ready.RunDirectory -ine $state.Explorer.DirectRun){throw 'Startup ready identity differs from exact shell owner.'}
  Assert-DirectStartup $startup
  Commit-DirectStartup $startup;$launchCommitted=$true
  $launchController.Dispose();$launchController=$null
 }
 Save-State
 Stage 'Task View monitor publisher' {& (Join-Path $PSScriptRoot 'Lab\DisplayMonitorPublisher\Ensure-MonitorPublisherUntilStop.ps1') -TargetPid $state.Explorer.Pid -TargetBorn ([uint64]$state.Explorer.BirthFileTime)}
 Stage 'Repeatable Start 10' {
  $s=Read-Session 'StartSessionCompat'
  if(!$s){& (Join-Path $PSScriptRoot 'Lab\StartSessionCompat\Enable-Start10-Session.ps1') -UntilStop -TargetPid $state.Explorer.Pid|Out-Host;$s=Read-Session 'StartSessionCompat'}
  if(!$s){throw 'Start UntilStop readiness missing.'};$script:state.Start=$s
 }
 # The network visibility helper uses Settings package identity. On a fresh
 # bundle establish it before installing the Settings activation debugger.
 # Reusing an existing Settings session still requires its auxiliary bypass.
 Stage 'Windows 10 network tray handler' {& (Join-Path $PSScriptRoot 'Lab\NetworkTrayUntilStopCompat\Ensure-NetworkTrayUntilStop.ps1') -Execute -TargetPid $state.Explorer.Pid -TargetBorn ([uint64]$state.Explorer.BirthFileTime)}
 Stage 'Repeatable Settings 10 with content adapters' {
  $s=Read-Session 'SettingsNoVfsSessionCompat'
  if(!$s){& (Join-Path $PSScriptRoot 'Lab\SettingsNoVfsSessionCompat\Enable-Settings10-NoVFS.ps1')|Out-Host;$s=Read-Session 'SettingsNoVfsSessionCompat'}
  if(!$s){throw 'Settings UntilStop readiness missing.'};$script:state.Settings=$s;$script:state.SettingsIncluded=$true
 }
 $state.Status=if(@($state.Stages|Where-Object Status -eq 'failed').Count){'partial-or-failed'}else{'running'}
 Save-State
 Write-Host ('UntilStop bundle: '+$state.Status+'; logs: '+$run)
 if($state.Status -ne 'running'){throw 'Some persistent components failed; working components remain active. See status.json.'}
}catch{$state.Status='partial-or-failed';$state.Error=$_.Exception.Message;Save-State;throw}
finally{
 try{
  if($launchController){
   if(!$launchCommitted -and $startup){Cancel-DirectStartup $startup 'Persistent startup failed, timed out or was explicitly stopped'}
   try{if(!$launchController.WaitForExit(30000)){$launchController.Kill();if(!$launchController.WaitForExit(10000)){throw 'Exact direct launcher cleanup is still pending.'}}}finally{$launchController.Dispose()}
  }
 }finally{if($startup){$startup.Parent.Dispose()};if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
