from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parent.parent
base=root/'outputs/Windows10-Components'
def write(path,text): path.write_text(text,encoding='utf-8-sig')
old=(base/'Start-Windows10-Maximum.ps1').read_text(encoding='utf-8-sig')
native=old[old.index("if(-not ('MaximumShell.Native'"):old.index("$ps=Join-Path")]
functions=old[old.index('function Find-Explorer'):old.index('function Find-SettingsSession')]
text=r'''param()
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
. (Join-Path $PSScriptRoot 'Launch-NonUiProcess.ps1')
'''+native+r'''
$expected=Join-Path $PSScriptRoot 'Runtime\Explorer10\explorer.exe'
'''+functions+r'''
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
 if(!$state.Explorer){
  $p=Start-NonUiProcess -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'Start-Explorer10-VFS.ps1'),'-Profile','host-dcomp-resource','-XamlQuirk') -WorkingDirectory $PSScriptRoot -RedirectStandardOutput (Join-Path $run 'explorer.log') -RedirectStandardError (Join-Path $run 'explorer.err')
  $p.Dispose();$until=[DateTime]::UtcNow.AddSeconds(60)
  do{Start-Sleep -Milliseconds 250;$state.Explorer=Find-Explorer}while(!$state.Explorer -and [DateTime]::UtcNow -lt $until)
  if(!$state.Explorer){throw 'Compatible Explorer readiness was not confirmed.'}
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
'''
write(base/'Start-Windows10-Persistent.ps1',text)
write(base/'Stop-Windows10-Persistent.ps1',r'''$ErrorActionPreference='Stop'
$errorsFound=@()
$actions=@(
 @('Lab\SettingsUntilStopCompat\active-session.txt','Lab\SettingsUntilStopCompat\Disable-Settings10-UntilStop.ps1'),
 @('Lab\StartSessionCompat\active-session.txt','Lab\StartSessionCompat\Stop-Start10-Session.ps1'),
 @('Lab\NetworkTrayUntilStopCompat\active-network-session.txt','Lab\NetworkTrayUntilStopCompat\Stop-NetworkTrayUntilStop.ps1'),
 @('Lab\DisplayMonitorPublisher\untilstop-current-state.txt','Lab\DisplayMonitorPublisher\Stop-MonitorPublisherUntilStop.ps1'))
foreach($a in $actions){if(Test-Path -LiteralPath (Join-Path $PSScriptRoot $a[0])){try{& (Join-Path $PSScriptRoot $a[1])|Out-Host}catch{$errorsFound+=@($_.Exception.Message);Write-Warning $_.Exception.Message}}}
if($errorsFound.Count){throw ($errorsFound -join '; ')}
''')
# Preserve explicit bounded diagnostics, change normal/default launch.
marker="$ErrorActionPreference='Stop'"
old=old.replace(marker,marker+"\nif(!$PSBoundParameters.ContainsKey('Seconds')){& (Join-Path $PSScriptRoot 'Start-Windows10-Persistent.ps1');return}",1)
write(base/'Start-Windows10-Maximum.ps1',old)
stop=base/'Stop-Windows10-Maximum.ps1'
t=stop.read_text(encoding='utf-8-sig').replace("$persistentSettings=", "& (Join-Path $PSScriptRoot 'Stop-Windows10-Persistent.ps1')\n$persistentSettings=",1)
write(stop,t)
write(base/'Start-Windows10-Current.ps1',"& (Join-Path $PSScriptRoot 'Windows10-OneClick.ps1') -Mode Start\n")
for name in ['Start-Windows10-Maximum.bat','Start-Windows10-Maximum-WithSettings.bat']:
 (base/name).write_text('@echo off\nsetlocal\n"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Windows10-OneClick.ps1" -Mode Start\nif errorlevel 1 pause\n',encoding='utf8')
p=base/'Windows10-OneClick.ps1';t=p.read_text(encoding='utf-8-sig')
t=t.replace(",[ValidateRange(60,3600)][int]$Seconds=3600",'')
t=t.replace("Version='oneclick-02'","Version='oneclick-03'").replace('Seconds=$Seconds','Lifetime=\'UntilStop\'')
t=t.replace("'Start-Windows10-Maximum.ps1','Stop-Windows10-Maximum.ps1'","'Start-Windows10-Persistent.ps1','Stop-Windows10-Persistent.ps1','Stop-Windows10-Maximum.ps1'")
t=t.replace("'Lab\\StartCompat\\Test-BrokerStartCompat.ps1'","'Lab\\StartSessionCompat\\Enable-Start10-Session.ps1','Lab\\StartSessionCompat\\Start10SessionDebugger.exe'")
t=t.replace('Lab\\DisplayMonitorPublisher\\Start-MonitorPublisher.ps1','Lab\\DisplayMonitorPublisher\\Ensure-MonitorPublisherUntilStop.ps1').replace('Lab\\DisplayMonitorPublisher\\MonitorPublisher.exe','Lab\\DisplayMonitorPublisher\\MonitorPublisherUntilStop.exe')
t=t.replace('Lab\\SettingsSessionCompat\\','Lab\\SettingsUntilStopCompat\\').replace('Settings10SessionDebugger.exe','Settings10UntilStopDebugger.exe')
t=t.replace('Lab\\NetworkTrayCompat\\Ensure-NetworkTray.ps1','Lab\\NetworkTrayUntilStopCompat\\Ensure-NetworkTrayUntilStop.ps1').replace('Lab\\NetworkTrayCompat\\NetworkTrayHost.exe','Lab\\NetworkTrayUntilStopCompat\\NetworkTrayUntilStop.exe')
start=t.index("  Write-Host 'Start, monitor publisher")
end=t.index("  Run-Stage 'Square window corners'",start)
t=t[:start]+r'''  Write-Host 'Components run until explicit Stop, sign-out or owner shutdown. Bootstrap watchdogs remain finite.'
  $maximumRoot=Join-Path $ComponentRoot 'state-persistent'
  $before=@(if(Test-Path -LiteralPath $maximumRoot){Get-ChildItem -LiteralPath $maximumRoot -Directory|ForEach-Object Name})
  Run-Stage 'Explorer 10, Start 10, Settings 10, Task View and network UntilStop' {& (Join-Path $ComponentRoot 'Start-Windows10-Persistent.ps1')}
  $created=@(Get-ChildItem -LiteralPath $maximumRoot -Directory -ErrorAction SilentlyContinue|Where-Object {$_.Name -notin $before -and $_.Name -match '^[0-9a-f]{32}$'})
  if($created.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $created[0].FullName 'status.json'))){
   $report.MaximumState=Join-Path $created[0].FullName 'status.json'
   $maximum=Get-Content -LiteralPath $report.MaximumState -Raw -Encoding UTF8|ConvertFrom-Json
   if($maximum.Status -ne 'running' -or !$maximum.SettingsIncluded){$failed=$true;Write-Warning 'Some persistent components were not enabled; inspect component status.json.'}
  }else{$failed=$true;Write-Warning 'A unique persistent readiness report was not found.'}
'''+t[end:]
# Check all persistent manifests, not only Settings.
start=t.index('  $manifest=Get-Content')
end=t.index('\n }\n if($Mode',start)
t=t[:start]+r'''  foreach($relative in @('Lab\SettingsUntilStopCompat\manifest.json','Lab\StartSessionCompat\manifest.json','Lab\NetworkTrayUntilStopCompat\manifest.json','Lab\DisplayMonitorPublisher\untilstop-manifest.json')){
   $manifest=Get-Content -LiteralPath (Join-Path $ComponentRoot $relative) -Raw -Encoding UTF8|ConvertFrom-Json
   foreach($item in $manifest.Files){if((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash -ine $item.SHA256){throw ('Dependency changed: '+$item.Path)}}
  }'''+t[end:]
write(p,t)
# Refresh only known edited launcher entries in bounded manifest; binary hashes stay unchanged.
p=base/'Lab/SettingsSessionCompat/manifest.json';m=json.loads(p.read_text(encoding='utf-8-sig'))
changed={base/n for n in ['Start-Windows10-Maximum.ps1','Stop-Windows10-Maximum.ps1','Start-Windows10-Maximum-WithSettings.bat']}
for item in m['Files']:
 if Path(item['Path']) in changed:item['SHA256']=hashlib.sha256(Path(item['Path']).read_bytes()).hexdigest()
p.write_text(json.dumps(m,indent=2),encoding='utf8')
print('Persistent entry points integrated; no activation performed')
