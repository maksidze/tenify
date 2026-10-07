param([ValidateSet('Enable','Disable','Status')][string]$Mode='Status',[ValidateRange(15,86400)][int]$Seconds=3600,[switch]$UntilStop,[int]$FixturePid=0,[string]$FixtureBirth,[string]$FixturePath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$currentPath=Join-Path $data 'current.json'
$launchMutex=New-Object Threading.Mutex($false,'Local\Windows10CornersLaunch')
$launchHeld=$false
try{
 $launchHeld=Lock-Mutex $launchMutex
 if(!$launchHeld){throw 'Another corner session command is in progress.'}
 $current=Read-Json $currentPath
 $status=if($current){Read-Json (Join-Path $data ($current.Session+'.status.json'))}else{$null}
 $live=Exact-Controller $current
 if($Mode -eq 'Status'){
  $count=@(Read-Journal).Count
  $shownStatus=if($live){$status.Status}elseif($count){'recovery-required'}else{'stopped'}
  [pscustomobject]@{Active=($null -ne $live);Session=$current.Session;ControllerPid=$current.Pid;Status=$shownStatus;SavedBaselines=$count;Journal=$journal}|ConvertTo-Json
  if($live){$live.Dispose()};return
 }
 if($Mode -eq 'Disable'){
  if($current){[IO.File]::WriteAllText($current.Cancel,'Stop requested')}
  if($live){try {if(!$live.WaitForExit(15000)){throw 'Exact controller has not exited; no forced termination performed.'}}finally{$live.Dispose()}}
  $m=New-JournalMutex;$h=$false
  try {$h=Lock-Mutex $m 1000;if(!$h){throw 'Journal is still owned; retry Stop after controller exit.'};Restore-Windows;if(@(Read-Journal).Count){throw 'Baseline restoration incomplete; journal retained.'}}
  finally {if($h){$m.ReleaseMutex()};$m.Dispose()}
  Write-Output 'Stopped; matching original corner preferences restored. Closed/reused/foreign windows skipped.';return
 }
 if($live){$live.Dispose();Write-Output 'A background corner session is already active; no duplicate started.';return}
 $m=New-JournalMutex;$h=$false
 try {$h=Lock-Mutex $m;if(!$h){throw 'Another controller owns the journal.'};Restore-Windows;if(@(Read-Journal).Count){throw 'Recover the existing journal before starting.'}}
 finally {if($h){$m.ReleaseMutex()};$m.Dispose()}
 $id=[guid]::NewGuid().ToString('N');$config=Join-Path $data ($id+'.config.json')
 $scope=if($FixturePid){'Fixture'}else{'AllVisible'}
 $cfg=@{Format=1;Session=$id;Cancel=(Join-Path $data ($id+'.cancel'));Scope=$scope;UntilStop=[bool]$UntilStop;DeadlineUtc=[DateTime]::UtcNow.AddSeconds($Seconds).ToString('o');TargetPid=$FixturePid;TargetBirth=$FixtureBirth;TargetPath=$FixturePath}
 Write-AtomicJson $config $cfg
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $p=Start-NonUiProcess -FilePath $ps -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'Controller.ps1'),'-Config',$config) -RedirectStandardOutput (Join-Path $data ($id+'.log')) -RedirectStandardError (Join-Path $data ($id+'.err')) -WorkingDirectory $PSScriptRoot
 try {
  $r=@{Session=$id;Pid=$p.Id;BirthFileTime=[string]$p.BirthFileTime;Path=$ps;Config=$config;Cancel=$cfg.Cancel}
  Write-AtomicJson $currentPath $r
  $until=[DateTime]::UtcNow.AddSeconds(15)
  do {$s=Read-Json (Join-Path $data ($id+'.status.json'));if($s -and $s.Status -eq 'running' -and [string]$s.BirthFileTime -eq [string]$r.BirthFileTime){Write-Output ('Hidden corner controller started: '+$p.Id);return};if($p.HasExited){throw ('Controller exited '+$p.ExitCode)};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $until)
  [IO.File]::WriteAllText($cfg.Cancel,'Startup timeout');throw 'Controller readiness timed out; cancellation recorded.'
 }finally{$p.Dispose()}
}finally{if($launchHeld){$launchMutex.ReleaseMutex()};$launchMutex.Dispose()}
