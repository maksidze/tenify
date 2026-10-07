param([ValidateSet('Enable','Disable','Status')][string]$Mode='Status')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$earlyCancel=$null
# Cancelling an already published immutable session is safe without the launch
# lock: a pending UAC approval/readiness wait must not block this marker.
if($Mode -eq 'Disable'){
 $snapshot=Read-Json (Join-Path $data 'current.json')
 if($snapshot){
  if($snapshot.Session -notmatch '^[a-f0-9]{32}$' -or $snapshot.Config -ine (Join-Path $data ($snapshot.Session+'.config.json')) -or $snapshot.Path -ine (Join-Path $PSScriptRoot 'ElevatedCornerHost.exe')){throw 'Invalid early-stop session pointer.'}
  $pending=Validate-Config $snapshot.Config
  if($pending.Scope -ne 'AllHigh'){throw 'Production Stop does not cancel fixture sessions.'}
  if(!(Test-Path -LiteralPath $pending.Cancel)){[IO.File]::WriteAllText($pending.Cancel,'Early stop requested')}
  $earlyCancel=$pending.Session
 }
}
$mutex=New-Object Threading.Mutex($false,'Local\CodexElevatedCornersLaunchV1');$held=$false
try{
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true};if(!$held){if($Mode -eq 'Disable' -and $earlyCancel){Write-Output ('Cancellation queued for exact session '+$earlyCancel+'; startup owner will observe it.');return};throw 'Another elevated-corner command is active.'}
 $pointer=Join-Path $data 'current.json';$r=Read-Json $pointer;if($r){if($r.Session -notmatch '^[a-f0-9]{32}$' -or $r.Config -ine (Join-Path $data ($r.Session+'.config.json'))){throw 'Invalid current session pointer.'};$validated=Validate-Config $r.Config};$hostLease=Exact-Host $r
 if($Mode -eq 'Status'){$status=if($r){Read-Json (Join-Path $data ($r.Session+'.status.json'))};[pscustomobject]@{Active=($null -ne $hostLease);Session=$r.Session;Pid=$r.Pid;Status=$status.Status;Integrity=if($hostLease){$hostLease.Integrity}else{0};Journal=(Join-Path $data 'high-journal.json')}|ConvertTo-Json;return}
 if($Mode -eq 'Disable'){
  if($r){$c=Validate-Config $r.Config;if(!(Test-Path -LiteralPath $c.Cancel)){[IO.File]::WriteAllText($c.Cancel,'Stop requested')}}
  if($hostLease){if(!$hostLease.Wait(20000)){throw 'Exact high companion did not stop; no foreign/elevated process terminated.'};$done=Read-Json $c.Status;if((Journal-Count $c.Journal) -or ($done -and $done.Status -notin @('stopped','failed-restored'))){throw 'High restoration remains incomplete; journal retained.'};return}
  if((Journal-Count (Join-Path $data 'high-journal.json'))){if(!$r){throw 'Recovery config unavailable; journal preserved.'};$restore=[CornerAccess]::Elevate((Join-Path $PSScriptRoot 'ElevatedCornerHost.exe'),('--recover "'+$r.Config+'"'),$PSScriptRoot);try{if(!$restore.Wait(25000)){throw 'Elevated recovery still active.'};if((Journal-Count (Join-Path $data 'high-journal.json'))){throw 'Elevated recovery remains incomplete.'}}finally{$restore.Dispose()}}
  return
 }
 if($hostLease){Write-Output 'Elevated-only corner companion already active.';return}
 $session=[guid]::NewGuid().ToString('N');$path=Join-Path $data ($session+'.config.json');$cfg=@{Format=1;Session=$session;Scope='AllHigh';Cancel=(Join-Path $data ($session+'.cancel'));Status=(Join-Path $data ($session+'.status.json'));Journal=(Join-Path $data 'high-journal.json')};Write-Json $path $cfg
 # Publish cancellation target before UAC/child launch to make early Stop durable.
 $record=@{Session=$session;Pid=0;Birth='0';Path=(Join-Path $PSScriptRoot 'ElevatedCornerHost.exe');Config=$path};Write-Json $pointer $record
 try{$new=[CornerAccess]::Elevate($record.Path,('--run "'+$path+'"'),$PSScriptRoot)}catch{if(!(Test-Path -LiteralPath $cfg.Cancel)){[IO.File]::WriteAllText($cfg.Cancel,'Launch failed/cancelled')};throw}
 try{$record.Pid=$new.Pid;$record.Birth=[string]$new.Birth;Write-Json $pointer $record;$deadline=[DateTime]::UtcNow.AddSeconds(90);do{$s=Read-Json $cfg.Status;if($s.Status -eq 'running'){Write-Output ('High-only hidden controller started: '+$new.Pid);return};if($new.Wait(0)){throw 'Elevated companion exited before readiness.'};Start-Sleep -Milliseconds 150}while([DateTime]::UtcNow -lt $deadline);[IO.File]::WriteAllText($cfg.Cancel,'Startup timeout');throw 'Elevated companion readiness timeout.'}finally{$new.Dispose()}
}finally{if($hostLease){$hostLease.Dispose()};if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
