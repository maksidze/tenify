$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
. (Join-Path $script:DirectLifecycleBase 'Launch-NonUiProcess.ps1')
$root=Join-Path $PSScriptRoot ('fixtures/'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
$results=@();$leases=@()
function Await-File([string]$Path){$until=[DateTime]::UtcNow.AddSeconds(12);while(!(Test-Path -LiteralPath $Path)){if([DateTime]::UtcNow -ge $until){throw ('Fixture file timeout '+$Path)};Start-Sleep -Milliseconds 25}}
foreach($test in 'ordinary-dispose','owner-death','nested-preflight','live-breakaway-dispose','live-breakaway-owner-death','cancel','deadline'){
 $dir=Join-Path $root $test;[IO.Directory]::CreateDirectory($dir)|Out-Null
 $worker=$null;$identities=@();$lease=$null
 try{
  $mode=if($test -like 'live-*'){'controller'}elseif($test -eq 'nested-preflight'){'preflight-controller'}elseif($test -in @('cancel','deadline')){'cancel'}else{'tree'}
  $args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'FixtureWorker.ps1'),'-Directory',$dir,'-Mode',$mode)
  if($mode -eq 'cancel'){$path=New-DirectStartup -Seconds $(if($test -eq 'deadline'){8}else{30});$lease=Open-DirectStartup $path;$leases+=@($lease);$args+=@('-StartupState',$path)}
  $worker=Start-NonUiProcess -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $args -RedirectStandardOutput (Join-Path $dir 'stdout') -RedirectStandardError (Join-Path $dir 'stderr')
  Await-File (Join-Path $dir 'worker-ready.json');Await-File (Join-Path $dir 'user.json');Await-File (Join-Path $dir 'explorer.json')
  foreach($name in @('worker-ready.json','explorer.json','user.json')){
   $r=Get-Content -LiteralPath (Join-Path $dir $name) -Raw|ConvertFrom-Json
   $identities+=@([DirectLaunchLifecycle.Identity]::Open([uint32]$r.Pid,[uint64]$r.Birth,$r.Path,$true))
   if($r.Console){throw 'Own fixture unexpectedly owns a console.'}
  }
  if($test -like '*owner-death'){$worker.Kill()}
  elseif($test -eq 'cancel'){Cancel-DirectStartup $lease 'Own cancellation fixture'}
  elseif($test -ne 'deadline'){[IO.File]::WriteAllText((Join-Path $dir 'finish'),'Own graceful dispose')}
  if(!$worker.WaitForExit(15000)){throw 'Own worker did not terminate.'}
  foreach($identity in $identities[0..1]){if(!$identity.Wait(5000)){throw 'Owned controller/fake Explorer survived job cleanup.'}}
  $survived=$identities[2].Alive
  if($test -like 'live-*'){
   if(!$survived){throw 'Fake user app was incorrectly killed with Explorer.'}
   $identities[2].Stop();if(!$identities[2].Wait(5000)){throw 'Own user fixture cleanup failed.'}
  }elseif($survived){throw 'Preflight descendant survived subtree job cleanup.'}
  $results+=@(@{Test=$test;Passed=$true;UserSurvived=$survived;ControllerBirth=[string]$worker.BirthFileTime;ConsoleCreated=$false})
 }finally{
  foreach($identity in $identities){try{if($identity.Alive){$identity.Stop();[void]$identity.Wait(5000)}}finally{$identity.Dispose()}}
  if($worker){if(!$worker.HasExited){$worker.Kill();[void]$worker.WaitForExit(5000)};$worker.Dispose()}
 }
}
# Exact birth must refuse a live but mismatched process; no PID-only ownership.
$mine=[DirectLaunchLifecycle.Identity]::Open([uint32]$PID,0,$null,$false)
try{$refused=$false;try{$bad=[DirectLaunchLifecycle.Identity]::Open([uint32]$PID,($mine.Birth+1),$mine.Path,$false);$bad.Dispose()}catch{$refused=$true};if(!$refused){throw 'Wrong birth accepted'};$results+=@(@{Test='wrong-parent-birth';Passed=$true})}finally{$mine.Dispose()}
# A committed lease has no total lifetime deadline. Cancellation still wins.
$path=New-DirectStartup -Seconds 1;$lease=Open-DirectStartup $path;$leases+=@($lease)
[IO.File]::WriteAllText($lease.State.CommitFile,'Own fixture committed');Start-Sleep -Milliseconds 1100;Assert-DirectStartup $lease
Cancel-DirectStartup $lease 'Own cancel overrides commit';$refused=$false;try{Assert-DirectStartup $lease}catch{$refused=$true};if(!$refused){throw 'Committed cancellation not observed'}
$results+=@(@{Test='commit-removes-deadline-cancel-still-wins';Passed=$true})
$actionMarker=Join-Path $root 'late-action-must-not-exist'
$refused=$false;try{Invoke-DirectStartupTransition $lease {[IO.File]::WriteAllText($actionMarker,'BAD')}}catch{$refused=$true}
if(!$refused -or (Test-Path -LiteralPath $actionMarker)){throw 'Cancelled transition executed its mutation.'}
$results+=@(@{Test='cancelled-transition-refuses-side-effect';Passed=$true})
# Hold a shared reader open across genuine atomic producer replacement.
$writer=$null;$heldRead=$null;$leaseFile=Join-Path $root 'shared-lease.bin'
[IO.File]::WriteAllBytes($leaseFile,(New-Object byte[] 16))
try{
 $heldRead=[IO.File]::Open($leaseFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
 $writer=Start-DirectOwnedJob -FilePath ('@PYTHON_DIR@\python.exe') -ArgumentList @((Join-Path $PSScriptRoot 'LeaseWriter.py'),$leaseFile) -RedirectStandardOutput (Join-Path $root 'writer.out') -RedirectStandardError (Join-Path $root 'writer.err')
 Await-File ($leaseFile+'.attempt');Start-Sleep -Milliseconds 50;$heldRead.Dispose();$heldRead=$null
 for($i=0;$i -lt 200;$i++){$bytes=Read-DirectSharedBytes $leaseFile 16;if($bytes.Length -ne 16){throw 'Torn shared lease.'};Start-Sleep -Milliseconds 2}
 if(!$writer.WaitForExit(5000) -or $writer.ExitCode -ne 0){throw 'Atomic lease writer blocked/failed.'}
 $json=Read-DirectSharedJson ($leaseFile+'.json');if($json.Replacements -ne 300){throw 'Missing writer evidence.'}
 $results+=@(@{Test='shared-read-delete-atomic-replace';Passed=$true;Replacements=300})
}finally{if($heldRead){$heldRead.Dispose()};if($writer){$writer.Dispose()}}
foreach($lease in $leases){[IO.File]::WriteAllText($lease.State.TerminalFile,'Own fixture finished');$lease.Parent.Dispose()}
$report=@{Passed=$true;Directory=$root;Cases=$results;UIActivated=$false;SystemFilesModified=$false}
$report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'own-proof.json') -Encoding UTF8
$report|ConvertTo-Json -Depth 6
