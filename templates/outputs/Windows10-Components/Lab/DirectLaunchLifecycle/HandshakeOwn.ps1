$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
$root=Join-Path $PSScriptRoot ('handshake-fixtures/'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
$script:DirectLifecycleBase=Join-Path $root 'isolated-base';[IO.Directory]::CreateDirectory($script:DirectLifecycleBase)|Out-Null
$results=@()
foreach($mode in 'approve','cancel-before-ack','fail-before-ready','foreign-parent','wrong-ack-birth'){
 $dir=Join-Path $root $mode;[IO.Directory]::CreateDirectory($dir)|Out-Null
 [IO.File]::WriteAllText((Join-Path $dir 'companions-running'),'Preserved until own preflight succeeds')
 $path=New-DirectStartup -Seconds 20;$lease=Open-DirectStartup $path;$worker=$null
 try{
  $worker=Start-DirectOwnedJob -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'HandshakeWorker.ps1'),'-StartupState',$path,'-FixtureBase',$script:DirectLifecycleBase,'-Directory',$dir,'-Mode',$(if($mode -in @('fail-before-ready','foreign-parent')){$mode}else{'wait'})) -RedirectStandardOutput (Join-Path $dir 'stdout') -RedirectStandardError (Join-Path $dir 'stderr') -WorkingDirectory $PSScriptRoot
  $until=[DateTime]::UtcNow.AddSeconds(10)
  while(!(Test-Path -LiteralPath $lease.State.PreflightFile) -and !$worker.HasExited){if([DateTime]::UtcNow -ge $until){throw 'Handshake ready timeout'};Start-Sleep -Milliseconds 20}
  if($mode -notin @('fail-before-ready','foreign-parent')){
   Start-Sleep -Milliseconds 100
   if(Test-Path -LiteralPath (Join-Path $dir 'transition')){throw 'Transition preceded approval'}
   if($mode -eq 'approve'){
    # Scoped Stop exemption must keep this exact parent's pending transaction.
    Cancel-PendingDirectStartups -PreserveStartupState $path
    Assert-DirectStartup $lease
    Remove-Item -LiteralPath (Join-Path $dir 'companions-running')
    Approve-DirectTransition $lease
   }elseif($mode -eq 'cancel-before-ack'){
    Cancel-DirectStartup $lease 'Own early cancellation'
    $refused=$false;try{Approve-DirectTransition $lease}catch{$refused=$true};if(!$refused){throw 'Late acknowledgement after cancel was accepted'}
   }else{
    $badParent=@{Pid=$lease.State.Parent.Pid;Birth=[string]([uint64]$lease.State.Parent.Birth+1);Path=$lease.State.Parent.Path}
    Write-DirectMarkerJson $lease.State.ContinueFile @{Version=1;Parent=$badParent;PreflightSHA256=(Get-FileHash -LiteralPath $lease.State.PreflightFile).Hash}
   }
  }
  if(!$worker.WaitForExit(5000) -or $worker.ExitCode -ne 0){throw 'Own handshake child failed'}
  $r=Read-DirectSharedJson (Join-Path $dir 'result.json')
  $expected=$mode -eq 'approve'
  if([bool]$r.Transition -ne $expected -or [bool](Test-Path -LiteralPath (Join-Path $dir 'transition')) -ne $expected){throw 'Unexpected transition result'}
  if(!$expected -and (!(Test-Path -LiteralPath (Join-Path $dir 'companions-running')) -or !$r.Refused)){throw 'Failed preflight/cancel did not preserve fake companions'}
  $results+=@(@{Mode=$mode;Passed=$true;Result=$r;CompanionsPreserved=(!$expected)})
 }finally{
  if($worker){$worker.Dispose()}
  [IO.File]::WriteAllText($lease.State.TerminalFile,'Own fixture complete');$lease.Parent.Dispose()
 }
}
# Kill only the exact fixture parent, leaving its held outer Job alive so that
# the child must observe parent death itself rather than Job teardown.
$dir=Join-Path $root 'parent-death';[IO.Directory]::CreateDirectory($dir)|Out-Null
$parentJob=$null;$parentIdentity=$null;$childIdentity=$null
try{
 $parentJob=Start-DirectOwnedJob -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'HandshakeParentOwn.ps1'),'-Directory',$dir) -RedirectStandardOutput (Join-Path $dir 'stdout') -RedirectStandardError (Join-Path $dir 'stderr') -WorkingDirectory $PSScriptRoot
 $until=[DateTime]::UtcNow.AddSeconds(12)
 while(!(Test-Path -LiteralPath (Join-Path $dir 'parent-ready.json'))){if($parentJob.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Own parent startup timeout'};Start-Sleep -Milliseconds 20}
 $r=Read-DirectSharedJson (Join-Path $dir 'parent-ready.json');$s=Read-DirectSharedJson $r.StartupState
 $childIdentity=[DirectLaunchLifecycle.Identity]::Open([uint32]$r.Worker.Pid,[uint64]$r.Worker.Birth,$r.Worker.Path,$true)
 $parentIdentity=[DirectLaunchLifecycle.Identity]::Open([uint32]$parentJob.Id,[uint64]$parentJob.BirthFileTime,(Join-Path $PSHOME 'powershell.exe'),$true)
 while(!(Test-Path -LiteralPath $s.PreflightFile)){if(!$childIdentity.Alive -or [DateTime]::UtcNow -ge $until){throw 'Own child preflight timeout'};Start-Sleep -Milliseconds 20}
 $parentIdentity.Stop();if(!$parentIdentity.Wait(5000) -or !$childIdentity.Wait(5000)){throw 'Parent death did not end pending child'}
 $r=Read-DirectSharedJson (Join-Path $dir 'result.json')
 if($r.Transition -or !$r.Refused -or $r.Error -ne 'Exact startup parent exited.' -or (Test-Path -LiteralPath (Join-Path $dir 'transition'))){throw 'Parent death allowed a late transition'}
 $results+=@(@{Mode='parent-death';Passed=$true;Result=$r;ExactParentOnlyTerminated=$true})
}finally{
 if($childIdentity){$childIdentity.Dispose()};if($parentIdentity){$parentIdentity.Dispose()};if($parentJob){$parentJob.Dispose()}
}
@{Passed=$true;Cases=$results;Directory=$root;UIActivated=$false;ProductionHandshakeFunctions=$true;CREATE_NO_WINDOW=$true}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'handshake-own-proof.json') -Encoding UTF8
