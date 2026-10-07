$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
$root=Join-Path $PSScriptRoot ('recovery-races/'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
$python='@PYTHON_DIR@\python.exe'
$cases=@()
foreach($case in 'new-desktop-ready','failed-transition-drained','restore-shell-gate-held'){
 $dir=Join-Path $root $case;[IO.Directory]::CreateDirectory($dir)|Out-Null
 [IO.File]::WriteAllText((Join-Path $dir 'simulated-shell'),'empty')
 $lease=$null;$gate=$null;$worker=$null;$other=$null
 try{
  $path=New-DirectStartup -Seconds 30;$lease=Open-DirectStartup $path
  if($case -eq 'restore-shell-gate-held'){$other=New-Object Threading.Mutex($false,'Local\Windows10DirectShellLaunch');if(!$other.WaitOne(0)){throw 'Own fixture shell gate busy.'}}
  else{$gate=Enter-DirectNativeRecoveryGate $lease}
  $worker=Start-DirectOwnedJob -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'RecoveryRaceChild.py'),$dir) -RedirectStandardOutput (Join-Path $dir 'stdout') -RedirectStandardError (Join-Path $dir 'stderr')
  $until=[DateTime]::UtcNow.AddSeconds(5)
  while(!(Test-Path -LiteralPath (Join-Path $dir 'observer-waiting'))){if($worker.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Own observer did not reach the gate.'};Start-Sleep -Milliseconds 20}
  if($gate){
   if($worker.WaitForExit(3000) -or (Test-Path -LiteralPath (Join-Path $dir 'simulated-fallback'))){throw 'Recovery ran during the newer shell transition.'}
   if($case -eq 'new-desktop-ready'){[IO.File]::WriteAllText((Join-Path $dir 'simulated-shell'),'new-desktop-ready')}
   else{[IO.File]::WriteAllText((Join-Path $dir 'simulated-drained'),'Exact own simulated job cleanup complete')}
   $gate.ReleaseMutex();$gate.Dispose();$gate=$null
  }
  if(!$worker.WaitForExit(5000) -or $worker.ExitCode -ne 0){throw 'Own recovery gate did not finish.'}
  $r=Read-DirectSharedJson (Join-Path $dir 'result.json')
  if(!$r.NativeExplorerNeverStarted -or $r.NativeStarted){throw 'Unexpected real native activation.'}
  if($case -eq 'new-desktop-ready' -and (!$r.ExistingShellPreserved -or $r.SimulatedFallbackRequested -or $r.ElapsedMs -lt 2900)){throw 'New shell was not preserved.'}
  if($case -eq 'failed-transition-drained' -and (!$r.SimulatedFallbackRequested -or !$r.CleanupWasComplete -or $r.ElapsedMs -lt 2900)){throw 'Failed transition recovery did not wait for cleanup.'}
  if($case -eq 'restore-shell-gate-held' -and (!$r.SimulatedFallbackRequested -or $r.ElapsedMs -gt 4500)){throw 'Recovery incorrectly waits on Restore shell gate.'}
  $cases+=@(@{Test=$case;Passed=$true;Result=$r})
 }finally{
  if($gate){$gate.ReleaseMutex();$gate.Dispose()}
  if($other){$other.ReleaseMutex();$other.Dispose()}
  if($worker){$worker.Dispose()}
  if($lease){[IO.File]::WriteAllText($lease.State.TerminalFile,'Own simulated race finished');$lease.Parent.Dispose()}
 }
}
@{Passed=$true;Cases=$cases;NativeExplorerNeverStarted=$true;Directory=$root}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'recovery-race-proof.json') -Encoding UTF8
