$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$proofDir=Join-Path $data ('proof-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($proofDir)|Out-Null
$fixturePath=Join-Path $PSScriptRoot 'ElevatedCornerFixture.exe';$hostPath=Join-Path $PSScriptRoot 'ElevatedCornerHost.exe'
$fixture=Start-NonUiProcess -FilePath $fixturePath -ArgumentList @($proofDir) -RedirectStandardOutput (Join-Path $proofDir 'fixture.log') -RedirectStandardError (Join-Path $proofDir 'fixture.err')
$hostChild=$null;$cfg=$null;$result=@{OnlyOwnHiddenFixture=$true;ActualUACStarted=$false;UserWindowsChanged=$false;Success=$false}
function Wait-Proof([scriptblock]$test){$end=[DateTime]::UtcNow.AddSeconds(20);do{try{if(&$test){return}}catch{};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $end);throw 'Own assertion timeout.'}
function Windows {Read-Json (Join-Path $proofDir 'windows.json')}
function New-Config {
 $nonce=[guid]::NewGuid().ToString('N');$c=@{Format=1;Session=$nonce;Scope='Fixture';Cancel=(Join-Path $data ($nonce+'.cancel'));Status=(Join-Path $data ($nonce+'.status.json'));Journal=(Join-Path $data ($nonce+'.journal.json'));TargetPid=$fixture.Id;TargetBirth=[string]$fixture.BirthFileTime;TargetPath=$fixturePath};$path=Join-Path $data ($nonce+'.config.json');Write-Json $path $c;@{Path=$path;Config=$c}
}
function Launch([string]$mode,$setting){$script:hostChild=Start-NonUiProcess -FilePath $hostPath -ArgumentList @($mode,$setting.Path) -RedirectStandardOutput (Join-Path $proofDir 'host.log') -RedirectStandardError (Join-Path $proofDir 'host.err')}
function Stop-Own($setting){[IO.File]::WriteAllText($setting.Config.Cancel,'Own stop');if(!$hostChild.WaitForExit(20000)){throw 'Own supervisor did not stop.'};if($hostChild.ExitCode -ne 0){throw ('Own host exit '+$hostChild.ExitCode+' '+(Get-Content ($setting.Path+'.stderr') -Raw -ErrorAction SilentlyContinue))};$hostChild.Dispose();$script:hostChild=$null;Wait-Proof {(Journal-Count $setting.Config.Journal) -eq 0}}
try{
 Wait-Proof {(Windows).av -eq 2 -and !(Windows).visibleA}
 $terminalBefore=@(Get-Process WindowsTerminal -ErrorAction SilentlyContinue|ForEach-Object {[string]$_.Id+':'+[string]$_.StartTime.ToUniversalTime().ToFileTimeUtc()})
 $cfg=New-Config
 # A production mode invocation from Medium cannot mutate any user windows.
 Launch '--run' $cfg;if(!$hostChild.WaitForExit(10000)){throw 'Integrity refusal timeout.'};$me=[CornerAccess]::Read([uint32]$PID);try{if($me.Integrity -lt 12288 -and $hostChild.ExitCode -ne 4){throw 'Production did not refuse Medium.'}}finally{$me.Dispose()};$hostChild.Dispose();$hostChild=$null;$result.MediumProductionRefused=$true
 Launch '--fixture' $cfg
 Wait-Proof {(Read-Json $cfg.Config.Status).Status -eq 'running' -and (Windows).av -eq 1}
 [IO.File]::WriteAllText((Join-Path $proofDir 'new'),'New own window')
 Wait-Proof {(Windows).b -and (Windows).bv -eq 1 -and (Windows).fv -eq 3 -and !(Windows).visibleB}
 $result.NewWindowApplied=$true
  $captured=[CornerAccess]::Read([uint32]$hostChild.Id);if(!$captured){throw 'Cannot capture own host lease'};$oldHostPid=$captured.Pid;$oldHostBirth=$captured.Birth;$oldHostPath=$captured.Path;Stop-Own $cfg;if(!$captured.Wait(0)){throw 'Exited own host handle not signaled'};$expired=[CornerAccess]::Exact($oldHostPid,$oldHostBirth,$oldHostPath);if($expired){$expired.Dispose();throw 'Exited exact host lease accepted'};$captured.Dispose();$result.ExitedHostRefused=$true;Wait-Proof {(Windows).av -eq 2 -and (Windows).bv -eq 3};$result.StopRestored=$true
 $cfg=New-Config;Launch '--fixture' $cfg;Wait-Proof {(Windows).av -eq 1 -and (Windows).bv -eq 1}
 $hostChild.Kill();$hostChild.WaitForExit(5000)|Out-Null;$hostChild.Dispose();$hostChild=$null
 if((Journal-Count $cfg.Config.Journal) -ne 2){throw 'Own crash journal missing.'}
 # Regression: recovery must work EVEN WHEN its cancel file already exists.
 [IO.File]::WriteAllText($cfg.Config.Cancel,'Crash recovery cancel exists')
 Launch '--fixture-recover' $cfg
 if(!$hostChild.WaitForExit(20000)){throw 'Own recovery timed out.'};if($hostChild.ExitCode -ne 0){throw ('Own recovery exit '+$hostChild.ExitCode)};$hostChild.Dispose();$hostChild=$null
 Wait-Proof {(Windows).av -eq 2 -and (Windows).bv -eq 3 -and (Journal-Count $cfg.Config.Journal) -eq 0}
 $result.CrashRecoveryWithCancel=$true
 $terminalAfter=@(Get-Process WindowsTerminal -ErrorAction SilentlyContinue|ForEach-Object {[string]$_.Id+':'+[string]$_.StartTime.ToUniversalTime().ToFileTimeUtc()})
 if(@($terminalAfter|Where-Object {$_ -notin $terminalBefore}).Count){throw 'New Terminal process appeared.'}
 $result.NewTerminalProcesses=0;$result.ForegroundWindows=0;$result.Success=$true
}finally{
 if($hostChild){try{if($cfg){[IO.File]::WriteAllText($cfg.Config.Cancel,'Own final cleanup')};if(!$hostChild.WaitForExit(20000)){$hostChild.Kill();$hostChild.WaitForExit(5000)|Out-Null}}finally{$hostChild.Dispose()}}
 [IO.File]::WriteAllText((Join-Path $proofDir 'exit'),'Own exit');if(!$fixture.WaitForExit(5000)){$fixture.Kill();$fixture.WaitForExit(5000)|Out-Null};$fixture.Dispose();Write-Json (Join-Path $proofDir 'result.json') $result;Write-Json (Join-Path $PSScriptRoot 'own-proof.json') $result
}
$result|ConvertTo-Json
