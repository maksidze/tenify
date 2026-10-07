$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$pointer=Join-Path $data 'current.json';$prior=if(Test-Path -LiteralPath $pointer){[IO.File]::ReadAllBytes($pointer)}else{$null};$previous=Read-Json $pointer;$active=Exact-Host $previous
if($active){$active.Dispose();throw 'Actual companion is active; own early-stop test refused.'}
if(Journal-Count (Join-Path $data 'high-journal.json')){throw 'User baseline journal present; own test refused.'}
$nonce=[guid]::NewGuid().ToString('N');$cfg=@{Format=1;Session=$nonce;Scope='AllHigh';Cancel=(Join-Path $data ($nonce+'.cancel'));Status=(Join-Path $data ($nonce+'.status.json'));Journal=(Join-Path $data 'high-journal.json')};$path=Join-Path $data ($nonce+'.config.json');Write-Json $path $cfg
$ready=Join-Path $data ($nonce+'.lock-ready');$release=Join-Path $data ($nonce+'.lock-release');$locker=$null
try{
 Write-Json $pointer @{Session=$nonce;Pid=0;Birth='0';Path=(Join-Path $PSScriptRoot 'ElevatedCornerHost.exe');Config=$path}
 $locker=Start-NonUiProcess -FilePath (Join-Path $PSScriptRoot 'MutexFixture.exe') -ArgumentList @($ready,$release) -RedirectStandardOutput (Join-Path $data ($nonce+'.lock.log')) -RedirectStandardError (Join-Path $data ($nonce+'.lock.err'))
 $end=[DateTime]::UtcNow.AddSeconds(5);while(!(Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $end){Start-Sleep -Milliseconds 50};if(!(Test-Path -LiteralPath $ready)){throw 'Own mutex holder not ready.'}
 & (Join-Path $PSScriptRoot 'ElevatedCorners.ps1') -Mode Disable
 if(!(Test-Path -LiteralPath $cfg.Cancel)){throw 'Early Stop failed to persist cancellation under held mutex.'}
 $result=@{Passed=$true;MutexHeldByOwnProcess=$true;CancelPersisted=$true;ActualUACStarted=$false;UserWindowsChanged=$false};Write-Json (Join-Path $PSScriptRoot 'early-cancel-proof.json') $result;$result|ConvertTo-Json
}finally{
 if($locker){[IO.File]::WriteAllText($release,'Release');if(!$locker.WaitForExit(5000)){$locker.Kill();$locker.WaitForExit(5000)|Out-Null};$locker.Dispose()}
 $current=Read-Json $pointer;if($current.Session -ne $nonce){throw 'Own pointer changed concurrently; not overwritten.'};if($prior){[IO.File]::WriteAllBytes($pointer,$prior)}else{Remove-Item -LiteralPath $pointer}
}
