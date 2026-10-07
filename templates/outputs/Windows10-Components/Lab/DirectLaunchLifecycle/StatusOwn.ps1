$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
$root=Join-Path $PSScriptRoot ('status-fixtures/'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
$python='@PYTHON_DIR@\python.exe'
$results=@()
foreach($mode in 'release','refuse','concurrent'){
 $dir=Join-Path $root $mode;[IO.Directory]::CreateDirectory($dir)|Out-Null
 $file=Join-Path $dir 'status.json';[IO.File]::WriteAllText($file,'{"sequence":0}')
 $worker=$null;$reader=$null;$reads=0
 try{
  if($mode -ne 'concurrent'){$reader=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}
  $worker=Start-DirectOwnedJob -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'StatusWriterOwn.py'),$dir,$mode) -RedirectStandardOutput (Join-Path $dir 'stdout') -RedirectStandardError (Join-Path $dir 'stderr')
  $until=[DateTime]::UtcNow.AddSeconds(10);while(!(Test-Path -LiteralPath (Join-Path $dir 'ready'))){if($worker.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Writer ready timeout'};Start-Sleep -Milliseconds 5}
  [IO.File]::WriteAllText((Join-Path $dir 'go'),'go')
  if($mode -eq 'release'){Start-Sleep -Milliseconds 100;$reader.Dispose();$reader=$null}
  if($mode -eq 'concurrent'){
   while(!$worker.WaitForExit(1)){$s=Read-DirectSharedJson $file;if($s.sequence -lt 0 -or $s.sequence -gt 400){throw 'Torn state'};$reads++;if([DateTime]::UtcNow -ge $until){throw 'Concurrent reader timeout'}}
  }
  if(!$worker.WaitForExit(5000) -or $worker.ExitCode -ne 0){throw 'Actual writer fixture failed'}
  if($reader){$reader.Dispose();$reader=$null}
  $r=Read-DirectSharedJson (Join-Path $dir 'result.json');$s=Read-DirectSharedJson $file
  if(!$r.Passed){throw 'Writer result failed'}
  if($mode -eq 'release' -and (!$r.Retries -or $s.sequence -ne 1)){throw 'Transient lock not exercised'}
  if($mode -eq 'refuse' -and ($s.sequence -ne 0 -or $r.ElapsedMs -lt 240 -or $r.ElapsedMs -gt 1000)){throw 'Persistent lock did not fail bounded while preserving original'}
  if($mode -eq 'concurrent' -and ($s.sequence -ne 400 -or !$reads)){throw 'Concurrent publication incomplete'}
  $results+=@(@{Mode=$mode;Result=$r;Reads=$reads;FinalSequence=$s.sequence;Passed=$true})
 }finally{if($reader){$reader.Dispose()};if($worker){$worker.Dispose()}}
}
@{Passed=$true;Cases=$results;Directory=$root;UIActivated=$false;Writer='Production AtomicStatus.write_json';CREATE_NO_WINDOW=$true}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'status-own-proof.json') -Encoding UTF8
