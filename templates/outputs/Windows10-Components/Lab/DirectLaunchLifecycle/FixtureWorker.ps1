param([string]$Directory,[ValidateSet('tree','controller','preflight-controller','cancel')][string]$Mode,[string]$StartupState)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
$python='@PYTHON_DIR@\python.exe'
$job=$null;$lease=$null
try{
 if($StartupState){$lease=Open-DirectStartup $StartupState;Assert-DirectStartup $lease}
 $actual=if($Mode -eq 'cancel'){'tree'}else{$Mode}
 $job=Start-DirectOwnedJob -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'FixtureChild.py'),$actual,$Directory) -RedirectStandardOutput (Join-Path $Directory 'child.stdout') -RedirectStandardError (Join-Path $Directory 'child.stderr') -BreakawayChildren:($Mode -eq 'controller')
 @{Pid=$job.Id;Birth=[string]$job.BirthFileTime;Path=$python}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Directory 'worker-ready.json')
 while(!(Test-Path -LiteralPath (Join-Path $Directory 'finish'))){
  if($lease){Assert-DirectStartup $lease}
  Start-Sleep -Milliseconds 50
 }
}catch{[IO.File]::WriteAllText((Join-Path $Directory 'error.txt'),$_.Exception.Message)}
finally{if($job){$job.Dispose()};if($lease){$lease.Parent.Dispose()};[IO.File]::WriteAllText((Join-Path $Directory 'worker-finished'),'Drained')}
