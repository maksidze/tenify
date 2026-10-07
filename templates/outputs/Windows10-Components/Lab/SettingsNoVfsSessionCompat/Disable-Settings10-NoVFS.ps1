param()
$ErrorActionPreference='Stop'
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1"
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1"
$pointer=Join-Path $PSScriptRoot 'active-session.txt'
if(!(Test-Path $pointer)){Write-Output 'No owned Settings NoVFS session';return}
$path=(Get-Content $pointer -Raw).Trim();$state=Get-Content $path -Raw|ConvertFrom-Json
if(Test-Path (Join-Path $state.Directory 'restored.json')){Write-Output 'Already restored';return}
[IO.File]::WriteAllText($state.CancelFile,'explicit stop')
# A dead controller cannot acknowledge cancel. Recover the validated session
# under the same lifetime mutex; never infer ownership from PID alone.
$owner=Get-Process -Id $state.Controller.Pid -ErrorAction SilentlyContinue
$ownerAlive=$false
if($owner){
 try{$ownerAlive=($owner.Path -ieq $state.Controller.Path -and $owner.StartTime.ToUniversalTime().ToFileTimeUtc() -eq [long]$state.Controller.Birth)}finally{$owner.Dispose()}
}
if(!$ownerAlive){
 . (Join-Path $PSScriptRoot '../../Launch-NonUiProcess.ps1')
 $python='@PYTHON_DIR@\python.exe'
 $recovery=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'SessionController.py'),'recover-stale',$path) -WorkingDirectory $PSScriptRoot -RedirectStandardOutput (Join-Path $state.Directory 'stop-recovery.log') -RedirectStandardError (Join-Path $state.Directory 'stop-recovery.err')
 try{
  if(!$recovery.WaitForExit(30000)){throw 'Exact stale Settings cleanup has not completed; see stop-recovery.log'}
  if($recovery.ExitCode -ne 0){throw ('Stale Settings cleanup refused: '+[IO.File]::ReadAllText((Join-Path $state.Directory 'stop-recovery.err')))}
 }finally{$recovery.Dispose()}
}
$until=[DateTime]::UtcNow.AddSeconds(30)
while(!(Test-Path (Join-Path $state.Directory 'restored.json'))){if([DateTime]::UtcNow -ge $until){throw 'Cleanup pending; controller retains ownership. See cleanup-pending.json'};Start-Sleep -Milliseconds 100}
Get-Content (Join-Path $state.Directory 'restored.json') -Raw
