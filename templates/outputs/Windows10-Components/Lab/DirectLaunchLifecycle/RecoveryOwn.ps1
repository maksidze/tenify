param([switch]$Parent,[string]$Directory)
$ErrorActionPreference='Stop'
foreach($name in 'Security','Utility','Management'){Import-Module (Join-Path $PSHOME ('Modules/Microsoft.PowerShell.'+$name+'/Microsoft.PowerShell.'+$name+'.psd1'))}
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
. (Join-Path $script:DirectLifecycleBase 'Launch-NonUiProcess.ps1')
$python='@PYTHON_DIR@\python.exe'
function Prepare-Observer([string]$Dir,[bool]$WrongBirth){
 [IO.Directory]::CreateDirectory($Dir)|Out-Null
 $me=[DirectLaunchLifecycle.Identity]::Open([uint32]$PID,0,$null,$false)
 try{$s=@{Parent=@{Pid=$me.Pid;Birth=[string]($me.Birth+[uint64]$WrongBirth);Path=$me.Path};Directory=$Dir;NativePath=(Join-Path $env:WINDIR 'explorer.exe');NativeSHA256=(Get-FileHash -LiteralPath (Join-Path $env:WINDIR 'explorer.exe')).Hash};[IO.File]::WriteAllText((Join-Path $Dir 'recovery.json'),($s|ConvertTo-Json -Depth 4))}finally{$me.Dispose()}
 Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'Recovery.py'),(Join-Path $Dir 'recovery.json')) -RedirectStandardOutput (Join-Path $Dir 'stdout') -RedirectStandardError (Join-Path $Dir 'stderr')
}
function Await-Ready([string]$Dir,$Process){$until=[DateTime]::UtcNow.AddSeconds(5);while(!(Test-Path -LiteralPath (Join-Path $Dir 'recovery-ready'))){if($Process.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Observer readiness failed.'};Start-Sleep -Milliseconds 30}}
if($Parent){$p=Prepare-Observer $Directory $false;try{Await-Ready $Directory $p}finally{$p.Dispose()};exit 0}
$root=Join-Path $PSScriptRoot ('recovery-fixtures/'+[Guid]::NewGuid().ToString('N'));$cases=@()
foreach($mode in 'normal-finish','wrong-birth','parent-death'){
 $dir=Join-Path $root $mode;$p=$null
 try{
  if($mode -eq 'parent-death'){
   [IO.Directory]::CreateDirectory($dir)|Out-Null
   $p=Start-NonUiProcess -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Parent','-Directory',$dir) -RedirectStandardOutput (Join-Path $dir 'parent.out') -RedirectStandardError (Join-Path $dir 'parent.err')
   if(!$p.WaitForExit(10000) -or $p.ExitCode -ne 0){throw 'Own observer parent failed.'}
  }else{
   $p=Prepare-Observer $dir ($mode -eq 'wrong-birth')
   if($mode -eq 'wrong-birth'){if(!$p.WaitForExit(5000) -or $p.ExitCode -eq 0 -or (Test-Path (Join-Path $dir 'recovery-ready'))){throw 'Wrong observer parent birth accepted.'};$cases+=@(@{Test=$mode;Passed=$true});continue}
   Await-Ready $dir $p;[IO.File]::WriteAllText((Join-Path $dir 'launcher-finished'),'Own fixture completed without shell transition')
   if(!$p.WaitForExit(8000) -or $p.ExitCode -ne 0){throw 'Observer did not finish.'}
  }
  $until=[DateTime]::UtcNow.AddSeconds(8);$file=Join-Path $dir 'recovery-result.json'
  while(!(Test-Path -LiteralPath $file)){if([DateTime]::UtcNow -ge $until){throw 'Observer result missing.'};Start-Sleep -Milliseconds 50}
  $r=Read-DirectSharedJson $file
  if($r.TransitionStarted -or $r.NativeStarted){throw 'Non-UI observer fixture attempted shell recovery.'}
  if($r.ParentExited -ne ($mode -eq 'parent-death')){throw 'Observer parent lifetime mismatch.'}
  $cases+=@(@{Test=$mode;Passed=$true;NativeStarted=$r.NativeStarted})
 }finally{if($p){if(!$p.HasExited){$p.Kill();[void]$p.WaitForExit(5000)};$p.Dispose()}}
}
@{Passed=$true;Cases=$cases;Directory=$root;NativeExplorerNeverStarted=$true}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'recovery-own-proof.json') -Encoding UTF8
