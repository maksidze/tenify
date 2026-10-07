$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')
$base=$script:DirectLifecycleBase
if(-not ('DirectPreflightOwn.Shell' -as [type])){Add-Type @'
using System;using System.Runtime.InteropServices;
namespace DirectPreflightOwn {public static class Shell {
 [DllImport("user32.dll")]static extern IntPtr GetShellWindow();
 [DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 public static uint Owner(){uint p;GetWindowThreadProcessId(GetShellWindow(),out p);return p;}
}}
'@}
$owner=[DirectLaunchLifecycle.Identity]::Open([DirectPreflightOwn.Shell]::Owner(),0,$null,$false)
$root=Join-Path $PSScriptRoot ('full-preflight/'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
$path=New-DirectStartup -Seconds 120;$lease=Open-DirectStartup $path;$worker=$null;$reads=0
$previous=@{};foreach($d in Get-ChildItem -LiteralPath (Join-Path $base 'state-direct') -Directory){$previous[$d.FullName]=$true}
try{
 $worker=Start-DirectOwnedJob -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $base 'Start-Explorer10-Direct.ps1'),'-StartupState',$path,'-PreflightOnly','-Profile','host-dcomp-resource','-XamlQuirk','-Icons10','-HybridTheme10') -RedirectStandardOutput (Join-Path $root 'stdout') -RedirectStandardError (Join-Path $root 'stderr')
 $until=[DateTime]::UtcNow.AddSeconds(75);$statusPath=$null
 while(!$worker.WaitForExit(10)){
  Assert-DirectStartup $lease
  if(!$statusPath){$new=@(Get-ChildItem -LiteralPath (Join-Path $base 'state-direct') -Directory -Filter 'preflight-*'|Where-Object {!$previous.ContainsKey($_.FullName)});if($new.Count -eq 1){$statusPath=Join-Path $new[0].FullName 'status.json'}}
  if($statusPath -and (Test-Path -LiteralPath $statusPath)){$null=Read-DirectSharedJson $statusPath;$reads++}
  if([DateTime]::UtcNow -ge $until){throw 'Full hidden preflight timeout'}
 }
 if($worker.ExitCode -ne 0){throw ('Full hidden preflight failed; '+$root)}
 $record=Read-DirectSharedJson $lease.State.PreflightFile;$proof=Read-DirectSharedJson $record.StatusFile
 if($record.Launcher.Pid -ne $worker.Id -or [uint64]$record.Launcher.Birth -ne [uint64]$worker.BirthFileTime -or $proof.status -ne 'preflight-pass' -or !$proof.ownedJobDrained -or !$reads){throw 'Full hidden preflight evidence missing'}
 if(!$owner.Alive -or [DirectPreflightOwn.Shell]::Owner() -ne $owner.Pid){throw 'Live shell identity changed during own preflight'}
 if(Test-Path -LiteralPath $lease.State.ContinueFile){throw 'Preflight-only wrapper unexpectedly requested a live transition'}
 $report=@{Passed=$true;Directory=$root;StartupState=$path;ConcurrentStatusReads=$reads;Preflight=$record;PreflightStatus=$proof.status;OwnedJobDrained=$proof.ownedJobDrained;PCS=$proof.pcsImageCount;USVFS=$proof.usvfsModuleCount;LiveShellPreserved=@{Pid=$owner.Pid;Birth=[string]$owner.Birth;Path=$owner.Path};UIActivated=$false;NoLiveTransition=$true}
 Write-DirectMarkerJson (Join-Path $root 'proof.json') $report
 $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'full-preflight-proof.json') -Encoding UTF8
}finally{
 if($worker){$worker.Dispose()};$lease.Parent.Dispose();$owner.Dispose()
}
