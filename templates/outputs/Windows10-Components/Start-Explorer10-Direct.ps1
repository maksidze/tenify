param([switch]$Guard,[string]$RunDirectory,[string]$StartupState,[uint32]$GuardOwnerPid,[uint64]$GuardOwnerBirth,[switch]$PreflightOnly,[switch]$CaptureDebug,[switch]$PackageIdentity,[switch]$XamlQuirk,[switch]$Icons10,[switch]$Theme10,[switch]$ControlTheme10,[switch]$HybridTheme10,[switch]$NoLegacyTouchpad,[string]$Profile='host-dcomp-resource')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
foreach($name in 'Security','Utility','Management'){Import-Module (Join-Path $PSHOME ('Modules/Microsoft.PowerShell.'+$name+'/Microsoft.PowerShell.'+$name+'.psd1')) -ErrorAction Stop}
. (Join-Path $PSScriptRoot 'Lab/DirectLaunchLifecycle/Lifecycle.ps1')
. (Join-Path $PSScriptRoot 'Launch-NonUiProcess.ps1')
if(-not ('DirectShell.Window' -as [type])){Add-Type @'
using System;using System.Runtime.InteropServices;
namespace DirectShell {public static class Window {
 [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string c,string t);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 public static uint Owner(){uint p=0;var w=GetShellWindow();if(w!=IntPtr.Zero)GetWindowThreadProcessId(w,out p);return p;}
 public static uint Tray(){uint p=0;var w=FindWindow("Shell_TrayWnd",null);if(w!=IntPtr.Zero)GetWindowThreadProcessId(w,out p);return p;}
}}
'@}
$nativeExe=Join-Path $env:WINDIR 'explorer.exe'
$oldExe=Join-Path $PSScriptRoot 'Runtime/Explorer10/explorer.exe'
function Write-Status([string]$Text){if($RunDirectory){(Get-Date -Format o)+' '+$Text|Add-Content -LiteralPath (Join-Path $RunDirectory 'launch.log')}}
if($Guard){
 $key=$null;$owner=$null;$lease=$null;$held=$false;$changed=$false;$guardError=$null
 $gate=New-Object Threading.Mutex($false,'Local\Explorer10AutoRestartGuard')
 try{
  if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Registry guard requires elevation.'}
  $owner=[DirectLaunchLifecycle.Identity]::Open($GuardOwnerPid,$GuardOwnerBirth,(Join-Path $PSHOME 'powershell.exe'),$false)
  $lease=Open-DirectStartup $StartupState;Assert-DirectStartup $lease
  try{$held=$gate.WaitOne(10000)}catch [Threading.AbandonedMutexException]{$held=$true}
  if(!$held){throw 'Another autorestart guard is active.'}
  Assert-DirectStartup $lease;if(!$owner.Alive){throw 'Exact unelevated launcher exited.'}
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',$true)
  if(!$key){throw 'Winlogon registry key unavailable.'}
  $existed=@($key.GetValueNames()) -contains 'AutoRestartShell';$saved=$null;$kind=$null
  if($existed){$kind=$key.GetValueKind('AutoRestartShell');$saved=$key.GetValue('AutoRestartShell',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
  @{Existed=$existed;Value=$saved;Kind=[string]$kind;OwnerPid=$GuardOwnerPid;OwnerBirth=[string]$GuardOwnerBirth}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $RunDirectory 'registry-backup.json') -Encoding UTF8
  Assert-DirectStartup $lease;if(!$owner.Alive){throw 'Launcher ended before autorestart mutation.'}
  $key.SetValue('AutoRestartShell',0,[Microsoft.Win32.RegistryValueKind]::DWord);$key.Flush();$changed=$true
  [IO.File]::WriteAllText((Join-Path $RunDirectory 'ready'),'Registry guard ready')
  $until=[DateTime]::UtcNow.AddSeconds(75)
  while([DateTime]::UtcNow -lt $until -and $owner.Alive -and !(Test-Path -LiteralPath (Join-Path $RunDirectory 'done'))){Assert-DirectStartup $lease;Start-Sleep -Milliseconds 100}
 }catch{$guardError=$_.Exception.Message;Write-Status ('GUARD: '+$guardError)}
 finally{
  try{
   if($changed){
    $owned=(@($key.GetValueNames()) -contains 'AutoRestartShell') -and $key.GetValueKind('AutoRestartShell') -eq [Microsoft.Win32.RegistryValueKind]::DWord -and [int]$key.GetValue('AutoRestartShell') -eq 0
    if($owned){if($existed){$key.SetValue('AutoRestartShell',$saved,$kind)}else{$key.DeleteValue('AutoRestartShell',$false)};$key.Flush();$result='OriginalValueAndKindRestored'}else{$result='ForeignValuePreserved'}
   }else{$result='NoMutation'}
   @{Result=$result;Error=$guardError}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $RunDirectory 'restored') -Encoding UTF8
  }finally{if($key){$key.Dispose()};if($owner){$owner.Dispose()};if($lease){$lease.Parent.Dispose()};if($held){$gate.ReleaseMutex()};$gate.Dispose()}
 }
 if($guardError){exit 1};exit 0
}
if($Theme10 -or $PackageIdentity -or $NoLegacyTouchpad -or $Profile -ne 'host-dcomp-resource'){throw 'Direct launcher supports only host-dcomp-resource without package identity or full Theme10.'}
if($ControlTheme10 -and $HybridTheme10){throw 'Choose one theme adapter.'}
$standalone=!$StartupState;if($standalone){$StartupState=New-DirectStartup -Seconds 180}
$lease=$null;$held=$false;$preflightProcess=$null;$controller=$null;$old=$null;$guardProcess=$null;$recovery=$null;$transition=$false;$marker=$null;$exitResult=1;$nativeRecoveryGate=$null
$shellGate=New-Object Threading.Mutex($false,'Local\Windows10DirectShellLaunch')
try{
 $lease=Open-DirectStartup $StartupState;Assert-DirectStartup $lease
 try{$held=$shellGate.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'Another direct shell transition is active.'}
 if((Get-Item -LiteralPath $oldExe).VersionInfo.FileVersion -notlike '10.0.19041.*' -or (Get-AuthenticodeSignature -LiteralPath $oldExe).Status -ne 'Valid'){throw 'Unexpected or unsigned Explorer image.'}
 if(!(Test-Path -LiteralPath (Join-Path (Split-Path $oldExe) 'ru-RU/explorer.exe.mui'))){throw 'Missing Explorer MUI.'}
 $python='@PYTHON_DIR@\python.exe'
 $helper=Join-Path $PSScriptRoot 'Lab/NoVfsShellCompat/Launch-Explorer10-NoVFS.py'
 $flags=@('--profile',$Profile);if($CaptureDebug){$flags+='--capture-debug'};if($XamlQuirk){$flags+='--xaml-quirk'};if($Icons10){$flags+='--icons10'};if($ControlTheme10){$flags+='--control-theme10'};if($HybridTheme10){$flags+='--hybrid-theme10'}
 $preflightDirectory=Join-Path $PSScriptRoot ('state-direct/preflight-'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($preflightDirectory)|Out-Null
 Assert-DirectStartup $lease
 $preflightProcess=Start-DirectOwnedJob -FilePath $python -ArgumentList (@($helper,'--preflight','--run-directory',$preflightDirectory)+$flags) -RedirectStandardOutput (Join-Path $preflightDirectory 'helper.stdout.log') -RedirectStandardError (Join-Path $preflightDirectory 'helper.stderr.log')
 try{
  $until=[DateTime]::UtcNow.AddSeconds(55)
  while(!$preflightProcess.WaitForExit(100)){Assert-DirectStartup $lease;if([DateTime]::UtcNow -ge $until){throw 'Hidden preflight timeout; exact owned job will be drained.'}}
  if($preflightProcess.ExitCode -ne 0){throw ('Hidden direct preflight failed: '+$preflightDirectory)}
 }finally{$preflightProcess.Dispose();$preflightProcess=$null}
 Assert-DirectStartup $lease
 Write-Host ('Direct hidden preflight passed: '+$preflightDirectory)
 $proofFile=Join-Path $preflightDirectory 'status.json';$proof=Read-DirectSharedJson $proofFile
 if($proof.status -ne 'preflight-pass' -or !$proof.preflight -or !$proof.ownedJobDrained -or $proof.VFS -ne $false -or $proof.pcsImageCount -ne 1 -or $proof.usvfsModuleCount -ne 0){throw 'Completed preflight evidence is incomplete.'}
 $preflightIdentity=[DirectLaunchLifecycle.Identity]::Open([uint32]$PID,0,$null,$false)
 try{
  $preflightRecord=@{Version=1;Launcher=@{Pid=$preflightIdentity.Pid;Birth=[string]$preflightIdentity.Birth;Path=$preflightIdentity.Path};StatusFile=$proofFile;StatusSHA256=(Get-FileHash -LiteralPath $proofFile).Hash;PreflightPid=$proof.pid;PreflightBirth=$proof.birthFileTime;OwnedJobDrained=$true}
  Invoke-DirectStartupTransition $lease {Write-DirectMarkerJson $lease.State.PreflightFile $preflightRecord}
 }finally{$preflightIdentity.Dispose()}
 if($PreflightOnly){$exitResult=0;return}
 # No companion stop, UAC or shell replacement before the exact parent approves.
 if($standalone){Approve-DirectTransition $lease}
 Wait-DirectTransitionApproval $lease
 if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Start normally; only the registry guard is elevated.'}
 $RunDirectory=Join-Path $PSScriptRoot ('state-direct/'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($RunDirectory)|Out-Null
 [IO.File]::WriteAllText((Join-Path $lease.State.Directory 'direct-run.txt'),$RunDirectory)
 $me=[DirectLaunchLifecycle.Identity]::Open([uint32]$PID,0,$null,$false)
 try{
  $recoveryState=@{Parent=@{Pid=$me.Pid;Birth=[string]$me.Birth;Path=$me.Path};Directory=$RunDirectory;NativePath=$nativeExe;NativeSHA256=(Get-FileHash -LiteralPath $nativeExe).Hash}
  $recoveryFile=Join-Path $RunDirectory 'recovery.json';[IO.File]::WriteAllText($recoveryFile,($recoveryState|ConvertTo-Json -Depth 4))
  $recovery=Start-NonUiProcess -FilePath $python -ArgumentList @((Join-Path $PSScriptRoot 'Lab/DirectLaunchLifecycle/Recovery.py'),$recoveryFile) -RedirectStandardOutput (Join-Path $RunDirectory 'recovery.log') -RedirectStandardError (Join-Path $RunDirectory 'recovery.err')
  $until=[DateTime]::UtcNow.AddSeconds(5);while(!(Test-Path -LiteralPath (Join-Path $RunDirectory 'recovery-ready'))){Assert-DirectStartup $lease;if($recovery.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Independent native recovery observer not ready.'};Start-Sleep -Milliseconds 50}
  Assert-DirectStartup $lease
  $guardProcess=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -PassThru -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-Guard','-RunDirectory',('"'+$RunDirectory+'"'),'-StartupState',('"'+$StartupState+'"'),'-GuardOwnerPid',[string]$PID,'-GuardOwnerBirth',[string]$me.Birth)
 }finally{$me.Dispose()}
 $until=[DateTime]::UtcNow.AddSeconds(15)
 while(!(Test-Path -LiteralPath (Join-Path $RunDirectory 'ready'))){Assert-DirectStartup $lease;if($guardProcess.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Autorestart guard did not become ready.'};Start-Sleep -Milliseconds 100}
 Assert-DirectStartup $lease
 $nativeRecoveryGate=Enter-DirectNativeRecoveryGate $lease
 $owner=[DirectShell.Window]::Owner()
 if($owner){
  $existing=[DirectLaunchLifecycle.Identity]::Open($owner,0,$null,$true)
  try{
   $allowed=@($oldExe,$nativeExe,(Join-Path (Split-Path $PSScriptRoot) 'Explorer10-Xaml/explorer.exe'))
   if($allowed -notcontains $existing.Path){throw 'Unexpected desktop owner preserved.'}
   $marker=Join-Path (Split-Path $PSScriptRoot) 'Shell10-Test/state/restart-in-progress.json'
   if(Test-Path -LiteralPath $marker){throw 'Another settings restart is active.'}
   Assert-DirectStartup $lease
   if([DirectShell.Window]::Owner() -ne $existing.Pid -or !$existing.Alive -or (Test-Path -LiteralPath (Join-Path $RunDirectory 'restored'))){throw 'Shell or registry guard changed before replacement.'}
   [IO.Directory]::CreateDirectory((Split-Path $marker))|Out-Null
   @{Pid=$PID;Run=$RunDirectory}|ConvertTo-Json|Set-Content -LiteralPath $marker -Encoding UTF8
   [IO.File]::WriteAllText((Join-Path $RunDirectory 'transition-started'),'Exact shell replacement authorized');$transition=$true
   Assert-DirectStartup $lease
   Invoke-DirectStartupTransition $lease {$existing.Stop();if(!$existing.Wait(5000)){throw 'Exact previous shell termination pending.'}}
  }finally{$existing.Dispose()}
 }
 Assert-DirectStartup $lease
 if(Test-Path -LiteralPath (Join-Path $RunDirectory 'restored')){throw 'Registry guard ended before child creation.'}
 [IO.File]::WriteAllText((Join-Path $RunDirectory 'transition-started'),'Creating exact direct shell child');$transition=$true
 Assert-DirectStartup $lease
 $controller=Invoke-DirectStartupTransition $lease {Start-DirectOwnedJob -BreakawayChildren -FilePath $python -ArgumentList (@($helper,'--run-directory',$RunDirectory)+$flags) -RedirectStandardOutput (Join-Path $RunDirectory 'helper.stdout.log') -RedirectStandardError (Join-Path $RunDirectory 'helper.stderr.log')}
 $until=[DateTime]::UtcNow.AddSeconds(30)
 while(!(Test-Path -LiteralPath (Join-Path $RunDirectory 'child-ready'))){Assert-DirectStartup $lease;if($controller.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Direct child bootstrap timed out or failed.'};Start-Sleep -Milliseconds 100}
 $s=Read-DirectSharedJson (Join-Path $RunDirectory 'status.json')
 $old=[DirectLaunchLifecycle.Identity]::Open([uint32]$s.pid,[uint64]$s.birthFileTime,$oldExe,$false)
 $until=[DateTime]::UtcNow.AddSeconds(20)
 do{
  Assert-DirectStartup $lease
  if(!$old.Alive -or $controller.HasExited){throw 'Direct child exited before desktop readiness.'}
  $s=Read-DirectSharedJson (Join-Path $RunDirectory 'status.json')
  if([DirectShell.Window]::Owner() -eq $old.Pid -and [DirectShell.Window]::Tray() -eq $old.Pid -and $s.directModuleGateVerified -and $s.pcsImageCount -eq 1 -and $s.usvfsModuleCount -eq 0){break}
  if([DateTime]::UtcNow -ge $until){throw 'Direct desktop/module readiness timeout.'};Start-Sleep -Milliseconds 100
 }while($true)
 $ready=@{Pid=$old.Pid;Birth=[string]$old.Birth;Path=$old.Path;RunDirectory=$RunDirectory}
 $readyTmp=$lease.State.ReadyFile+'.tmp';[IO.File]::WriteAllText($readyTmp,($ready|ConvertTo-Json));[IO.File]::Move($readyTmp,$lease.State.ReadyFile)
 if($standalone){Commit-DirectStartup $lease}
 while(!(Test-Path -LiteralPath $lease.State.CommitFile)){Assert-DirectStartup $lease;Start-Sleep -Milliseconds 100}
 Assert-DirectStartup $lease
 [IO.File]::WriteAllText((Join-Path $RunDirectory 'done'),'Desktop and physical modules ready')
 if($marker -and (Test-Path -LiteralPath $marker) -and (Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json).Run -eq $RunDirectory){Remove-Item -LiteralPath $marker}
 $nativeRecoveryGate.ReleaseMutex();$nativeRecoveryGate.Dispose();$nativeRecoveryGate=$null
 $shellGate.ReleaseMutex();$held=$false
 Write-Status ('Ready UntilStop exact PID '+$old.Pid+' birth '+$old.Birth)
 while(!$old.Wait(500)){if($controller.HasExited){throw 'Direct controller exited while its shell was still present.'}}
 if(!$controller.WaitForExit(10000)){throw 'Direct controller cleanup deadline exceeded.'}
 $s=Read-DirectSharedJson (Join-Path $RunDirectory 'status.json')
 if($s.status -eq 'error' -or $controller.ExitCode -ne 0){throw ('Direct controller ended: '+$s.error)}
 $exitResult=0
}catch{Write-Status ('ERROR: '+$_.Exception.Message);Write-Error $_ -ErrorAction Continue}
finally{
 try{
  if($preflightProcess){$preflightProcess.Dispose()}
  if($controller){$controller.Dispose()}
  if($old){$old.Dispose()}
 }finally{
  # Owned jobs have been disposed before allowing an older observer to recover.
  # Recovery must not take Windows10DirectShellLaunch: Restore holds that gate
  # while waiting for native shell readiness.
  if($nativeRecoveryGate){$nativeRecoveryGate.ReleaseMutex();$nativeRecoveryGate.Dispose();$nativeRecoveryGate=$null}
  if($RunDirectory){[IO.File]::WriteAllText((Join-Path $RunDirectory 'done'),'Launcher finally')}
  if($guardProcess){[void]$guardProcess.WaitForExit(10000);$guardProcess.Dispose()}
  if($marker -and (Test-Path -LiteralPath $marker) -and (Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json).Run -eq $RunDirectory){Remove-Item -LiteralPath $marker}
  if($recovery){
   [IO.File]::WriteAllText((Join-Path $RunDirectory 'launcher-finished'),'Owned jobs drained; observer may recover an empty shell')
   if(!$recovery.WaitForExit(15000)){Write-Warning 'Independent native recovery is still pending; observer retained.'}elseif($recovery.ExitCode -ne 0){Write-Warning 'Native recovery observer failed; inspect recovery.err.'}
   $recovery.Dispose()
  }
  if($lease){[IO.File]::WriteAllText($lease.State.TerminalFile,(@{LauncherPid=$PID;ExitCode=$exitResult;TimeUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json));$lease.Parent.Dispose()}
  if($held){$shellGate.ReleaseMutex()};$shellGate.Dispose()
 }
}
exit $exitResult
