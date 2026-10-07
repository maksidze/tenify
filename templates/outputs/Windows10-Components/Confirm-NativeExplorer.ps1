# The publisher observes the exact Explorer handle/shell owner and exits when it changes.
. (Join-Path $PSScriptRoot 'Lab/DirectLaunchLifecycle/Lifecycle.ps1')
if(-not ('RestoreMaximumShell.Native' -as [type])){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
namespace RestoreMaximumShell { public static class Native {
 [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string c,string t);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 public static uint Owner(){uint p;GetWindowThreadProcessId(GetShellWindow(),out p);return p;}
 public static uint Tray(){uint p;GetWindowThreadProcessId(FindWindow("Shell_TrayWnd",null),out p);return p;}
}}
'@
}
$until=[DateTime]::UtcNow.AddSeconds(30);$native=$null
do {
 $owner=[RestoreMaximumShell.Native]::Owner()
 if($owner){
  try{$p=[DirectLaunchLifecycle.Identity]::Open($owner,0,(Join-Path $env:WINDIR 'explorer.exe'),$false)}catch{$p=$null}
  if($p){Start-Sleep -Milliseconds 200;if($p.Alive -and [RestoreMaximumShell.Native]::Owner() -eq $p.Pid -and [RestoreMaximumShell.Native]::Tray() -eq $p.Pid){$native=$p;break};$p.Dispose()}
 }
 Start-Sleep -Milliseconds 250
}while([DateTime]::UtcNow -lt $until)
if(!$native){throw 'Native Explorer recovery was not confirmed. Inspect the direct run logs; no unrelated process was terminated.'}
try{Write-Host ('Native Windows Explorer owns desktop and tray, PID '+$native.Pid+', birth '+$native.Birth+'.')}finally{$native.Dispose()}
