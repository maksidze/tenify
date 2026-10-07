$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
& (Join-Path $PSScriptRoot 'Stop-Windows10-Persistent.ps1')
$persistentSettings=Join-Path $PSScriptRoot 'Lab\SettingsSessionCompat\active-session.txt'
if(Test-Path -LiteralPath $persistentSettings){& (Join-Path $PSScriptRoot 'Disable-Settings10-VFS.ps1')}
& (Join-Path $PSScriptRoot 'Stop-Settings10.ps1')
& (Join-Path $PSScriptRoot 'Stop-Menu10.ps1')
& (Join-Path $PSScriptRoot 'Stop-Explorer10-VFS.ps1')
# The publisher observes the exact Explorer handle/shell owner and exits when it changes.
if(-not ('RestoreMaximumShell.Native' -as [type])){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
namespace RestoreMaximumShell { public static class Native {
 [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 public static uint Owner(){uint p;GetWindowThreadProcessId(GetShellWindow(),out p);return p;}
}}
'@
}
$until=[DateTime]::UtcNow.AddSeconds(30);$native=$null
do {
 $owner=[RestoreMaximumShell.Native]::Owner()
 if($owner){$p=Get-Process -Id $owner -ErrorAction SilentlyContinue;if($p -and $p.Path -ieq (Join-Path $env:WINDIR 'explorer.exe')){$native=$p;break}}
 Start-Sleep -Milliseconds 250
}while([DateTime]::UtcNow -lt $until)
if(!$native){throw 'Native Explorer recovery was not confirmed. Inspect the VFS run logs; no unrelated process was terminated.'}
Write-Host ('Native Windows Explorer owns the desktop, PID '+$native.Id+'.')
