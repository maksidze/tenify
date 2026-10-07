param([switch]$Guard, [string]$RunDirectory, [switch]$PreflightOnly)
$ErrorActionPreference='Stop'
$oldExe=Join-Path $PSScriptRoot 'Runtime\Explorer10\explorer.exe'
$nativeExe=Join-Path $env:WINDIR 'explorer.exe'
$regPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class Explorer10Probe {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI {
  public int cb; public string reserved,desktop,title; public uint x,y,xSize,ySize,xChars,yChars,fill,flags; public short show,reservedSize; public IntPtr reservedPointer,input,output,error;
 }
 [StructLayout(LayoutKind.Sequential)] struct PI {public IntPtr process,thread;public uint pid,tid;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,System.Text.StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string cwd,ref SI si,out PI pi);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr h,uint code);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 public static void Preflight(string exe) {
  SI si=new SI();si.cb=Marshal.SizeOf(typeof(SI));PI pi;
  if(!CreateProcess(exe,new System.Text.StringBuilder("\""+exe+"\""),IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,System.IO.Path.GetDirectoryName(exe),ref si,out pi))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  try {if(!TerminateProcess(pi.process,0))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());WaitForSingleObject(pi.process,5000);}
  finally {CloseHandle(pi.thread);CloseHandle(pi.process);}
 }
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string cls,string title);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
 public static uint Owner(string cls) { uint p=0; var h=FindWindow(cls,null); if(h!=IntPtr.Zero)GetWindowThreadProcessId(h,out p); return p; }
}
'@
function Write-Status([string]$Text) {
 (Get-Date -Format o)+' '+$Text | Add-Content -LiteralPath (Join-Path $RunDirectory 'launch.log')
}
if($Guard) {
 $isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if(-not $isAdmin){throw 'The registry guard requires elevation.'}
 $saved=$null; $changed=$false
 try {
  $properties=Get-ItemProperty -LiteralPath $regPath
  $existed=$null -ne $properties.PSObject.Properties['AutoRestartShell']
  $saved=if($existed){[int]$properties.AutoRestartShell}else{$null}
  @{Existed=$existed;Value=$saved} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunDirectory 'registry-backup.json')
  New-ItemProperty -LiteralPath $regPath -Name AutoRestartShell -PropertyType DWord -Value 0 -Force | Out-Null
  $changed=$true; Write-Status 'Autorestart temporarily disabled'
  New-Item -ItemType File -Path (Join-Path $RunDirectory 'ready') | Out-Null
  $deadline=(Get-Date).AddSeconds(40)
  while((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath (Join-Path $RunDirectory 'done'))){Start-Sleep -Milliseconds 250}
 } catch { Write-Status ('GUARD ERROR: '+$_.Exception.Message) }
 finally {
  if($changed) {
   if($existed){Set-ItemProperty -LiteralPath $regPath -Name AutoRestartShell -Value $saved}
   else{Remove-ItemProperty -LiteralPath $regPath -Name AutoRestartShell}
   Write-Status 'Original autorestart setting restored'
  }
  New-Item -ItemType File -Path (Join-Path $RunDirectory 'restored') -Force | Out-Null
  if([Explorer10Probe]::Owner('Progman') -eq 0){Start-Process -FilePath $nativeExe}
 }
 exit
}
foreach($language in 'ru-RU') {
 if(-not(Test-Path -LiteralPath (Join-Path (Split-Path $oldExe) ($language+'\explorer.exe.mui')))){throw "Missing $language MUI file"}
}
if((Get-Item -LiteralPath $oldExe).VersionInfo.FileVersion -notlike '10.0.19041.*'){throw 'Unexpected Explorer version'}
if((Get-AuthenticodeSignature -LiteralPath $oldExe).Status -ne 'Valid'){throw 'Explorer signature is not valid; current shell unchanged'}
[Explorer10Probe]::Preflight($oldExe)
if($PreflightOnly){Write-Host 'PASS: signed ISO Explorer process can be created. Live shell unchanged.';exit 0}
$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($isAdmin){throw 'Start this launcher normally. Only the registry guard should be elevated.'}
$RunDirectory=Join-Path $PSScriptRoot ('state\'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null
Write-Status 'Requesting UAC for temporary autorestart control'
try {
 $guardProcess=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -PassThru -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-Guard','-RunDirectory',('"'+$RunDirectory+'"'))
 $deadline=(Get-Date).AddSeconds(15)
 while(-not(Test-Path -LiteralPath (Join-Path $RunDirectory 'ready'))) {
  if($guardProcess.HasExited){throw 'Elevated guard did not start'}
  if((Get-Date) -gt $deadline){throw 'Registry guard timeout'}
  Start-Sleep -Milliseconds 200
 }
 $shellOwner=[Explorer10Probe]::Owner('Progman')
 if($shellOwner) {
  $existing=Get-Process -Id $shellOwner
  if($existing.Path -ieq $oldExe){throw 'Windows 10 Explorer is already the shell'}
  $xamlExe=Join-Path (Split-Path $PSScriptRoot) 'Explorer10-Xaml\explorer.exe'
  if($existing.Path -ine $nativeExe -and $existing.Path -ine $xamlExe){throw 'Unexpected desktop owner'}
  Write-Status "Stopping system shell PID $shellOwner"
  $ownRestartMarker=Join-Path (Split-Path $PSScriptRoot) 'Shell10-Test\state\restart-in-progress.json'
  New-Item -ItemType Directory -Path (Split-Path $ownRestartMarker) -Force | Out-Null
  @{Pid=$PID;Started=(Get-Date -Format o)} | ConvertTo-Json | Set-Content -LiteralPath $ownRestartMarker -Encoding UTF8
  Stop-Process -Id $shellOwner
  $existing.WaitForExit()
 }
 $old=Start-Process -FilePath $oldExe -WorkingDirectory (Split-Path $oldExe) -PassThru
 Write-Status "Started Windows 10 Explorer PID $($old.Id)"
 $deadline=(Get-Date).AddSeconds(20)
 do {
  Start-Sleep -Milliseconds 250
  if([Explorer10Probe]::Owner('Progman') -eq $old.Id -and [Explorer10Probe]::Owner('Shell_TrayWnd') -eq $old.Id) {
   Write-Status 'SUCCESS: Windows 10 Explorer owns desktop and taskbar'
   if($ownRestartMarker -and (Test-Path -LiteralPath $ownRestartMarker) -and (Get-Content -LiteralPath $ownRestartMarker -Raw | ConvertFrom-Json).Pid -eq $PID){Remove-Item -LiteralPath $ownRestartMarker}
   New-Item -ItemType File -Path (Join-Path $RunDirectory 'done') | Out-Null
   Wait-Process -Id $old.Id -ErrorAction SilentlyContinue
   exit 0
  }
  if($old.HasExited){throw "Old Explorer exited with code $($old.ExitCode)"}
 } while((Get-Date) -lt $deadline)
 throw 'Old Explorer startup timeout'
} catch {
 Write-Status ('ERROR: '+$_.Exception.Message)
 if($old -and -not $old.HasExited){Stop-Process -Id $old.Id -ErrorAction SilentlyContinue}
 Write-Error $_ -ErrorAction Continue
} finally {
 if($ownRestartMarker -and (Test-Path -LiteralPath $ownRestartMarker) -and (Get-Content -LiteralPath $ownRestartMarker -Raw | ConvertFrom-Json).Pid -eq $PID){Remove-Item -LiteralPath $ownRestartMarker}
 New-Item -ItemType File -Path (Join-Path $RunDirectory 'done') -Force | Out-Null
 # The test settings menu may be replacing this Explorer with another old instance.
 # Give its restart operation time to finish before restoring the native shell.
 $restartMarker=Join-Path (Split-Path $PSScriptRoot) 'Shell10-Test\state\restart-in-progress.json'
 $restartDeadline=(Get-Date).AddSeconds(30)
 while((Test-Path -LiteralPath $restartMarker) -and [Explorer10Probe]::Owner('Progman') -eq 0 -and (Get-Date) -lt $restartDeadline){Start-Sleep -Milliseconds 200}
 if([Explorer10Probe]::Owner('Progman') -eq 0){Start-Process -FilePath $nativeExe}
}

exit 1
