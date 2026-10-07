param([Parameter(Mandatory=$true)][int]$TargetPid)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
Add-Type @'
using System;using System.Runtime.InteropServices;using System.Text;
public static class AppThemeIdentity {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint a,bool b,uint p);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint f,StringBuilder p,ref uint n);
 [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 public static string[] Read(int pid){IntPtr h=OpenProcess(0x1000,false,(uint)pid);if(h==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();try{StringBuilder p=new StringBuilder(32768);uint n=32768;long c,e,k,u;if(!QueryFullProcessImageName(h,0,p,ref n)||!GetProcessTimes(h,out c,out e,out k,out u))throw new System.ComponentModel.Win32Exception();return new string[]{p.ToString(),c.ToString()};}finally{CloseHandle(h);}}
}
'@
$identity=[AppThemeIdentity]::Read($TargetPid)
if($identity[0].StartsWith($env:WINDIR,[StringComparison]::OrdinalIgnoreCase)){throw 'This launcher is for explicitly selected third-party applications.'}
$run=Join-Path $PSScriptRoot ('state\app-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($run)|Out-Null
$config=Join-Path $run 'selected.json'
@{Pid=$TargetPid;Birth=[UInt64]$identity[1];Path=$identity[0];SHA256=(Get-FileHash -LiteralPath $identity[0]).Hash.ToLowerInvariant()}|ConvertTo-Json|Set-Content -LiteralPath $config -Encoding UTF8
$python='@PYTHON_DIR@\pythonw.exe'
$script=Join-Path $PSScriptRoot 'Apply.py'
$arguments=@(('"'+$script+'"'),('"'+$config+'"'))
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($admin){$controller=Start-Process -FilePath $python -ArgumentList $arguments -WindowStyle Hidden -PassThru}else{$controller=Start-Process -FilePath $python -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru}
if(!$controller.WaitForExit(20000)){throw ('App style installer is still pending. Do not restart it. '+$run)}
$result=Join-Path $run 'selected.result.json'
if(!(Test-Path -LiteralPath $result)){throw ('No report. '+$run)}
Get-Content -LiteralPath $result -Raw -Encoding UTF8
