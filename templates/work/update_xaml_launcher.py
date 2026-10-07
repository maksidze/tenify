from pathlib import Path
import shutil,json,hashlib
p=Path('outputs/Start-Explorer10-Xaml.ps1')
s=p.read_text(encoding='utf-8-sig')
s=s.replace('param([switch]$Guard, [string]$RunDirectory)','param([switch]$Guard, [string]$RunDirectory, [switch]$PreflightOnly)')
s=s.replace("$regPath='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'", "$regPath='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'\n$manifestRegPath='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide'")
s=s.replace('public static class Explorer10Probe {', '''public static class Explorer10Probe {
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
  if(!CreateProcess(exe,new System.Text.StringBuilder("\\\""+exe+"\\\""),IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,System.IO.Path.GetDirectoryName(exe),ref si,out pi))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  try {if(!TerminateProcess(pi.process,0))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());WaitForSingleObject(pi.process,5000);}
  finally {CloseHandle(pi.thread);CloseHandle(pi.process);}
 }''')
s=s.replace('$saved=$null; $changed=$false', '$saved=$null; $changed=$false; $manifestChanged=$false')
s=s.replace('  $properties=Get-ItemProperty -LiteralPath $regPath', '''  $manifestProperties=Get-ItemProperty -LiteralPath $manifestRegPath
  $manifestExisted=$null -ne $manifestProperties.PSObject.Properties['PreferExternalManifest']
  $manifestSaved=if($manifestExisted){$manifestProperties.PreferExternalManifest}else{$null}
  $manifestKind=if($manifestExisted){(Get-Item -LiteralPath $manifestRegPath).GetValueKind('PreferExternalManifest').ToString()}else{$null}
  @{Existed=$manifestExisted;Value=$manifestSaved;Kind=$manifestKind} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunDirectory 'manifest-registry-backup.json')
  New-ItemProperty -LiteralPath $manifestRegPath -Name PreferExternalManifest -PropertyType DWord -Value 1 -Force | Out-Null
  $manifestChanged=$true; Write-Status 'External manifest preference temporarily enabled'
  $properties=Get-ItemProperty -LiteralPath $regPath''')
s=s.replace('  if($changed) {', '''  if($manifestChanged) {
   if($manifestExisted){New-ItemProperty -LiteralPath $manifestRegPath -Name PreferExternalManifest -PropertyType $manifestKind -Value $manifestSaved -Force | Out-Null}
   else{Remove-ItemProperty -LiteralPath $manifestRegPath -Name PreferExternalManifest}
   Write-Status 'Original external manifest preference restored'
  }
  if($changed) {''')
needle="if((Get-Item -LiteralPath $oldExe).VersionInfo.FileVersion -notlike '10.0.19041.*'){throw 'Unexpected Explorer version'}"
s=s.replace(needle,needle+'''
if((Get-AuthenticodeSignature -LiteralPath $oldExe).Status -ne 'Valid'){throw 'Explorer signature is not valid. Current shell has not been stopped.'}
if(-not(Test-Path -LiteralPath ($oldExe+'.manifest'))){throw 'Missing external XAML manifest. Current shell has not been stopped.'}
[Explorer10Probe]::Preflight($oldExe)
if($PreflightOnly){Write-Host 'PASS: signature valid; suspended process created and removed. Current shell was not restarted. XAML UI requires a separate interactive test.';exit 0}''')
s=s.replace(" $shellOwner=[Explorer10Probe]::Owner('Progman')", " [Explorer10Probe]::Preflight($oldExe)\n Write-Status 'Signed Explorer preflight passed with external manifest preference'\n $shellOwner=[Explorer10Probe]::Owner('Progman')")
p.write_text(s,encoding='utf-8-sig')
dst=Path('outputs/Explorer10-Xaml')
shutil.copy2(dst/'explorer.exe','work/explorer10-embedded-patched.exe')
original=Path(r'C:\Users\MAKSIDZE\Documents\Explorer_10\explorer.exe')
shutil.copy2(original,dst/'explorer.exe')
shutil.copy2(dst/'explorer.manifest.xml',dst/'explorer.exe.manifest')
info=json.loads((dst/'patch-info.json').read_text(encoding='utf-8-sig'))
info.update({'method':'Signed, byte-identical Explorer with external manifest; temporary PreferExternalManifest during startup','activeExeSHA256':hashlib.sha256((dst/'explorer.exe').read_bytes()).hexdigest(),'signature':'Original Microsoft Authenticode signature retained','embeddedPatchActive':False,'interactiveXamlVerified':False})
(dst/'patch-info.json').write_text(json.dumps(info,ensure_ascii=False,indent=2),encoding='utf-8')
# Restarting this variant from the BAT settings menu needs its matching guard.
p=Path('outputs/Shell10-Test/SettingsBackend.ps1');s=p.read_text(encoding='utf-8-sig')
s=s.replace("$guardScript=Join-Path (Split-Path $PSScriptRoot) 'Start-Explorer10.ps1'", "$guardScript=Join-Path (Split-Path $PSScriptRoot) 'Start-Explorer10.ps1'\n if($oldExe -ieq $patchedExe){$guardScript=Join-Path (Split-Path $PSScriptRoot) 'Start-Explorer10-Xaml.ps1'}")
p.write_text(s,encoding='utf-8-sig')
