from pathlib import Path
p=Path('outputs/Windows10-Components/Lab/SettingsBrokerCompat/Restore-SettingsBroker.ps1')
s=p.read_text(encoding='utf-8-sig').lstrip('\ufeff');a=s.index(' $terminated=@()');z=s.index(' [pscustomobject]@{RestoreUtc=',a)
block=r''' $terminated=@();$claimStatus='NoClaim'
 if(-not ('SettingsClaimIdentity' -as [type])){Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class SettingsClaimIdentity {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out ulong born,out ulong exit,out ulong kernel,out ulong user);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder s,ref uint count);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern int GetPackageFullName(IntPtr h,ref uint n,StringBuilder s);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr h,uint code);
 public static int Stop(uint pid,ulong expectedBorn,string expectedPath,string expectedPackage){
  IntPtr h=OpenProcess(0x101001,false,pid);if(h==IntPtr.Zero)return Marshal.GetLastWin32Error()==87?0:4;
  try{if(WaitForSingleObject(h,0)==0)return 2;ulong born,exit,kernel,user;if(!GetProcessTimes(h,out born,out exit,out kernel,out user))return 4;
   var image=new StringBuilder(32768);uint n=32768;if(born!=expectedBorn||!QueryFullProcessImageName(h,0,image,ref n)||!String.Equals(image.ToString(),expectedPath,StringComparison.OrdinalIgnoreCase))return 3;
   var pkg=new StringBuilder(4096);n=4096;if(GetPackageFullName(h,ref n,pkg)!=0||pkg.ToString()!=expectedPackage)return 3;
   if(!TerminateProcess(h,0xdec0))return 4;return WaitForSingleObject(h,5000)==0?1:4;
  }finally{CloseHandle(h);}
 }
}
'@
 }
 $claim=$state.Report+'.claim'
 if(Test-Path -LiteralPath $claim){
  $bytes=[IO.File]::ReadAllBytes($claim)
  if($bytes.Length -eq 16 -and [BitConverter]::ToUInt32($bytes,0) -eq 1396919346){
   $child=[BitConverter]::ToUInt32($bytes,4);$born=[BitConverter]::ToUInt64($bytes,8)
   $result=[SettingsClaimIdentity]::Stop($child,$born,$state.NativePath,$state.PackageFullName)
   $claimStatus=@('NotRunning','ExactOwnedTerminated','AlreadyExited','IdentityMismatchRefused','HandleOperationFailed')[$result]
   if($result -eq 1){$terminated+=$child};if($result -eq 4){throw 'Exact owned Settings handle termination failed; retain guard evidence.'}
  }else{$claimStatus='LegacyOrInvalidClaimRefused'}
 }
'''
s=s[:a]+block+s[z:];s=s.replace('OtherPackageProcessesUntouched=$true}', 'OtherPackageProcessesUntouched=$true;ClaimStatus=$claimStatus}');p.write_text(s,encoding='utf-8-sig')
assert 1396919346==0x53434c32
p=Path('outputs/Windows10-Components/Stop-Settings10.ps1');s=p.read_text(encoding='utf-8-sig').lstrip('\ufeff');s=s.replace('$prepared=Get-Content', "[IO.File]::WriteAllText(($preparedPath+'.cancel'),'Manual cancellation requested')\n$prepared=Get-Content",1)
s=s.replace("if($states.Count -ne 1){throw ('Expected one exact report-owned session; found '+$states.Count)}", "if($states.Count -eq 0){Write-Host 'Startup cancellation recorded; no broker state exists yet.';return}\nif($states.Count -ne 1){throw ('Expected one exact report-owned session; found '+$states.Count)}")
p.write_text(s,encoding='utf-8-sig')
