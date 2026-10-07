using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class BootstrapChainProof {
 [DllImport("ole32.dll")]static extern int CoInitializeEx(IntPtr p,uint flags);
 [DllImport("ole32.dll")]static extern void CoUninitialize();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr LoadLibraryEx(string path,IntPtr h,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)]static extern IntPtr GetProcAddress(IntPtr h,string name);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate uint Init(IntPtr p);
 public static int Main(string[] a){if(a.Length!=2)return 64;using(var log=new StreamWriter(a[0],false,new UTF8Encoding(false))){log.AutoFlush=true;bool co=false;try{
  int hr=CoInitializeEx(IntPtr.Zero,0);log.WriteLine("CoInit="+hr.ToString("X8"));Marshal.ThrowExceptionForHR(hr);co=true;
  IntPtr module=LoadLibraryEx(a[1],IntPtr.Zero,0x1100);if(module==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  var initialize=(Init)Marshal.GetDelegateForFunctionPointer(GetProcAddress(module,"SettingsInitialize"),typeof(Init));uint result=initialize(IntPtr.Zero);log.WriteLine("CompositeInitialize="+result.ToString("X8"));if(result!=0)return 1;
  int installed=Marshal.ReadInt32(GetProcAddress(module,"SettingsCaptionInstalled"));log.WriteLine("CaptionInstalled="+installed);
  var restore=(Init)Marshal.GetDelegateForFunctionPointer(GetProcAddress(module,"SettingsCaptionRestore"),typeof(Init));result=restore(IntPtr.Zero);log.WriteLine("OwnCaptionRestore="+result.ToString("X8"));log.WriteLine("CaptionInstalledAfter="+Marshal.ReadInt32(GetProcAddress(module,"SettingsCaptionInstalled")));
  log.WriteLine("COMPLETE own process only; retained SystemProfile worker is reclaimed on process exit");return installed==1&&result==0?0:2;
 }catch(Exception e){log.WriteLine(e);return 3;}finally{if(co)CoUninitialize();}}}
}
