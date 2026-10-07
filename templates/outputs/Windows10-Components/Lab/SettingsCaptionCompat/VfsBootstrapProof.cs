using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class VfsBootstrapProof {
 [DllImport("ole32.dll")]static extern int CoInitializeEx(IntPtr p,uint flags);
 [DllImport("ole32.dll")]static extern void CoUninitialize();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr LoadLibraryEx(string path,IntPtr h,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)]static extern IntPtr GetProcAddress(IntPtr h,string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern IntPtr GetModuleHandle(string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern uint GetModuleFileName(IntPtr h,StringBuilder p,uint n);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern uint K32GetMappedFileName(IntPtr process,IntPtr address,StringBuilder p,uint n);
 [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")]static extern IntPtr GetConsoleWindow();
 [DllImport("kernel32.dll")]static extern bool VirtualProtect(IntPtr p,UIntPtr n,uint protection,out uint old);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate uint Init(IntPtr p);
 [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)]delegate int Verify(IntPtr module,string expected);
 public static int Main(string[] a){if(a.Length!=4)return 64;using(var log=new StreamWriter(a[0],false,new UTF8Encoding(false))){log.AutoFlush=true;bool co=false;IntPtr vm=IntPtr.Zero;byte original=0;bool altered=false;try{
  log.WriteLine("Console="+GetConsoleWindow());
  int hr=CoInitializeEx(IntPtr.Zero,0);log.WriteLine("CoInit="+hr.ToString("X8"));Marshal.ThrowExceptionForHR(hr);co=true;
  if(a[3]=="bad-byte") {vm=LoadLibraryEx(a[2],IntPtr.Zero,8);if(vm==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());IntPtr target=IntPtr.Add(vm,0x4bab0);original=Marshal.ReadByte(target);uint old,tmp;if(!VirtualProtect(target,(UIntPtr)1,0x40,out old))throw new Exception("Own byte protection");Marshal.WriteByte(target,(byte)(original^1));VirtualProtect(target,(UIntPtr)1,old,out tmp);altered=true;}
  IntPtr module=LoadLibraryEx(a[1],IntPtr.Zero,0x1100);if(module==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  var initialize=(Init)Marshal.GetDelegateForFunctionPointer(GetProcAddress(module,"SettingsInitialize"),typeof(Init));uint result=initialize(IntPtr.Zero);log.WriteLine("CompositeInitialize="+result.ToString("X8"));
  vm=GetModuleHandle("SystemSettingsViewModel.Desktop.dll");var logical=new StringBuilder(4096);var physical=new StringBuilder(4096);GetModuleFileName(vm,logical,4096);K32GetMappedFileName(GetCurrentProcess(),vm,physical,4096);log.WriteLine("VM_LOGICAL="+logical);log.WriteLine("VM_PHYSICAL="+physical);
  IntPtr verifyAddress=GetProcAddress(module,"SettingsCaptionMappedModuleMatches");if(verifyAddress!=IntPtr.Zero){var verify=(Verify)Marshal.GetDelegateForFunctionPointer(verifyAddress,typeof(Verify));log.WriteLine("VERIFY_REAL_VM="+verify(vm,a[2]));log.WriteLine("VERIFY_WRONG_MODULE="+verify(GetModuleHandle("kernel32.dll"),a[2]));}
  int installed=Marshal.ReadInt32(GetProcAddress(module,"SettingsCaptionInstalled"));log.WriteLine("CaptionInstalled="+installed);
  if(installed!=0){var restore=(Init)Marshal.GetDelegateForFunctionPointer(GetProcAddress(module,"SettingsCaptionRestore"),typeof(Init));log.WriteLine("OwnRestore="+restore(IntPtr.Zero).ToString("X8"));}
  return a[3]=="bad-byte"?(result==0x8007051aU&&installed==0?0:4):(result==0&&installed==1?0:1);
 }catch(Exception e){log.WriteLine(e);return 3;}finally{if(altered&&vm!=IntPtr.Zero){IntPtr target=IntPtr.Add(vm,0x4bab0);uint old,tmp;if(VirtualProtect(target,(UIntPtr)1,0x40,out old)){Marshal.WriteByte(target,original);VirtualProtect(target,(UIntPtr)1,old,out tmp);}}if(co)CoUninitialize();}}}
}
