using System;using System.IO;using System.Text;using System.Runtime.InteropServices;
class TaskbarProviderProbe {
 [DllImport("combase.dll")]static extern int RoInitialize(int kind);
 [DllImport("combase.dll")]static extern void RoUninitialize();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr LoadLibraryEx(string path,IntPtr file,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)]static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("combase.dll",CharSet=CharSet.Unicode)]static extern int WindowsCreateString(string text,int length,out IntPtr value);
 [DllImport("combase.dll")]static extern int WindowsDeleteString(IntPtr value);
 [DllImport("combase.dll")]static extern IntPtr WindowsGetStringRawBuffer(IntPtr value,out uint length);
 [DllImport("combase.dll")]static extern int RoGetActivationFactory(IntPtr name,ref Guid iid,out IntPtr factory);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GetPointer(IntPtr self,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)]delegate int LoadPri(IntPtr self,string path);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GetSetting(IntPtr id,out IntPtr result);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GetString(IntPtr self,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GetType(IntPtr self,out int value);
 static T Slot<T>(IntPtr value,int slot){return (T)(object)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(value),slot*8),typeof(T));}
 static void Drop(ref IntPtr value){if(value!=IntPtr.Zero){Marshal.Release(value);value=IntPtr.Zero;}}
 static string Read(IntPtr value){uint size;IntPtr p=WindowsGetStringRawBuffer(value,out size);if(size>65536)throw new Exception("Oversize HSTRING");return Marshal.PtrToStringUni(p,(int)size);}
 static int Main(string[] args){if(args.Length<3||args.Length>4)return 64;bool initialized=false;IntPtr resourceName=IntPtr.Zero,factory=IntPtr.Zero,manager=IntPtr.Zero,extension=IntPtr.Zero;using(var log=new StreamWriter(args[0],false,new UTF8Encoding(false))){log.AutoFlush=true;try{
  int hr=RoInitialize(1);Marshal.ThrowExceptionForHR(hr);initialized=true;
  if(args.Length==4){string cls="Windows.ApplicationModel.Resources.Core.ResourceManager";Marshal.ThrowExceptionForHR(WindowsCreateString(cls,cls.Length,out resourceName));Guid statics=new Guid("4a8eac58-b652-459d-8de1-239471e8b22b");Marshal.ThrowExceptionForHR(RoGetActivationFactory(resourceName,ref statics,out factory));Marshal.ThrowExceptionForHR(Slot<GetPointer>(factory,7)(factory,out manager));Guid ext=new Guid("8c25e859-1042-4da0-9232-bf2aa8ff3726");Marshal.ThrowExceptionForHR(Marshal.QueryInterface(manager,ref ext,out extension));hr=Slot<LoadPri>(extension,6)(extension,args[3]);log.WriteLine("LOAD_OLD_PRI\t"+hr.ToString("X8"));Marshal.ThrowExceptionForHR(hr);}
  IntPtr module=LoadLibraryEx(args[1],IntPtr.Zero,8);if(module==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  IntPtr address=GetProcAddress(module,"GetSetting");if(address==IntPtr.Zero||address.ToInt64()-module.ToInt64()!=Convert.ToInt64(args[2],16))throw new Exception("GetSetting export RVA mismatch");
  var get=(GetSetting)(object)Marshal.GetDelegateForFunctionPointer(address,typeof(GetSetting));
  foreach(string id in new[]{"SystemSettings_Taskbar_Lock","SystemSettings_Taskbar_Autohide","SystemSettings_Taskbar_SmallButtons","SystemSettings_Taskbar_Badging","SystemSettings_Taskbar_Location","SystemSettings_Taskbar_GlommingPrimary","SystemSettings_Taskbar_PeekPreviewDesktop","SystemSettings_Taskbar_ReplaceCommandPromptWithPowerShellWinX"}){
   IntPtr key=IntPtr.Zero,obj=IntPtr.Zero,item=IntPtr.Zero,text=IntPtr.Zero;
   try{Marshal.ThrowExceptionForHR(WindowsCreateString(id,id.Length,out key));hr=get(key,out obj);log.WriteLine("SETTING\t"+id+"\t"+hr.ToString("X8"));if(hr<0||obj==IntPtr.Zero)continue;
    Guid iid=new Guid("40c037cc-d8bf-489e-8697-d66baa3221bf");hr=Marshal.QueryInterface(obj,ref iid,out item);log.WriteLine("QI\t"+hr.ToString("X8"));if(hr<0||item==IntPtr.Zero)continue;
    log.WriteLine("DESCRIPTION_RVA\t"+(Marshal.ReadIntPtr(Marshal.ReadIntPtr(item),11*8).ToInt64()-module.ToInt64()).ToString("X"));
    int type;hr=Slot<GetType>(item,7)(item,out type);log.WriteLine("TYPE\t"+hr.ToString("X8")+"\t"+type);
    hr=Slot<GetString>(item,6)(item,out text);log.WriteLine("ID\t"+hr.ToString("X8")+"\t"+(hr>=0?Read(text):""));if(text!=IntPtr.Zero){WindowsDeleteString(text);text=IntPtr.Zero;}
    hr=Slot<GetString>(item,11)(item,out text);log.WriteLine("DESCRIPTION\t"+hr.ToString("X8")+"\t"+(hr>=0?Read(text):""));
   }finally{if(text!=IntPtr.Zero)WindowsDeleteString(text);Drop(ref item);Drop(ref obj);if(key!=IntPtr.Zero)WindowsDeleteString(key);}
  }
  log.WriteLine("COMPLETE read-only provider queries; no setters, no Settings activation");return 0;
 }catch(Exception e){log.WriteLine(e);return 1;}finally{Drop(ref extension);Drop(ref manager);Drop(ref factory);if(resourceName!=IntPtr.Zero)WindowsDeleteString(resourceName);if(initialized)RoUninitialize();}}}
}
