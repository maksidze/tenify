using System;using System.IO;using System.Text;using System.Runtime.InteropServices;
class NtMapProbe {
 [DllImport("combase.dll")]static extern int RoInitialize(int kind);
 [DllImport("combase.dll")]static extern void RoUninitialize();
 [DllImport("combase.dll",CharSet=CharSet.Unicode)]static extern int WindowsCreateString(string text,int length,out IntPtr value);
 [DllImport("combase.dll")]static extern int WindowsDeleteString(IntPtr value);
 [DllImport("combase.dll")]static extern IntPtr WindowsGetStringRawBuffer(IntPtr value,out uint length);
 [DllImport("combase.dll")]static extern int RoGetActivationFactory(IntPtr name,ref Guid iid,out IntPtr factory);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GetPointer(IntPtr self,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Query(IntPtr self,IntPtr key,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)]delegate int LoadPri(IntPtr self,string path);
 static T Slot<T>(IntPtr value,int slot){return (T)(object)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(value),slot*8),typeof(T));}
 static void Drop(ref IntPtr value){if(value!=IntPtr.Zero){Marshal.Release(value);value=IntPtr.Zero;}}
 static IntPtr H(string text){IntPtr value;Marshal.ThrowExceptionForHR(WindowsCreateString(text,text.Length,out value));return value;}
 static string Read(IntPtr value){uint size;IntPtr p=WindowsGetStringRawBuffer(value,out size);if(size>65536)throw new Exception("Oversize HSTRING");return Marshal.PtrToStringUni(p,(int)size);}
 static int MapQuery(IntPtr self,int slot,string name,out IntPtr result){var key=H(name);try{return Slot<Query>(self,slot)(self,key,out result);}finally{WindowsDeleteString(key);}}
 static void Inspect(IntPtr manager,StreamWriter log,string label){IntPtr maps=IntPtr.Zero,map=IntPtr.Zero,sub=IntPtr.Zero;try{
  int hr=Slot<GetPointer>(manager,7)(manager,out maps);Marshal.ThrowExceptionForHR(hr);hr=MapQuery(maps,6,"Windows.UI.SettingsHandlers-nt",out map);log.WriteLine(label+" MAP "+hr.ToString("X8"));if(hr<0||map==IntPtr.Zero)return;
  hr=MapQuery(map,9,"Resources",out sub);log.WriteLine(label+" SUBTREE "+hr.ToString("X8"));if(hr<0||sub==IntPtr.Zero)return;
  foreach(string id in new[]{"SystemSettings_Taskbar_Lock","SystemSettings_Taskbar_Autohide","SystemSettings_Taskbar_SmallButtons","SystemSettings_Taskbar_Badging","SystemSettings_Taskbar_Location","SystemSettings_Taskbar_GlommingPrimary","SystemSettings_Taskbar_PeekPreviewDesktop","SystemSettings_Taskbar_ReplaceCommandPromptWithPowerShellWinX","SystemSettings_ShellMode_TaskbarTabletModeAutohide"}){IntPtr candidate=IntPtr.Zero,text=IntPtr.Zero;try{hr=MapQuery(sub,7,id+"Description",out candidate);log.WriteLine(label+" CANDIDATE "+id+" "+hr.ToString("X8")+" present="+(candidate!=IntPtr.Zero));if(hr>=0&&candidate!=IntPtr.Zero){hr=Slot<GetPointer>(candidate,10)(candidate,out text);log.WriteLine(label+" STRING "+hr.ToString("X8")+" "+(hr>=0?Read(text):""));}}finally{if(text!=IntPtr.Zero)WindowsDeleteString(text);Drop(ref candidate);}}
 }finally{Drop(ref sub);Drop(ref map);Drop(ref maps);}}
 static int Main(string[]args){if(args.Length!=2)return 64;bool initialized=false;IntPtr name=IntPtr.Zero,factory=IntPtr.Zero,manager=IntPtr.Zero,extension=IntPtr.Zero;using(var log=new StreamWriter(args[0],false,new UTF8Encoding(false))){log.AutoFlush=true;try{
  Marshal.ThrowExceptionForHR(RoInitialize(1));initialized=true;name=H("Windows.ApplicationModel.Resources.Core.ResourceManager");Guid statics=new Guid("4a8eac58-b652-459d-8de1-239471e8b22b");Marshal.ThrowExceptionForHR(RoGetActivationFactory(name,ref statics,out factory));Marshal.ThrowExceptionForHR(Slot<GetPointer>(factory,6)(factory,out manager));Inspect(manager,log,"BEFORE");
  Drop(ref manager);Marshal.ThrowExceptionForHR(Slot<GetPointer>(factory,6)(factory,out manager));
  Guid ext=new Guid("8c25e859-1042-4da0-9232-bf2aa8ff3726");Marshal.ThrowExceptionForHR(Marshal.QueryInterface(manager,ref ext,out extension));int hr=Slot<LoadPri>(extension,6)(extension,args[1]);log.WriteLine("LOAD_OLD_PRI "+hr.ToString("X8"));Marshal.ThrowExceptionForHR(hr);Inspect(manager,log,"AFTER");log.WriteLine("COMPLETE original fresh manager then distinct fresh manager loaded before map access, no UI");return 0;
 }catch(Exception e){log.WriteLine(e);return 1;}finally{Drop(ref extension);Drop(ref manager);Drop(ref factory);if(name!=IntPtr.Zero)WindowsDeleteString(name);if(initialized)RoUninitialize();}}}
}
