using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class SettingsApplicabilityProbe {
 [DllImport("ole32.dll")] static extern int CoInitializeEx(IntPtr p,uint flags);
 [DllImport("ole32.dll")] static extern void CoUninitialize();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryEx(string p,IntPtr file,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetModuleFileName(IntPtr module,StringBuilder path,int chars);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandle(string name);
 [DllImport("combase.dll",CharSet=CharSet.Unicode)] static extern int WindowsCreateString(string p,int length,out IntPtr value);
 [DllImport("combase.dll")] static extern int WindowsDeleteString(IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetDesktop(out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetFactory(IntPtr name,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetPtr(IntPtr self,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetIids(IntPtr self,out uint count,out IntPtr array);
 [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)] delegate int IsApplicable(IntPtr self,string name,IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int IsSettingApplicable(IntPtr self,IntPtr name,IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint Initialize(IntPtr ignored);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate void LambdaCall(IntPtr context);
 static T From<T>(IntPtr p) { return (T)(object)Marshal.GetDelegateForFunctionPointer(p,typeof(T)); }
 static IntPtr Method(IntPtr p,int n) { return Marshal.ReadIntPtr(Marshal.ReadIntPtr(p),n*IntPtr.Size); }
 static T Slot<T>(IntPtr p,int n) { return From<T>(Method(p,n)); }
 static StreamWriter log;
 static void HR(string n,int hr){log.WriteLine(n+"\t"+hr.ToString("X8"));Marshal.ThrowExceptionForHR(hr);}
 static void Release(ref IntPtr p){if(p!=IntPtr.Zero){Marshal.Release(p);p=IntPtr.Zero;}}
 static readonly string[] ids={"SettingsGroupEntry","SettingsGroupDisplayMonitorSettings","SettingsGroupDisplayBrightnessColorSettings","SettingsGroupDisplayHDColorSettings","SettingsGroupDisplayScaleAndLayoutSettings","SettingsGroupDisplayMultiDisplaySettings","SettingsGroupExtensionApps"};
 public static int Main(string[] args) {
  if(args.Length!=4&&args.Length!=5)return 64; bool co=false;IntPtr factory=IntPtr.Zero,statics=IntPtr.Zero,environment=IntPtr.Zero,db=IntPtr.Zero,name=IntPtr.Zero,buffer=IntPtr.Zero,iids=IntPtr.Zero;
  using(log=new StreamWriter(args[0],false,new UTF8Encoding(false))) {log.AutoFlush=true;try {
   int hr=CoInitializeEx(IntPtr.Zero,0);HR("CoInitializeMTA",hr);co=true;
   IntPtr module=LoadLibraryEx(args[2],IntPtr.Zero,8);if(module==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   var path=new StringBuilder(32768);GetModuleFileName(module,path,path.Capacity);log.WriteLine("MODULE\t"+path);
   long expected=Convert.ToInt64(args[3],16);IntPtr target;
   if(args[1]=="public") {
    string cls="SystemSettings.DataModel.SettingsEnvironmentDatabase";HR("HString",WindowsCreateString(cls,cls.Length,out name));
    HR("Factory",From<GetFactory>(GetProcAddress(module,"DllGetActivationFactory"))(name,out factory));
    Guid sid=new Guid("faedfc6b-cb6b-4533-843c-4f394bfd66d5");HR("QIStatics",Marshal.QueryInterface(factory,ref sid,out statics));
    HR("GetSettingsEnvironment",Slot<GetPtr>(statics,6)(statics,out environment));
    Guid iid=new Guid("acbe964b-0eed-4d11-9ca9-fdeb63598d2e");HR("QI_ISettingsEnvironmentDatabase",Marshal.QueryInterface(environment,ref iid,out db));target=db;
   } else if(args[1]=="private") {HR("GetDesktopSettingsEnvironment",From<GetDesktop>(GetProcAddress(module,"GetDesktopSettingsEnvironment"))(out environment));target=environment;}
   else return 65;
   uint count=0;HR("GetIids",Slot<GetIids>(target,3)(target,out count,out iids));if(count>64)throw new InvalidDataException("IID count exceeds bound");
   for(uint n=0;n<count;n++){byte[] bytes=new byte[16];Marshal.Copy(new IntPtr(iids.ToInt64()+n*16),bytes,0,16);Guid g=new Guid(bytes);IntPtr queried;int qi=Marshal.QueryInterface(target,ref g,out queried);log.WriteLine("IID\t"+g+"\tQI="+qi.ToString("X8")+"\tsame="+(queried==target));Release(ref queried);}
   Marshal.FreeCoTaskMem(iids);iids=IntPtr.Zero;
   int slot=args[1]=="private"?7:6;long actual=Method(target,slot).ToInt64()-module.ToInt64();log.WriteLine("METHOD\tslot="+slot+"\trva="+actual.ToString("X"));if(actual!=expected)throw new InvalidDataException("Exact method RVA mismatch");
   IntPtr helper=IntPtr.Zero;IsSettingApplicable merged=null;if(args.Length==5){if(args[1]!="public")throw new ArgumentException("Merge fixture requires public native database");helper=LoadLibraryEx(args[4],IntPtr.Zero,0x1100);if(helper==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());merged=From<IsSettingApplicable>(GetProcAddress(helper,"SettingsCaptionQuery"));}
   buffer=Marshal.AllocHGlobal(24);bool valid=true;
   foreach(string id in ids) {
    for(int i=0;i<24;i++)Marshal.WriteByte(buffer,i,0xA5);Marshal.WriteByte(buffer,8,0);IntPtr value=IntPtr.Add(buffer,8),key=IntPtr.Zero;
    try {if(args[1]=="private")hr=Slot<IsApplicable>(target,slot)(target,id,value);else {HR("KeyString",WindowsCreateString(id,id.Length,out key));hr=Slot<IsSettingApplicable>(target,slot)(target,key,value);}}
    finally {if(key!=IntPtr.Zero)WindowsDeleteString(key);}
    bool canary=true;for(int i=0;i<24;i++)if(i!=8&&Marshal.ReadByte(buffer,i)!=0xA5)canary=false;
    log.WriteLine("APPLICABLE\t"+id+"\t"+hr.ToString("X8")+"\t"+Marshal.ReadByte(value)+"\tcanary="+canary);valid&=hr>=0&&canary;
    if(merged!=null){for(int i=0;i<24;i++)Marshal.WriteByte(buffer,i,0xA5);Marshal.WriteByte(buffer,8,0);HR("MergeString",WindowsCreateString(id,id.Length,out key));try{hr=merged(target,key,value);}finally{WindowsDeleteString(key);}canary=true;for(int i=0;i<24;i++)if(i!=8&&Marshal.ReadByte(buffer,i)!=0xA5)canary=false;log.WriteLine("MERGED\t"+id+"\t"+hr.ToString("X8")+"\t"+Marshal.ReadByte(value)+"\tcanary="+canary);valid&=hr>=0&&canary;}
   }
   if(helper!=IntPtr.Zero){
    log.WriteLine("ROUTES\told="+Marshal.ReadInt32(GetProcAddress(helper,"SettingsCaptionOldCalls"))+"\tnative="+Marshal.ReadInt32(GetProcAddress(helper,"SettingsCaptionNativeCalls")));
    uint init=From<Initialize>(GetProcAddress(helper,"SettingsCaptionInitialize"))(IntPtr.Zero);log.WriteLine("OWN_INIT\t"+init.ToString("X8"));valid&=init==0;
    IntPtr vm=GetModuleHandle("SystemSettingsViewModel.Desktop.dll");
    if(init==0&&vm!=IntPtr.Zero){
     byte[] patch=new byte[16];Marshal.Copy(IntPtr.Add(vm,0x4bab0),patch,0,16);log.WriteLine("OWN_PATCH\t"+BitConverter.ToString(patch));
     IntPtr memory=Marshal.AllocHGlobal(160);try {
      for(int i=0;i<160;i++)Marshal.WriteByte(memory,i,0);IntPtr obj=memory,context=IntPtr.Add(memory,64),keySlot=IntPtr.Add(memory,112),value=IntPtr.Add(memory,128);
      Marshal.WriteIntPtr(obj,0x30,target);Marshal.WriteIntPtr(context,8,obj);Marshal.WriteIntPtr(context,16,keySlot);Marshal.WriteIntPtr(context,24,value);
      foreach(string id in new[]{"SettingsPageAbout_New","SettingsPageAppsNotifications"}){IntPtr key;HR("LambdaString",WindowsCreateString(id,id.Length,out key));try{Marshal.WriteIntPtr(keySlot,key);Marshal.WriteByte(value,0,0xA5);Marshal.WriteByte(value,1,0xCC);From<LambdaCall>(IntPtr.Add(vm,0x4bab0))(context);log.WriteLine("OWN_LAMBDA\t"+id+"\t"+Marshal.ReadByte(value)+"\tcanary="+(Marshal.ReadByte(value,1)==0xCC));valid&=Marshal.ReadByte(value)==0&&Marshal.ReadByte(value,1)==0xCC;}finally{WindowsDeleteString(key);}}
     }finally{Marshal.FreeHGlobal(memory);}
     uint restore=From<Initialize>(GetProcAddress(helper,"SettingsCaptionRestore"))(IntPtr.Zero);log.WriteLine("OWN_RESTORE\t"+restore.ToString("X8"));Marshal.Copy(IntPtr.Add(vm,0x4bab0),patch,0,16);log.WriteLine("OWN_ORIGINAL\t"+BitConverter.ToString(patch));valid&=restore==0&&BitConverter.ToString(patch)=="48-83-EC-28-48-8B-41-08-4C-8B-41-18-4C-8B-48-30";
    }
   }
   log.WriteLine("COMPLETE\t"+valid);return valid?0:2;
  } catch(Exception e){log.WriteLine("ERROR\t"+e.HResult.ToString("X8")+"\t"+e);return 1;}
  finally{if(iids!=IntPtr.Zero)Marshal.FreeCoTaskMem(iids);if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);Release(ref db);Release(ref environment);Release(ref statics);Release(ref factory);if(name!=IntPtr.Zero)WindowsDeleteString(name);if(co)CoUninitialize();}
  }
 }
}
