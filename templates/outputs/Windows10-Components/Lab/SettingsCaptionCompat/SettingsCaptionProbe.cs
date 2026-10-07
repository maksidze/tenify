using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Windows.ApplicationModel.Resources.Core;

public static class SettingsCaptionProbe {
 [DllImport("combase.dll")] static extern int RoInitialize(int type);
 [DllImport("combase.dll")] static extern void RoUninitialize();
 [DllImport("combase.dll", CharSet=CharSet.Unicode)] static extern int WindowsCreateString(string s,int n,out IntPtr value);
 [DllImport("combase.dll")] static extern int WindowsDeleteString(IntPtr value);
 [DllImport("combase.dll")] static extern int RoGetActivationFactory(IntPtr name,ref Guid iid,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetPtr(IntPtr p,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)] delegate int LoadPri(IntPtr p,string path);
 static T Slot<T>(IntPtr p,int n) { return (T)(object)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(p),n*IntPtr.Size),typeof(T)); }
 static StreamWriter log;
 static string Safe(string x) { return (x??"<null>").Replace("\r","\\r").Replace("\n","\\n").Replace("\t","\\t"); }
 static void HR(string name,int hr) { log.WriteLine(name+"\t"+hr.ToString("X8")); log.Flush(); Marshal.ThrowExceptionForHR(hr); }
 static void Release(ref IntPtr p) { if(p!=IntPtr.Zero) { Marshal.Release(p); p=IntPtr.Zero; } }
 static readonly string[] ids={"SettingsPagePCSystemDisplay","SettingsPageAudio","SettingsPageAppsNotifications","SettingsPageAbout_ControlPanelSystem","SettingsPageAbout","SettingsPageAbout_New","SettingsPagePCSystemInfo"};
 static string Qualifiers(ResourceCandidate c) { var rows=new List<string>(); foreach(var q in c.Qualifiers) rows.Add(q.QualifierName+"="+q.QualifierValue); return String.Join(";",rows.ToArray()); }
 static void Query(ResourceMap map,string key,ResourceContext context,string language) {
  try { var c=map.GetValue(key,context); log.WriteLine("VALUE\t"+Safe(key)+"\t"+language+"\t"+Safe(c.ValueAsString)+"\t"+Safe(Qualifiers(c))); }
  catch(Exception e) { log.WriteLine("VALUE_ERROR\t"+Safe(key)+"\t"+language+"\t"+e.HResult.ToString("X8")); }
 }
 public static int Main(string[] args) {
  if(args.Length<2||args.Length>3)return 64;
  IntPtr name=IntPtr.Zero,factory=IntPtr.Zero,manager=IntPtr.Zero,extension=IntPtr.Zero; bool ro=false;
  using(log=new StreamWriter(args[0],false,new UTF8Encoding(false))) { log.AutoFlush=true;
   try {
    int hr=RoInitialize(1);HR("RoInitialize",hr);ro=true;
    string cls="Windows.ApplicationModel.Resources.Core.ResourceManager";HR("String",WindowsCreateString(cls,cls.Length,out name));
    Guid statics=new Guid("4a8eac58-b652-459d-8de1-239471e8b22b");HR("Factory",RoGetActivationFactory(name,ref statics,out factory));
    HR("GetCurrentResourceManagerForSystemProfile",Slot<GetPtr>(factory,7)(factory,out manager));
    if(args[1]=="old") { if(args.Length!=3)return 65;Guid ext=new Guid("8c25e859-1042-4da0-9232-bf2aa8ff3726");HR("QIExtension",Marshal.QueryInterface(manager,ref ext,out extension));HR("LoadPriFileForSystemUse",Slot<LoadPri>(extension,6)(extension,args[2])); }
    else if(args[1]!="native") return 66;
    var map=ResourceManager.Current.AllResourceMaps["Windows.UI.SettingsAppThreshold"];
    log.WriteLine("MAP\t"+map.Uri+"\t"+map.Count);
    var keys=new List<string>();
    foreach(var key in map.Keys) {
     foreach(var id in ids) if(key.IndexOf("/"+id+"/",StringComparison.Ordinal)>=0 || key.EndsWith("/"+id,StringComparison.Ordinal)) {keys.Add(key);break;}
    }
    foreach(var key in keys) {
     log.WriteLine("KEY\t"+key);
     foreach(string lang in new[]{"ru-RU","en-US"}) {var context=new ResourceContext();context.QualifierValues["Language"]=lang;Query(map,key,context,lang);}
     try { var named=map[key];foreach(var c in named.Candidates) log.WriteLine("CANDIDATE\t"+Safe(key)+"\t"+Safe(c.ValueAsString)+"\t"+Safe(Qualifiers(c))); }
     catch(Exception e){log.WriteLine("CANDIDATE_ERROR\t"+Safe(key)+"\t"+e.HResult.ToString("X8"));}
    }
    log.WriteLine("COMPLETE\tkeys="+keys.Count+"\tmode="+args[1]);return keys.Count>0?0:67;
   }catch(Exception e) {log.WriteLine("ERROR\t"+e.HResult.ToString("X8")+"\t"+Safe(e.ToString()));return 1;}
   finally {Release(ref extension);Release(ref manager);Release(ref factory);if(name!=IntPtr.Zero)WindowsDeleteString(name);if(ro)RoUninitialize();}
  }
 }
}
