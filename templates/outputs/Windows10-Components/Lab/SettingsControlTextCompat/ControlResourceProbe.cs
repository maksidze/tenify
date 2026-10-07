using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Windows.ApplicationModel.Resources.Core;
using Windows.Foundation;
using Windows.Storage.Streams;
public static class ControlResourceProbe {
 [DllImport("combase.dll")]static extern int RoInitialize(int type);
 [DllImport("combase.dll")]static extern void RoUninitialize();
 [DllImport("combase.dll",CharSet=CharSet.Unicode)]static extern int WindowsCreateString(string name,int length,out IntPtr value);
 [DllImport("combase.dll")]static extern int WindowsDeleteString(IntPtr value);
 [DllImport("combase.dll")]static extern int RoGetActivationFactory(IntPtr name,ref Guid iid,out IntPtr result);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GetPtr(IntPtr p,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)]delegate int LoadPri(IntPtr p,string path);
 static T Slot<T>(IntPtr p,int n){return (T)(object)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(p),n*IntPtr.Size),typeof(T));}
 static void Release(ref IntPtr p){if(p!=IntPtr.Zero){Marshal.Release(p);p=IntPtr.Zero;}}
 static string Safe(string s){return (s??"<null>").Replace("\r","\\r").Replace("\n","\\n").Replace("\t","\\t");}
 static void Wait(IAsyncInfo operation){var until=DateTime.UtcNow.AddSeconds(5);while(operation.Status==AsyncStatus.Started&&DateTime.UtcNow<until)System.Threading.Thread.Sleep(10);if(operation.Status!=AsyncStatus.Completed){operation.Cancel();throw new TimeoutException("Candidate stream did not complete: "+operation.Status);}}
 public static int Main(string[] args){if(args.Length!=4)return 64;IntPtr name=IntPtr.Zero,factory=IntPtr.Zero,manager=IntPtr.Zero,ext=IntPtr.Zero;bool ro=false;
  using(var log=new StreamWriter(args[0],false,new UTF8Encoding(false))){log.AutoFlush=true;try{
   Marshal.ThrowExceptionForHR(RoInitialize(1));ro=true;string cls="Windows.ApplicationModel.Resources.Core.ResourceManager";Marshal.ThrowExceptionForHR(WindowsCreateString(cls,cls.Length,out name));Guid statics=new Guid("4a8eac58-b652-459d-8de1-239471e8b22b");Marshal.ThrowExceptionForHR(RoGetActivationFactory(name,ref statics,out factory));Marshal.ThrowExceptionForHR(Slot<GetPtr>(factory,7)(factory,out manager));
   if(args[1]=="old"){Guid iid=new Guid("8c25e859-1042-4da0-9232-bf2aa8ff3726");Marshal.ThrowExceptionForHR(Marshal.QueryInterface(manager,ref iid,out ext));Marshal.ThrowExceptionForHR(Slot<LoadPri>(ext,6)(ext,args[2]));}
   var map=ResourceManager.Current.AllResourceMaps["Windows.UI.SettingsAppThreshold"];log.WriteLine("MAP\t"+map.Count);int n=0;
   foreach(string key in map.Keys){bool include=false;foreach(string s in new[]{"Taskbar","TaskBar","Display","NightLight","ColorProfile"})if(key.IndexOf(s,StringComparison.OrdinalIgnoreCase)>=0)include=true;if(!include)continue;
    try{var context=new ResourceContext();context.QualifierValues["Language"]="ru-RU";var candidate=map.GetValue(key,context);
     if(candidate.Kind==ResourceCandidateKind.EmbeddedData&&key.EndsWith(".xbf",StringComparison.OrdinalIgnoreCase)){
      var operation=candidate.GetValueAsStreamAsync();Wait(operation);var stream=operation.GetResults();if(stream.Size>16777216)throw new InvalidDataException("Embedded data exceeds bound");using(var reader=new DataReader(stream)){var load=reader.LoadAsync((uint)stream.Size);Wait(load);uint size=load.GetResults();byte[] bytes=new byte[size];reader.ReadBytes(bytes);string file=Path.Combine(args[3],(n++).ToString("D3")+"-"+Path.GetFileName(key));File.WriteAllBytes(file,bytes);log.WriteLine("XBF\t"+key+"\t"+file+"\t"+size);}operation.Close();
     }else log.WriteLine("VALUE\t"+key+"\t"+Safe(candidate.ValueAsString));
    }catch(Exception e){log.WriteLine("ERROR\t"+key+"\t"+e.HResult.ToString("X8")+"\t"+Safe(e.Message));}
   }
   return 0;
  }catch(Exception e){log.WriteLine(e);return 1;}finally{Release(ref ext);Release(ref manager);Release(ref factory);if(name!=IntPtr.Zero)WindowsDeleteString(name);if(ro)RoUninitialize();}}
 }
}
