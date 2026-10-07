using System;using System.IO;using System.Text;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Threading;
class ControlTextFixture {
 [DllImport("combase.dll")]static extern int RoInitialize(int kind);
 [DllImport("combase.dll")]static extern void RoUninitialize();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr LoadLibraryEx(string path,IntPtr file,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)]static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern IntPtr GetModuleHandle(string name);
 [DllImport("kernel32.dll")]static extern bool VirtualProtect(IntPtr p,UIntPtr size,uint protection,out uint previous);
 [DllImport("kernel32.dll")]static extern bool FlushInstructionCache(IntPtr process,IntPtr p,UIntPtr size);
 [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
 [DllImport("combase.dll",CharSet=CharSet.Unicode)]static extern int WindowsCreateString(string text,int length,out IntPtr value);
 [DllImport("combase.dll")]static extern int WindowsDeleteString(IntPtr value);
 [DllImport("combase.dll")]static extern IntPtr WindowsGetStringRawBuffer(IntPtr value,out uint length);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Query(IntPtr p,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int NamedQuery(IntPtr p,IntPtr name,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Factory(IntPtr name,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate uint Initialize(IntPtr p);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate IntPtr Projection(IntPtr p);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int QI(IntPtr p,ref Guid iid,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate uint Ref(IntPtr p);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Iids(IntPtr p,out uint count,out IntPtr list);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Integer(IntPtr p,out int value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Boolean(IntPtr p,out byte value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int SetNamed(IntPtr p,IntPtr name,IntPtr value);
 [StructLayout(LayoutKind.Sequential)]struct Rect {public float X,Y,W,H;}
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Invoke(IntPtr p,IntPtr window,Rect bounds);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int AddEvent(IntPtr p,IntPtr callback,out long token);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int RemoveEvent(IntPtr p,long token);
 static Guid ItemIID=new Guid("40c037cc-d8bf-489e-8697-d66baa3221bf");
 static readonly string[] Keys={"SystemSettings_Taskbar_Lock","SystemSettings_Taskbar_Autohide","SystemSettings_Taskbar_SmallButtons","SystemSettings_Taskbar_Badging","SystemSettings_Taskbar_Location","SystemSettings_Taskbar_GlommingPrimary","SystemSettings_Taskbar_PeekPreviewDesktop","SystemSettings_Taskbar_ReplaceCommandPromptWithPowerShellWinX","SystemSettings_ShellMode_TaskbarTabletModeAutohide"};
 static T D<T>(IntPtr p){return (T)(object)Marshal.GetDelegateForFunctionPointer(p,typeof(T));}
 static T Slot<T>(IntPtr p,int slot){return D<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(p),slot*8));}
 static IntPtr H(string s){IntPtr result;Marshal.ThrowExceptionForHR(WindowsCreateString(s,s.Length,out result));return result;}
 static string S(IntPtr h){uint length;var p=WindowsGetStringRawBuffer(h,out length);if(length>65536)throw new Exception("oversize");return Marshal.PtrToStringUni(p,(int)length);}
 static void Drop(ref IntPtr p){if(p!=IntPtr.Zero){Marshal.Release(p);p=IntPtr.Zero;}}
 static StreamWriter Log;
 static void Assert(bool value,string label){Log.WriteLine((value?"PASS ":"FAIL ")+label);if(!value)throw new Exception(label);}
 static byte[] Bytes(IntPtr p,int count){var b=new byte[count];Marshal.Copy(p,b,0,count);return b;}
 static bool Equal(byte[] a,byte[] b){if(a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 static void Write(IntPtr p,byte[] bytes){uint previous,ignored;if(!VirtualProtect(p,(UIntPtr)bytes.Length,0x40,out previous))throw new Exception("VirtualProtect");Marshal.Copy(bytes,0,p,bytes.Length);if(!VirtualProtect(p,(UIntPtr)bytes.Length,previous,out ignored)||!FlushInstructionCache(GetCurrentProcess(),p,(UIntPtr)bytes.Length))throw new Exception("write cleanup");}
 /* Full twenty-slot ISettingItem ABI. Unused typed methods fail and are counted;
    this fixture never offers setters or fabricates a native resource string. */
 sealed class FakeItem:IDisposable {
  public string Id=Keys[0],Description="";public int DescriptionHR,IdHR;public bool Accept=true;public int Refs=1,IdCalls,DescriptionCalls,UnusedCalls;
  public IntPtr Object;IntPtr tableMemory;List<Delegate> delegates=new List<Delegate>();
  void Add(Delegate d,int slot){delegates.Add(d);Marshal.WriteIntPtr(IntPtr.Add(tableMemory,8),slot*8,Marshal.GetFunctionPointerForDelegate(d));}
  public FakeItem(){tableMemory=Marshal.AllocHGlobal(22*8);for(int n=0;n<22*8;n++)Marshal.WriteByte(tableMemory,n,0x5A);Object=Marshal.AllocHGlobal(16);Marshal.WriteIntPtr(Object,IntPtr.Add(tableMemory,8));Marshal.WriteInt64(Object,8,0x12345678);
   Add(new QI(QueryInterface),0);Add(new Ref(AddRef),1);Add(new Ref(Release),2);Add(new Iids(GetIids),3);Add(new Query(GetClass),4);Add(new Integer(GetInt),5);Add(new Query(GetId),6);Add(new Integer(GetInt),7);
   Add(new Boolean(GetBool),8);Add(new Boolean(GetBool),9);Add(new Boolean(GetBool),10);Add(new Query(GetDescription),11);Add(new Boolean(GetBool),12);Add(new NamedQuery(GetNamed),13);Add(new SetNamed(Set),14);Add(new NamedQuery(GetNamed),15);Add(new SetNamed(Set),16);Add(new Invoke(InvokeMethod),17);Add(new AddEvent(AddHandler),18);Add(new RemoveEvent(RemoveHandler),19);
  }
  int QueryInterface(IntPtr p,ref Guid iid,out IntPtr value){value=IntPtr.Zero;if(Accept&&(iid==ItemIID||iid==new Guid("00000000-0000-0000-c000-000000000046")||iid==new Guid("af86e2e0-b12d-4c6a-9c5a-d7aa65101e90"))){Refs++;value=Object;return 0;}return unchecked((int)0x80004002);}
  uint AddRef(IntPtr p){return (uint)++Refs;}uint Release(IntPtr p){return (uint)--Refs;}
  int GetIids(IntPtr p,out uint n,out IntPtr list){n=0;list=IntPtr.Zero;UnusedCalls++;return unchecked((int)0x80004001);}
  int GetClass(IntPtr p,out IntPtr text){text=IntPtr.Zero;UnusedCalls++;return unchecked((int)0x80004001);}
  int GetInt(IntPtr p,out int value){value=0;UnusedCalls++;return unchecked((int)0x80004001);}
  int GetBool(IntPtr p,out byte value){value=0;UnusedCalls++;return unchecked((int)0x80004001);}
  int GetId(IntPtr p,out IntPtr text){IdCalls++;text=IdHR<0?IntPtr.Zero:H(Id);return IdHR;}
  int GetDescription(IntPtr p,out IntPtr text){DescriptionCalls++;text=DescriptionHR<0?IntPtr.Zero:H(Description);return DescriptionHR;}
  int GetNamed(IntPtr p,IntPtr key,out IntPtr value){value=IntPtr.Zero;UnusedCalls++;return unchecked((int)0x80004001);}
  int Set(IntPtr p,IntPtr key,IntPtr value){UnusedCalls++;return unchecked((int)0x80004001);}
  int InvokeMethod(IntPtr p,IntPtr window,Rect bounds){UnusedCalls++;return unchecked((int)0x80004001);}
  int AddHandler(IntPtr p,IntPtr callback,out long token){token=0;UnusedCalls++;return unchecked((int)0x80004001);}
  int RemoveHandler(IntPtr p,long token){UnusedCalls++;return unchecked((int)0x80004001);}
  public void Dispose(){Assert(Refs==1&&UnusedCalls==0,"fake balanced refs and no values/setters/events");Assert(Marshal.ReadInt64(tableMemory)==0x5A5A5A5A5A5A5A5A&&Marshal.ReadInt64(tableMemory,21*8)==0x5A5A5A5A5A5A5A5A&&Marshal.ReadInt64(Object,8)==0x12345678,"fake layout canaries");Marshal.FreeHGlobal(Object);Marshal.FreeHGlobal(tableMemory);GC.KeepAlive(delegates);}
 }
 static string Run(Query query,FakeItem item,int expected){IntPtr value;int hr=query(item.Object,out value);try{Assert(hr==expected,"genuine HRESULT "+hr.ToString("X8"));return hr>=0?S(value):"";}finally{if(value!=IntPtr.Zero)WindowsDeleteString(value);}}
 static void Synthetic(Query query){
  using(var f=new FakeItem()){f.Description="fixture-native-nonempty";Assert(Run(query,f,0)==f.Description&&f.IdCalls==0,"native nonempty precedence");}
  using(var f=new FakeItem()){f.Id="SystemSettings_Taskbar_NotInScope";Assert(Run(query,f,0)=="","unscoped preserved");}
  using(var f=new FakeItem()){f.Id=Keys[0].ToLowerInvariant();Assert(Run(query,f,0)=="","case-sensitive allowlist");}
  using(var f=new FakeItem()){f.Id=Keys[0]+"\0ignored";Assert(Run(query,f,0)=="","embedded NUL not accepted");}
  using(var f=new FakeItem()){f.DescriptionHR=unchecked((int)0x80070005);Run(query,f,f.DescriptionHR);Assert(f.IdCalls==0,"native failure no fallback");}
  using(var f=new FakeItem()){f.DescriptionHR=1;Assert(Run(query,f,1)==""&&f.IdCalls==0,"S_FALSE preserved");}
  using(var f=new FakeItem()){f.IdHR=unchecked((int)0x80070057);Run(query,f,f.IdHR);}
  using(var f=new FakeItem()){f.Accept=false;Run(query,f,unchecked((int)0x80004002));Assert(f.DescriptionCalls==0,"wrong IID rejected");}
  foreach(string id in Keys)using(var f=new FakeItem()){f.Id=id;string text=Run(query,f,0);Assert(text.Length>0&&f.IdCalls==1&&f.DescriptionCalls==1,"real resource "+id);Log.WriteLine("RESOURCE\t"+id+"\t"+text);}
 }
 static int Main(string[] args){if(args.Length!=4)return 64;int result=65;var thread=new Thread(delegate(){result=RunFixture(args);});thread.SetApartmentState(args[3]=="sta"?ApartmentState.STA:ApartmentState.MTA);thread.Start();thread.Join();return result;}
 static int RunFixture(string[] args){bool ro=false;IntPtr db=IntPtr.Zero;using(Log=new StreamWriter(args[0],false,new UTF8Encoding(false))){Log.AutoFlush=true;try{
  Marshal.ThrowExceptionForHR(RoInitialize(args[3]=="sta"?0:1));ro=true;IntPtr helper=LoadLibraryEx(args[1],IntPtr.Zero,0x1100);Assert(helper!=IntPtr.Zero,"helper load");var query=D<Query>(GetProcAddress(helper,"SettingsControlTextQuery"));var initialize=D<Initialize>(GetProcAddress(helper,"SettingsControlTextInitialize"));var restore=D<Initialize>(GetProcAddress(helper,"SettingsControlTextRestore"));
  if(args[3]=="missing-dependency"){using(var f=new FakeItem())Run(query,f,unchecked((int)0x8007051A));Assert(initialize(IntPtr.Zero)==0x8007051A,"missing dependency installation rejected");return 0;}
  Synthetic(query);
  IntPtr vm=LoadLibraryEx(args[2],IntPtr.Zero,0x1100);Assert(vm!=IntPtr.Zero,"old VM load");IntPtr context=IntPtr.Add(vm,0x398e4),call=IntPtr.Add(vm,0x398f8);byte[] contextBefore=Bytes(context,33),callBefore=Bytes(call,5),projectionBefore=Bytes(IntPtr.Add(vm,0x3b7ac),128);
  if(args[3]=="bad-guard"){byte[] bad=(byte[])contextBefore.Clone();bad[0]^=1;Write(context,bad);try{Assert(initialize(IntPtr.Zero)==0x8007051A,"foreign instruction context rejected");Assert(Equal(Bytes(context,33),bad),"rejected bytes unchanged");}finally{Write(context,contextBefore);}return 0;}
  uint result=initialize(IntPtr.Zero);Assert(result==0,"initialize "+result.ToString("X8"));Assert(initialize(IntPtr.Zero)==0,"idempotent initialize");byte[] patched=Bytes(call,5);Assert(!Equal(callBefore,patched)&&patched[0]==0xE8,"single CALL patched");Assert(Equal(Bytes(IntPtr.Add(vm,0x3b7ac),128),projectionBefore),"shared projection untouched");
  byte[] contextAfter=Bytes(context,33);for(int i=0;i<33;i++)if(i<20||i>=25)Assert(contextAfter[i]==contextBefore[i],"surrounding instruction byte "+i);
  IntPtr stub=new IntPtr(call.ToInt64()+5+Marshal.ReadInt32(call,1));Assert(Marshal.ReadByte(stub)==0xFF&&Marshal.ReadByte(stub,1)==0x25,"near trampoline decoded");Projection installedProjection=D<Projection>(stub);
  foreach(string id in Keys)using(var f=new FakeItem()){f.Id=id;IntPtr value=installedProjection(f.Object);try{Assert(S(value).Length>0,"installed branch trampoline "+id);}finally{WindowsDeleteString(value);}}
  IntPtr module=LoadLibraryEx("C:\\Windows\\System32\\SystemSettings.DataModel.dll",IntPtr.Zero,0x800),name=H("SystemSettings.DataModel.SettingsDatabase"),factory=IntPtr.Zero,instance=IntPtr.Zero;
  try{Marshal.ThrowExceptionForHR(D<Factory>(GetProcAddress(module,"DllGetActivationFactory"))(name,out factory));Marshal.ThrowExceptionForHR(Slot<Query>(factory,6)(factory,out instance));Guid iid=new Guid("d68a97b7-4f47-4cb6-9e1f-a01c1232f755");Marshal.ThrowExceptionForHR(Marshal.QueryInterface(instance,ref iid,out db));}finally{WindowsDeleteString(name);Drop(ref instance);Drop(ref factory);}
  foreach(string id in Keys){IntPtr key=H(id),item=IntPtr.Zero,native=IntPtr.Zero,adapted=IntPtr.Zero;try{int hr=Slot<NamedQuery>(db,6)(db,key,out item);Log.WriteLine("REAL_GETSETTING\t"+id+"\t"+hr.ToString("X8"));if(id==Keys[8]){Assert(hr==unchecked((int)0x80070002)&&item==IntPtr.Zero,"ninth backend genuinely unavailable; no projection call and no fabricated item");Log.WriteLine("LIMITATION ninth Description is resolvable only if another real provider supplies its ISettingItem");continue;}Assert(hr==0&&item!=IntPtr.Zero,"real item "+id);hr=Slot<Query>(item,11)(item,out native);Assert(hr==0&&S(native)=="","real native empty "+id);adapted=installedProjection(item);Assert(S(adapted).Length>0,"real adapted description "+id);Log.WriteLine("REAL_RESOURCE\t"+id+"\t"+S(adapted));}finally{if(adapted!=IntPtr.Zero)WindowsDeleteString(adapted);if(native!=IntPtr.Zero)WindowsDeleteString(native);Drop(ref item);WindowsDeleteString(key);}}
  byte[] foreign=(byte[])patched.Clone();foreign[4]^=1;Write(call,foreign);try{Assert(restore(IntPtr.Zero)==0x8007051A,"foreign hook rollback refused");Assert(Equal(Bytes(call,5),foreign),"foreign bytes preserved");}finally{Write(call,patched);}
  Assert(restore(IntPtr.Zero)==0,"restore");Assert(restore(IntPtr.Zero)==0,"idempotent restore");Assert(Equal(Bytes(context,33),contextBefore),"complete original context restored");Assert(Equal(Bytes(IntPtr.Add(vm,0x3b7ac),128),projectionBefore),"original shared stub still intact");
  Log.WriteLine("COUNTERS native="+Marshal.ReadInt32(GetProcAddress(helper,"SettingsControlTextNativeCalls"))+" fallback="+Marshal.ReadInt32(GetProcAddress(helper,"SettingsControlTextFallbackCalls"))+" errors="+Marshal.ReadInt32(GetProcAddress(helper,"SettingsControlTextFailures")));
  Log.WriteLine("COMPLETE own non-UI fixture; no Settings app, registry, VFS or setters");return 0;
 }catch(Exception e){Log.WriteLine(e);return 1;}finally{Drop(ref db);if(ro)RoUninitialize();}}}
}
