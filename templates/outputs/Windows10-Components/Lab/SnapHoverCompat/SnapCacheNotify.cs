using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;

// Ordinary out-of-process shell COM client. Never opens the shell for writing.
internal static class SnapCacheNotify
{
    const string TwinuiHash = "10ae13c8560cc89abb33425f9b9e6d49368d43f39e73e3845f3f0e191eb5af2f";
    const string RegistrySubkey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    static readonly Guid CacheClass = new Guid("a919ea73-490e-4d5c-9ba7-97cbc73119fe");
    static readonly Guid CacheService = new Guid("53660488-8855-460b-a9ab-5cfc6b5012ca");
    static readonly Guid CacheInterface = new Guid("4214f6fa-eb36-4e2f-9ca2-23fdc1832df7");
    static readonly Guid ImmersiveShell = new Guid("c2f03a33-21f5-47fa-b4bb-156362a2f239");
    static readonly Guid ServiceProvider = new Guid("6d5140c1-7436-11ce-8034-00aa006009fa");
    static readonly Guid ClassFactory = new Guid("00000001-0000-0000-c000-000000000046");
    [DllImport("ole32.dll")] static extern int CoInitializeEx(IntPtr reserved, uint flags);
    [DllImport("ole32.dll")] static extern void CoUninitialize();
    [DllImport("ole32.dll")] static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid, out IntPtr obj);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryEx(string file, IntPtr fileHandle, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
    [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder path, ref uint length);
    [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetClass(ref Guid clsid, ref Guid iid, out IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int CreateInstance(IntPtr self, IntPtr outer, ref Guid iid, out IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int QueryService(IntPtr self, ref Guid service, ref Guid iid, out IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetBool(IntPtr self, uint setting, IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int SettingChanged(IntPtr self, uint setting);
    static T Slot<T>(IntPtr obj, int slot) where T:class
    {
        if(obj==IntPtr.Zero) throw new InvalidOperationException("Null COM object");
        return (T)(object)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(obj),slot*IntPtr.Size),typeof(T));
    }
    static string Q(string value) { return "\""+value.Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r","\\r").Replace("\n","\\n")+"\""; }
    static void Emit(string values) { Console.WriteLine("{"+values+"}"); Console.Out.Flush(); }
    static string Hex(int hr) { return unchecked((uint)hr).ToString("x8"); }
    static void Check(int hr, string step) { if(hr<0) throw new COMException(step,hr); }
    static void Release(ref IntPtr obj) { if(obj!=IntPtr.Zero) { Marshal.Release(obj); obj=IntPtr.Zero; } }
    static string RegistrySnapshot()
    {
        using(RegistryKey key=Registry.CurrentUser.OpenSubKey(RegistrySubkey))
        {
            object value=key==null?null:key.GetValue("EnableSnapAssistFlyout",null,RegistryValueOptions.DoNotExpandEnvironmentNames);
            if(value==null) return "absent";
            if(key.GetValueKind("EnableSnapAssistFlyout")!=RegistryValueKind.DWord) throw new InvalidOperationException("Preference is not DWORD");
            return "DWORD:"+unchecked((uint)(int)value).ToString();
        }
    }
    static int Read(IntPtr cache, string stage)
    {
        IntPtr buffer=Marshal.AllocHGlobal(12);
        try
        {
            Marshal.WriteInt32(buffer,0,unchecked((int)0xa55aa55a));
            Marshal.WriteInt32(buffer,4,unchecked((int)0xeeeeeeee));
            Marshal.WriteInt32(buffer,8,unchecked((int)0x55aa55aa));
            int hr=Slot<GetBool>(cache,4)(cache,11,IntPtr.Add(buffer,4));
            int value=Marshal.ReadInt32(buffer,4);
            bool canary=Marshal.ReadInt32(buffer,0)==unchecked((int)0xa55aa55a)&&Marshal.ReadInt32(buffer,8)==unchecked((int)0x55aa55aa);
            Emit("\"stage\":"+Q(stage)+",\"GetBOOL\":"+Q(Hex(hr))+",\"setting\":11,\"value\":"+value+",\"canaries\":"+canary.ToString().ToLowerInvariant());
            Check(hr,"GetBOOL(11)");
            if(!canary) throw new InvalidOperationException("GetBOOL wrote outside four-byte BOOL output");
            return value;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    static int Main(string[] args)
    {
        bool refresh=args.Length==1&&args[0]=="--refresh";
        if(!refresh && !(args.Length==1&&args[0]=="--read")) return 64;
        IntPtr module=IntPtr.Zero,factory=IntPtr.Zero,fresh=IntPtr.Zero,provider=IntPtr.Zero,live=IntPtr.Zero,shellHandle=IntPtr.Zero;
        bool initialized=false;
        // Independent bound if the controller is closed or a COM Release blocks.
        Timer watchdog=new Timer(delegate { Environment.Exit(124); },null,14000,Timeout.Infinite);
        try
        {
            if(IntPtr.Size!=8) throw new InvalidOperationException("x64 client required");
            string twinui=Path.Combine(Environment.SystemDirectory,"twinui.dll");
            using(SHA256 hash=SHA256.Create()) using(FileStream file=File.OpenRead(twinui))
                if(BitConverter.ToString(hash.ComputeHash(file)).Replace("-","").ToLowerInvariant()!=TwinuiHash) throw new InvalidOperationException("Unsupported twinui.dll hash");
            uint pid; IntPtr shellWindow=GetShellWindow();
            if(shellWindow==IntPtr.Zero||GetWindowThreadProcessId(shellWindow,out pid)==0) throw new InvalidOperationException("No current shell window");
            shellHandle=OpenProcess(0x101000,false,pid); // SYNCHRONIZE | QUERY_LIMITED_INFORMATION only.
            if(shellHandle==IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            StringBuilder image=new StringBuilder(32768); uint capacity=(uint)image.Capacity;
            long birth,exit,kernel,user;
            if(!QueryFullProcessImageName(shellHandle,0,image,ref capacity)||!GetProcessTimes(shellHandle,out birth,out exit,out kernel,out user)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            Emit("\"shellPid\":"+pid+",\"birthFileTime\":"+birth+",\"shellPath\":"+Q(image.ToString()));
            string registry=RegistrySnapshot(); Emit("\"registry\":"+Q(registry));
            Check(CoInitializeEx(IntPtr.Zero,0),"CoInitializeEx(MTA)"); initialized=true;
            module=LoadLibraryEx(twinui,IntPtr.Zero,0x800); if(module==IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            IntPtr getClassAddress=GetProcAddress(module,"DllGetClassObject"); if(getClassAddress==IntPtr.Zero) throw new EntryPointNotFoundException("DllGetClassObject");
            GetClass getClass=(GetClass)Marshal.GetDelegateForFunctionPointer(getClassAddress,typeof(GetClass));
            Guid cls=CacheClass,iid=ClassFactory;
            Check(getClass(ref cls,ref iid,out factory),"Own DllGetClassObject"); iid=CacheInterface;
            Check(Slot<CreateInstance>(factory,3)(factory,IntPtr.Zero,ref iid,out fresh),"Own cache CreateInstance");
            if(fresh==IntPtr.Zero) throw new InvalidOperationException("Own cache returned S_OK with null output");
            if(Marshal.ReadIntPtr(Marshal.ReadIntPtr(fresh),3*8).ToInt64()-module.ToInt64()!=0x2cb3a0 || Marshal.ReadIntPtr(Marshal.ReadIntPtr(fresh),4*8).ToInt64()-module.ToInt64()!=0x83e20) throw new InvalidOperationException("Own cache ABI guard mismatch");
            int expected=Read(fresh,"freshExpected");
            cls=ImmersiveShell; iid=ServiceProvider;
            int hr=CoCreateInstance(ref cls,IntPtr.Zero,4,ref iid,out provider); Emit("\"CoCreateImmersiveShell\":"+Q(Hex(hr))); Check(hr,"CoCreateImmersiveShell");
            Guid sid=CacheService; iid=CacheInterface;
            hr=Slot<QueryService>(provider,3)(provider,ref sid,ref iid,out live); Emit("\"QueryService\":"+Q(Hex(hr))); Check(hr,"QueryService exact cache SID/IID");
            int before=Read(live,"before");
            if(refresh)
            {
                uint currentPid;
                if(GetShellWindow()!=shellWindow || GetWindowThreadProcessId(shellWindow,out currentPid)==0 || currentPid!=pid || WaitForSingleObject(shellHandle,0)!=258) throw new InvalidOperationException("Shell changed before refresh");
                if(RegistrySnapshot()!=registry) throw new InvalidOperationException("Preference changed before refresh");
                hr=Slot<SettingChanged>(live,3)(live,11); Emit("\"OnSettingChanged\":"+Q(Hex(hr))+",\"setting\":11"); Check(hr,"OnSettingChanged(11)");
                int after=Read(live,"after");
                if(RegistrySnapshot()!=registry) throw new InvalidOperationException("Preference changed during refresh");
                if(after!=expected) throw new InvalidOperationException("Live cache does not match fresh cache; no automatic Explorer restart");
                Emit("\"result\":\"refreshed\",\"matchesFresh\":true");
            }
            else Emit("\"result\":\"read-only\",\"matchesFresh\":"+(before==expected).ToString().ToLowerInvariant());
            return 0;
        }
        catch(Exception e) { Emit("\"error\":"+Q(e.Message)+",\"hresult\":"+Q(Hex(e.HResult))); return 1; }
        finally
        {
            Release(ref live); Release(ref provider); Release(ref fresh); Release(ref factory);
            if(initialized) CoUninitialize();
            if(module!=IntPtr.Zero) FreeLibrary(module);
            if(shellHandle!=IntPtr.Zero) CloseHandle(shellHandle);
            watchdog.Dispose();
        }
    }
}
