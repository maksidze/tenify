using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace DirectLaunchLifecycle {
 public sealed class Identity : IDisposable {
  IntPtr process;
  public uint Pid {get;private set;}
  public ulong Birth {get;private set;}
  public string Path {get;private set;}
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out ulong c,out ulong e,out ulong k,out ulong u);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr h,uint flags,StringBuilder text,ref uint n);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr h,uint code);
  [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
  static Exception Error(){return new Win32Exception(Marshal.GetLastWin32Error());}
  public static Identity Open(uint pid,ulong birth,string path,bool termination){
   var x=new Identity();x.process=OpenProcess(0x101000u|(termination?1u:0u),false,pid);
   if(x.process==IntPtr.Zero)throw Error();
   try{
    ulong c,e,k,u;var b=new StringBuilder(32768);uint n=(uint)b.Capacity;
    if(!GetProcessTimes(x.process,out c,out e,out k,out u)||!QueryFullProcessImageNameW(x.process,0,b,ref n))throw Error();
    x.Pid=pid;x.Birth=c;x.Path=b.ToString();
    if(birth!=0&&birth!=c)throw new InvalidOperationException("Process birth differs");
    if(!String.IsNullOrEmpty(path)&&!String.Equals(path,x.Path,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Process path differs");
    if(!x.Alive)throw new InvalidOperationException("Process already exited");return x;
   }catch{x.Dispose();throw;}
  }
  public bool Alive{get{if(process==IntPtr.Zero)throw new ObjectDisposedException("Identity");uint r=WaitForSingleObject(process,0);if(r==258)return true;if(r==0)return false;throw Error();}}
  public bool Wait(int milliseconds){if(process==IntPtr.Zero)throw new ObjectDisposedException("Identity");uint r=WaitForSingleObject(process,(uint)milliseconds);if(r==0)return true;if(r==258)return false;throw Error();}
  public void Stop(){if(Alive&&!TerminateProcess(process,0))throw Error();}
  public void Dispose(){if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}GC.SuppressFinalize(this);}
  ~Identity(){if(process!=IntPtr.Zero)CloseHandle(process);}
 }
}
