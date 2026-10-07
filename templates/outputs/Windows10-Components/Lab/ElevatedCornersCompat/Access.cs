using System;using System.Text;using System.Runtime.InteropServices;using System.ComponentModel;
public sealed class CornerProcessLease:IDisposable {
 internal IntPtr Handle;public uint Pid;public string Path;public ulong Birth;public uint Integrity;
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll")]static extern uint WaitForSingleObject(IntPtr h,uint ms);
 public bool Wait(int ms){return WaitForSingleObject(Handle,(uint)ms)==0;}
 public void Dispose(){if(Handle!=IntPtr.Zero){CloseHandle(Handle);Handle=IntPtr.Zero;}}
}
public static class CornerAccess {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out ulong a,out ulong b,out ulong c,out ulong d);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder p,ref uint size);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr h,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr h,int type,IntPtr p,uint n,out uint needed);
 [DllImport("advapi32.dll")]static extern IntPtr GetSidSubAuthority(IntPtr sid,uint n);
 [DllImport("advapi32.dll")]static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 static uint IL(IntPtr h){IntPtr token;if(!OpenProcessToken(h,8,out token))return 0;try{uint n;GetTokenInformation(token,25,IntPtr.Zero,0,out n);if(n==0||n>65536)return 0;IntPtr b=Marshal.AllocHGlobal((int)n);try{if(!GetTokenInformation(token,25,b,n,out n))return 0;IntPtr sid=Marshal.ReadIntPtr(b);byte count=Marshal.ReadByte(GetSidSubAuthorityCount(sid));return count==0?0:unchecked((uint)Marshal.ReadInt32(GetSidSubAuthority(sid,(uint)count-1)));}finally{Marshal.FreeHGlobal(b);}}finally{CloseHandle(token);}}
 static CornerProcessLease Captured(IntPtr h,uint pid){var r=new CornerProcessLease();r.Handle=h;r.Pid=pid;ulong x,y,z;if(!GetProcessTimes(h,out r.Birth,out x,out y,out z)){r.Dispose();return null;}var p=new StringBuilder(32768);uint size=(uint)p.Capacity;if(!QueryFullProcessImageName(h,0,p,ref size)){r.Dispose();return null;}r.Path=p.ToString();r.Integrity=IL(h);return r;}
 public static CornerProcessLease Read(uint pid){IntPtr h=OpenProcess(0x101000,false,pid);return h==IntPtr.Zero?null:Captured(h,pid);}
 public static CornerProcessLease Exact(uint pid,ulong birth,string path){var r=Read(pid);if(r!=null&&(r.Wait(0)||r.Birth!=birth||!String.Equals(r.Path,path,StringComparison.OrdinalIgnoreCase))){r.Dispose();return null;}return r;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct EXEC {public int Size;public uint Mask;public IntPtr Window;public string Verb,File,Parameters,Directory;public int Show;public IntPtr Instance,IDList;public string Class;public IntPtr ClassKey;public uint HotKey;public IntPtr Icon,Process;}
 [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ShellExecuteEx(ref EXEC e);
 public static CornerProcessLease Elevate(string exe,string args,string directory){var e=new EXEC();e.Size=Marshal.SizeOf(typeof(EXEC));e.Mask=0x40|0x400;e.Verb="runas";e.File=exe;e.Parameters=args;e.Directory=directory;e.Show=0;if(!ShellExecuteEx(ref e))throw new Win32Exception(Marshal.GetLastWin32Error());if(e.Process==IntPtr.Zero)throw new InvalidOperationException("UAC launcher returned no owned process handle");IntPtr captured=e.Process;var r=Captured(captured,GetProcessId(captured));if(r==null)throw new InvalidOperationException("Elevated companion identity unavailable");if(!String.Equals(r.Path,exe,StringComparison.OrdinalIgnoreCase)){r.Dispose();throw new InvalidOperationException("Elevated companion identity differs");}return r;}
 [DllImport("kernel32.dll")]static extern uint GetProcessId(IntPtr h);
}
