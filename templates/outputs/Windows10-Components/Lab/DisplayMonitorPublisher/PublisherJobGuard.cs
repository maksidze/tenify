using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace Explorer10Publisher {
 // Anonymous job owns only the newly-created helper. This API cannot attach an existing PID.
 public sealed class JobChild : IDisposable {
  IntPtr job,process;
  public uint Pid {get;private set;}
  public ulong BirthFileTime {get;private set;}
  public bool AssignedBeforeResume {get;private set;}
  [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
   public long ProcessTime,JobTime;public uint Flags;public UIntPtr MinimumWorkingSet,MaximumWorkingSet;
   public uint ActiveProcessLimit;public UIntPtr Affinity;public uint PriorityClass,SchedulingClass;
  }
  [StructLayout(LayoutKind.Sequential)] struct IoCounters {public ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes;}
  [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;}
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct StartupInfo {
   public uint Size;public string Reserved,Desktop,Title;public uint X,Y,XSize,YSize,XCountChars,YCountChars,FillAttribute,Flags;
   public ushort ShowWindow,Reserved2Count;public IntPtr Reserved2,StandardInput,StandardOutput,StandardError;
  }
  [StructLayout(LayoutKind.Sequential)] struct ProcessInformation {public IntPtr Process,Thread;public uint ProcessId,ThreadId;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attributes,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimits info,uint bytes);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string image,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string currentDirectory,ref StartupInfo startup,out ProcessInformation information);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out ulong creation,out ulong exit,out ulong kernel,out ulong user);
  static Exception Error(string stage){return new Win32Exception(Marshal.GetLastWin32Error(),stage);}
  // Standard Windows argv escaping. No shell interpretation.
  public static string QuoteArgument(string argument){
   if(argument==null)throw new ArgumentNullException("argument");if(argument.IndexOf('\0')>=0)throw new ArgumentException("NUL in argument");
   var s=new StringBuilder("\"");int slashes=0;
   foreach(char c in argument){if(c=='\\'){slashes++;continue;}if(c=='"'){s.Append('\\',slashes*2+1);s.Append(c);slashes=0;continue;}s.Append('\\',slashes);slashes=0;s.Append(c);}
   s.Append('\\',slashes*2);s.Append('"');return s.ToString();
  }
  public static JobChild Start(string image,string[] arguments){
   if(IntPtr.Size!=8||Marshal.SizeOf(typeof(ExtendedLimits))!=144)throw new PlatformNotSupportedException("Exact x64 job layout required");
   image=System.IO.Path.GetFullPath(image);var child=new JobChild();ProcessInformation pi=new ProcessInformation();bool resumed=false;
   try{
    child.job=CreateJobObjectW(IntPtr.Zero,null);if(child.job==IntPtr.Zero)throw Error("CreateJobObject");
    var limits=new ExtendedLimits();limits.Basic.Flags=0x2000; // KILL_ON_JOB_CLOSE
    if(!SetInformationJobObject(child.job,9,ref limits,(uint)Marshal.SizeOf(limits)))throw Error("SetInformationJobObject");
    var command=new StringBuilder(QuoteArgument(image));foreach(var a in arguments)command.Append(' ').Append(QuoteArgument(a));
    var si=new StartupInfo();si.Size=(uint)Marshal.SizeOf(si);
    // No inherited handles, CREATE_SUSPENDED | CREATE_NO_WINDOW.
    if(!CreateProcessW(image,command,IntPtr.Zero,IntPtr.Zero,false,0x08000004,IntPtr.Zero,System.IO.Path.GetDirectoryName(image),ref si,out pi))throw Error("CreateProcess suspended");
    child.process=pi.Process;child.Pid=pi.ProcessId;ulong birth,exit,kernel,user;
    if(!GetProcessTimes(child.process,out birth,out exit,out kernel,out user))throw Error("GetProcessTimes");child.BirthFileTime=birth;
    if(!AssignProcessToJobObject(child.job,child.process))throw Error("AssignProcessToJobObject");
    bool member;if(!IsProcessInJob(child.process,child.job,out member)||!member)throw Error("Verify job membership");
    child.AssignedBeforeResume=true;if(ResumeThread(pi.Thread)==0xffffffff)throw Error("ResumeThread");resumed=true;return child;
   }catch{
    // Before successful assignment the exact new process is still suspended.
    // Terminate by the creation handle, never by numeric PID.
    if(pi.Process!=IntPtr.Zero&&!resumed){TerminateProcess(pi.Process,0xE001);WaitForSingleObject(pi.Process,5000);}
    child.Dispose();throw;
   }finally{if(pi.Thread!=IntPtr.Zero)CloseHandle(pi.Thread);}
  }
  public bool WaitForExit(int milliseconds){
   if(milliseconds<0||milliseconds>3610000)throw new ArgumentOutOfRangeException("milliseconds");if(process==IntPtr.Zero)throw new ObjectDisposedException("JobChild");
   uint r=WaitForSingleObject(process,(uint)milliseconds);if(r==0)return true;if(r==258)return false;throw Error("WaitForSingleObject");
  }
  public uint ExitCode{get{uint code;if(process==IntPtr.Zero)throw new ObjectDisposedException("JobChild");if(!GetExitCodeProcess(process,out code))throw Error("GetExitCodeProcess");return code;}}
  public bool StopAndWait(int milliseconds){
   if(process==IntPtr.Zero)return true;if(WaitForExit(0))return true;
   if(job!=IntPtr.Zero&&!TerminateJobObject(job,0xE002))throw Error("TerminateJobObject exact owned job");return WaitForExit(milliseconds);
  }
  public void Dispose(){
   // Closing the last job handle is also the fallback if explicit termination
   // failed. Keep the exact process handle through the bounded wait.
   if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}
   if(process!=IntPtr.Zero){WaitForSingleObject(process,5000);CloseHandle(process);process=IntPtr.Zero;}
  }
 }
}
