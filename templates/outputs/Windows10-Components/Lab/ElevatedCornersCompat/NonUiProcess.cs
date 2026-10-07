using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
namespace Explorer10Tools {
 // Direct CreateProcess, never ShellExecute. Log handles belong to the child,
 // so a background controller keeps its logs after its launcher's process exits.
 public sealed class NonUiProcess : IDisposable {
  IntPtr process;
  public uint Id {get;private set;}
  public ulong BirthFileTime {get;private set;}
  public DateTime StartTime {get{return DateTime.FromFileTimeUtc((long)BirthFileTime).ToLocalTime();}}
  public IntPtr Handle {get{EnsureOpen();return process;}}
  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {public uint Size;public IntPtr Descriptor;public int Inherit;}
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct StartupInfo {
   public uint Size;public string Reserved,Desktop,Title;public uint X,Y,XSize,YSize,XCountChars,YCountChars,FillAttribute,Flags;
   public ushort ShowWindow,Reserved2Count;public IntPtr Reserved2,StandardInput,StandardOutput,StandardError;
  }
  [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx {public StartupInfo Startup;public IntPtr Attributes;}
  [StructLayout(LayoutKind.Sequential)] struct ProcessInformation {public IntPtr Process,Thread;public uint ProcessId,ThreadId;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string path,uint access,uint share,ref SecurityAttributes attributes,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returnedSize);
  [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string image,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string currentDirectory,ref StartupInfoEx startup,out ProcessInformation information);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out ulong creation,out ulong exit,out ulong kernel,out ulong user);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint exit);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint exit);
  static Exception Error(string stage){return new Win32Exception(Marshal.GetLastWin32Error(),stage);}
  static bool Valid(IntPtr h){return h!=IntPtr.Zero&&h!=new IntPtr(-1);}
  void EnsureOpen(){if(!Valid(process))throw new ObjectDisposedException("NonUiProcess");}
  public static string QuoteArgument(string argument){
   if(argument==null)throw new ArgumentNullException("argument");if(argument.IndexOf('\0')>=0)throw new ArgumentException("NUL in argument");
   var b=new StringBuilder("\"");int slashes=0;
   foreach(char c in argument){if(c=='\\'){slashes++;continue;}if(c=='"'){b.Append('\\',slashes*2+1);b.Append(c);slashes=0;continue;}b.Append('\\',slashes);slashes=0;b.Append(c);}
   b.Append('\\',slashes*2);b.Append('"');return b.ToString();
  }
  static IntPtr StreamHandle(string path,bool input,ref SecurityAttributes attributes){
   bool nul=String.IsNullOrEmpty(path);string target=nul?"NUL":Path.GetFullPath(path);
   if(!nul){string directory=Path.GetDirectoryName(target);if(!Directory.Exists(directory))throw new DirectoryNotFoundException(directory);}
   IntPtr handle=CreateFileW(target,input?0x80000000u:0x40000000u,7,ref attributes,nul?3u:2u,0x80,IntPtr.Zero);
   if(!Valid(handle))throw Error("Open standard stream "+target);return handle;
  }
  public static NonUiProcess Start(string image,string[] arguments,string outputPath,string errorPath,string workingDirectory){
   if(IntPtr.Size!=8)throw new PlatformNotSupportedException("x64 controller required");
   image=Path.GetFullPath(image);if(!File.Exists(image))throw new FileNotFoundException("Program is missing",image);
   if(!String.IsNullOrEmpty(outputPath)&&!String.IsNullOrEmpty(errorPath)&&String.Equals(Path.GetFullPath(outputPath),Path.GetFullPath(errorPath),StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Use separate stdout and stderr paths");
   if(!String.IsNullOrEmpty(workingDirectory))workingDirectory=Path.GetFullPath(workingDirectory);
   var child=new NonUiProcess();var si=new StartupInfoEx();var pi=new ProcessInformation();
   IntPtr stdin=IntPtr.Zero,stdout=IntPtr.Zero,stderr=IntPtr.Zero,handles=IntPtr.Zero;bool attributesReady=false;
   try{
    var sa=new SecurityAttributes();sa.Size=(uint)Marshal.SizeOf(sa);sa.Inherit=1;
    stdin=StreamHandle(null,true,ref sa);stdout=StreamHandle(outputPath,false,ref sa);stderr=StreamHandle(errorPath,false,ref sa);
    IntPtr bytes=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);if(bytes==IntPtr.Zero)throw Error("Size handle attribute list");
    si.Attributes=Marshal.AllocHGlobal(bytes);if(!InitializeProcThreadAttributeList(si.Attributes,1,0,ref bytes))throw Error("Initialize handle attribute list");attributesReady=true;
    handles=Marshal.AllocHGlobal(IntPtr.Size*3);Marshal.WriteIntPtr(handles,0,stdin);Marshal.WriteIntPtr(handles,IntPtr.Size,stdout);Marshal.WriteIntPtr(handles,IntPtr.Size*2,stderr);
    if(!UpdateProcThreadAttribute(si.Attributes,0,new IntPtr(0x20002),handles,new IntPtr(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero))throw Error("Restrict inherited handle list");
    si.Startup.Size=(uint)Marshal.SizeOf(si);si.Startup.Flags=0x100;si.Startup.StandardInput=stdin;si.Startup.StandardOutput=stdout;si.Startup.StandardError=stderr;
    var command=new StringBuilder(QuoteArgument(image));foreach(var argument in arguments)command.Append(' ').Append(QuoteArgument(argument));
    // CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT. Only the 3 listed stream
    // handles may be inherited. No shell, no default Terminal activation.
    if(!CreateProcessW(image,command,IntPtr.Zero,IntPtr.Zero,true,0x08080000,IntPtr.Zero,workingDirectory,ref si,out pi))throw Error("Create non-UI process");
    child.process=pi.Process;child.Id=pi.ProcessId;ulong birth,exit,kernel,user;
    if(!GetProcessTimes(child.process,out birth,out exit,out kernel,out user))throw Error("Read created process identity");child.BirthFileTime=birth;
    return child;
   }catch{
    if(Valid(pi.Process)){TerminateProcess(pi.Process,0xE003);WaitForSingleObject(pi.Process,5000);}child.Dispose();throw;
   }finally{
    if(Valid(pi.Thread))CloseHandle(pi.Thread);
    if(attributesReady)DeleteProcThreadAttributeList(si.Attributes);
    if(si.Attributes!=IntPtr.Zero)Marshal.FreeHGlobal(si.Attributes);if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);
    if(Valid(stdin))CloseHandle(stdin);if(Valid(stdout))CloseHandle(stdout);if(Valid(stderr))CloseHandle(stderr);
   }
  }
  public bool WaitForExit(int milliseconds){if(milliseconds<0)throw new ArgumentOutOfRangeException("milliseconds");EnsureOpen();uint r=WaitForSingleObject(process,(uint)milliseconds);if(r==0)return true;if(r==258)return false;throw Error("Wait for exact created process");}
  public void WaitForExit(){EnsureOpen();if(WaitForSingleObject(process,0xffffffff)!=0)throw Error("Wait for exact created process");}
  public bool HasExited{get{return WaitForExit(0);}}
  public uint ExitCode{get{EnsureOpen();uint code;if(!GetExitCodeProcess(process,out code))throw Error("GetExitCodeProcess");return code;}}
  public void Kill(){EnsureOpen();if(HasExited)return;if(!TerminateProcess(process,1))throw Error("Terminate exact created process");}
  // Like System.Diagnostics.Process.Dispose, closes our handle without stopping
  // a deliberately independent controller/rollback guard.
  public void Dispose(){if(Valid(process)){CloseHandle(process);process=IntPtr.Zero;}GC.SuppressFinalize(this);}
  ~NonUiProcess(){if(Valid(process))CloseHandle(process);}
 }
}
