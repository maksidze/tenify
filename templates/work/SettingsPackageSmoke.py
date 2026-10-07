"""Disposable, owned settings child with package identity and continuously flushed diagnostics."""
from pathlib import Path
import ctypes as C,sys,os,subprocess,json,time,uuid
from ctypes import wintypes as W
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';lab=base/'Lab/SettingsIdentity'
sys.path.insert(0,str(base));from ChildDiagnostics import ChildDiagnostics
P=C.c_void_p;D=W.DWORD;k=C.WinDLL('kernel32',use_last_error=True)
def api(n,r,t):f=getattr(k,n);f.restype=r;f.argtypes=t;return f
class SI(C.Structure):
 _fields_=[('cb',D),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',D),('y',D),('xs',D),('ys',D),('xc',D),('yc',D),('fill',D),('flags',D),('show',W.WORD),('res2',W.WORD),('pres2',P),('hin',P),('hout',P),('herr',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',D),('tid',D)]
create=api('CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
resume=api('ResumeThread',D,[P]);term=api('TerminateProcess',W.BOOL,[P,D]);wait=api('WaitForSingleObject',D,[P,D]);close=api('CloseHandle',W.BOOL,[P]);getExit=api('GetExitCodeProcess',W.BOOL,[P,C.POINTER(D)])
pkg=api('GetCurrentPackageFullName',C.c_int32,[C.POINTER(D),W.LPWSTR]);pkgChild=api('GetPackageFullName',C.c_int32,[P,C.POINTER(D),W.LPWSTR])
state={'phase':'initialized','controllerPid':os.getpid(),'systemFilesModified':False};pi=PI();debug=None;vfs=None;parameters=None;dllDir=None
def save():
 (lab/'smoke-progress.json').write_text(json.dumps(state,indent=2),encoding='utf8')
save()
try:
 n=D(4096);b=C.create_unicode_buffer(n.value);status=pkg(C.byref(n),b);state['identity']={'hr':status,'name':b.value};save()
 exe=base/'Image/4/Windows/ImmersiveControlPanel/SystemSettings.exe';si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\Default'
 nativeVfs='--native-vfs' in sys.argv
 if nativeVfs:
  dllDir=os.add_dll_directory(str(base/'Tools/USVFS/bin'));vfs=C.WinDLL(str(base/'Tools/USVFS/bin/usvfs_x64.dll'),use_last_error=True)
  def vf(n,r,t):f=getattr(vfs,n);f.restype=r;f.argtypes=t;return f
  parameters=vf('usvfsCreateParameters',P,[])();vf('usvfsSetInstanceName',None,[P,C.c_char_p])(parameters,('Settings10_'+uuid.uuid4().hex).encode())
  if not vf('usvfsCreateVFS',W.BOOL,[P])(parameters):raise C.WinError(C.get_last_error())
  link=vf('usvfsVirtualLinkFile',W.BOOL,[W.LPCWSTR,W.LPCWSTR,C.c_uint]);linkDir=vf('usvfsVirtualLinkDirectoryStatic',W.BOOL,[W.LPCWSTR,W.LPCWSTR,C.c_uint])
  for filename in ['SystemSettings.dll','SystemSettingsViewModel.Desktop.dll','Telemetry.Common.dll','resources.pri']:
   old=exe.parent/filename;target=Path('C:/Windows/ImmersiveControlPanel')/filename
   if not link(str(old),str(target),0):raise C.WinError(C.get_last_error())
  resources=base/'Image/4/Windows/SystemResources/Windows.UI.SettingsAppThreshold'
  if not linkDir(str(resources),'C:/Windows/SystemResources/Windows.UI.SettingsAppThreshold',8):raise C.WinError(C.get_last_error())
  blacklist=vf('usvfsBlacklistExecutable',None,[W.LPCWSTR])
  for name in ['SystemSettingsBroker.exe','RuntimeBroker.exe','dllhost.exe','explorer.exe','StartMenuExperienceHost.exe','ShellExperienceHost.exe']:blacklist(name)
  create=vf('usvfsCreateProcessHooked',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
  exe=Path('C:/Windows/ImmersiveControlPanel/SystemSettings.exe');state['nativePathWithPrivateVFS']=True;save()
 state['phase']='creating';save()
 if not create(str(exe),C.create_unicode_buffer(subprocess.list2cmdline([str(exe),'-ServerName:microsoft.windows.immersivecontrolpanel'])),None,None,False,4,None,str(exe.parent),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
 state.update(phase='created',pid=pi.pid);save()
 debug=ChildDiagnostics(pi.process,pi.pid,lab/('settings-native-vfs-debug.jsonl' if nativeVfs else 'settings-package-server-debug.jsonl'));resume(pi.thread);state['phase']='running';save()
 deadline=time.monotonic()+(70 if nativeVfs else 10)
 while time.monotonic()<deadline and wait(pi.process,0)==258:debug.pump(100)
 status=D();getExit(pi.process,C.byref(status));state.update(phase='observed',exitCode=status.value);save()
except BaseException as e:state.update(phase='error',error=repr(e));save()
finally:
 if pi.process:
  term(pi.process,0)
  end=time.monotonic()+2
  while debug and time.monotonic()<end and wait(pi.process,0)==258:debug.pump(100)
  if debug:debug.close()
  close(pi.thread);close(pi.process)
 if vfs:
  vf('usvfsDisconnectVFS',None,[])()
  if parameters:vf('usvfsFreeParameters',None,[P])(parameters)
 if dllDir:dllDir.close()
 state['cleanup']=True;save()
