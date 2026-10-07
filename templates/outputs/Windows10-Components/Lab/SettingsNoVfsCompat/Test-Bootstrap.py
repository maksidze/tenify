from pathlib import Path
import ctypes as C,sys,subprocess,json,importlib.util,traceback
from ctypes import wintypes as W
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parent/'ShellAppearanceCompat'));from OwnBootstrap import OwnChildBootstrap
spec=importlib.util.spec_from_file_location('SettingsNoVfs',H/'Launch-SettingsNoVfs.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
P=C.c_void_p
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('cbReserved',W.WORD),('bytes',P),('input',P),('output',P),('error',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',W.DWORD),('tid',W.DWORD)]
k=C.WinDLL('kernel32',use_last_error=True)
def bind(n,r,a):f=getattr(k,n);f.restype=r;f.argtypes=a;return f
create=bind('CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,P,P]);wait=bind('WaitForSingleObject',W.DWORD,[P,W.DWORD]);terminate=bind('TerminateProcess',W.BOOL,[P,W.UINT]);close=bind('CloseHandle',W.BOOL,[P]);dbg=bind('CheckRemoteDebuggerPresent',W.BOOL,[P,C.POINTER(W.BOOL)])
proof=dict(NoVFS=True,NoUI=True,ActualSystemSettingsExe=False);pi=PI()
try:
 exe=H/'FactoryFixture.exe';log=H/'bootstrap-child.log';si=SI();si.cb=C.sizeof(si);cmd=C.create_unicode_buffer(subprocess.list2cmdline([str(exe),str(log)]));assert create(str(exe),cmd,None,None,False,0x08000004,None,str(H),C.byref(si),C.byref(pi)),C.get_last_error()
 b=OwnChildBootstrap(pi,exe);b.pause_at_entry();b.finish(detach=True,resume_primary=False);proof['Selector']=M.initialize_remote(b,H/'SettingsFactorySelector.dll','SettingsNoVfsFixtureInitialize');proof['Content']=M.initialize_remote(b,H.parent/'SettingsContentCompat/SettingsContentCompat.dll','SettingsInitialize');present=W.BOOL();assert dbg(pi.process,C.byref(present)) and not present.value;proof['DebuggerAbsent']=True;b.resume_primary();assert wait(pi.process,10000)==0;getexit=bind('GetExitCodeProcess',W.BOOL,[P,C.POINTER(W.DWORD)]);exitcode=W.DWORD();assert getexit(pi.process,C.byref(exitcode)) and exitcode.value==0;proof['ExitCode']=exitcode.value;proof['ChildLog']=log.read_text(encoding='utf-8-sig');assert 'COMPLETE' in proof['ChildLog'];proof['Passed']=True
except:proof['Error']=traceback.format_exc()
finally:
 if pi.process:
  if wait(pi.process,0)==258:terminate(pi.process,0xdeca);wait(pi.process,5000)
  close(pi.thread);close(pi.process)
 (H/'bootstrap-own-proof.json').write_text(json.dumps(proof,indent=2))
