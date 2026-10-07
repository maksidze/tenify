"""Own private worker exact-name refusal/positive browser; normal WinMain held."""
import ctypes as C,struct,uuid,json,subprocess,importlib.util
from ctypes import wintypes as W
from pathlib import Path
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1]
def module(path,name):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
api=module(LAB/'Launch-ControlTheme10.py','control_api');entry=module(BASE/'Launch-ResourceCompat.py','control_entry')
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True);P=C.c_void_p
def bind(lib,n,r,a):f=getattr(lib,n);f.restype=r;f.argtypes=a;return f
create=bind(k,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,P,P]);wait=bind(k,'WaitForSingleObject',W.DWORD,[P,W.DWORD]);terminate=bind(k,'TerminateProcess',W.BOOL,[P,W.UINT]);close=bind(k,'CloseHandle',W.BOOL,[P]);desktop=bind(u,'CreateDesktopW',P,[W.LPCWSTR,W.LPCWSTR,P,W.DWORD,W.DWORD,P]);closeDesktop=bind(u,'CloseDesktop',W.BOOL,[P]);exitThread=bind(k,'GetExitCodeThread',W.BOOL,[P,C.POINTER(W.DWORD)])
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('reservedSize',W.WORD),('bytes',P),('input',P),('output',P),('error',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',W.DWORD),('tid',W.DWORD)]
root=LAB/'fixtures'/uuid.uuid4().hex;folder=root/'Folder';folder.mkdir(parents=True);(folder/'own.txt').write_text('Own worker item');name='ControlThemeOwned-'+uuid.uuid4().hex;desk=desktop(name,None,None,0,0x10000000,None);pi=PI();proof=dict(OwnChildOnly=True,PrivateNeverSwitched=True,NormalWinMainHeld=True)
try:
 si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+name;exe=BASE/'Runtime/Explorer10/explorer.exe';cmd=C.create_unicode_buffer(subprocess.list2cmdline([str(exe)]))
 if not create(str(exe),cmd,None,None,False,0x08000004,None,str(exe.parent),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
 boot=entry.OwnChildBootstrap(pi,exe);boot.pause_at_entry(20);boot.finish(detach=True,resume_primary=False);api.install_control_theme10(boot);pre=api.prepare_control_theme10_probe(boot);base=int(pre['Base'],16);dll=LAB/'BrowserProbe.dll'
 for wanted in ['Default',name]:
  f=str(folder.resolve()).encode('utf-16-le')+b'\0\0';d=wanted.encode('utf-16-le')+b'\0\0';mem=boot.alloc(pi.process,None,4096,0x3000,4);boot.patch(mem,struct.pack('<QQ',mem+16,mem+16+len(f))+f+d);tid=W.DWORD();thread=boot.remote_thread(pi.process,None,0,base+api.exports(dll)['ControlBrowserProbeWorker'],mem,0,C.byref(tid))
  if not thread or wait(thread,20000)!=0:raise RuntimeError('Own worker failed/timeout')
  code=W.DWORD();exitThread(thread,C.byref(code));close(thread);boot.free(pi.process,mem,0,0x8000)
  if wanted=='Default':proof['WrongExpectedDesktopRefused']=code.value==5 and struct.unpack('<12I',boot.read(base+api.exports(dll)['ControlBrowserState'],48))[3]==0
  else:
   data=struct.unpack('<12I',boot.read(base+api.exports(dll)['ControlBrowserState'],48));proof['ActualPrivateWorkerNavigation']=code.value==0 and data[5]==1 and data[7]==1 and data[8]==1 and data[9]>=1 and data[10]>=1;proof['WorkerThread']=tid.value
finally:
 if pi.process:terminate(pi.process,0xdeca);wait(pi.process,5000);close(pi.thread);close(pi.process)
 proof['DesktopClosed']=bool(closeDesktop(desk))
proof['Passed']=proof.get('WrongExpectedDesktopRefused') and proof.get('ActualPrivateWorkerNavigation') and proof['DesktopClosed'];(LAB/'own-worker-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
if not proof['Passed']:raise RuntimeError('Own worker proof failed')
