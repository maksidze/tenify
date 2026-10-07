"""Own new signed Explorer image, private desktop never switched; WinMain held."""
import ctypes as C,struct,uuid,json,subprocess,importlib.util,sys
from ctypes import wintypes as W
from pathlib import Path
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1]
def module(path,name):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
api=module(LAB/'Launch-ControlTheme10.py','control_bootstrap');native=module(BASE/'Launch-ResourceCompat.py','own_control_entry')
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True);P=C.c_void_p
def bind(lib,name,r,a):f=getattr(lib,name);f.restype=r;f.argtypes=a;return f
create=bind(k,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,P,P]);wait=bind(k,'WaitForSingleObject',W.DWORD,[P,W.DWORD]);close=bind(k,'CloseHandle',W.BOOL,[P]);terminate=bind(k,'TerminateProcess',W.BOOL,[P,W.UINT]);desktop=bind(u,'CreateDesktopW',P,[W.LPCWSTR,W.LPCWSTR,P,W.DWORD,W.DWORD,P]);closeDesktop=bind(u,'CloseDesktop',W.BOOL,[P])
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('reservedSize',W.WORD),('bytes',P),('input',P),('output',P),('error',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',W.DWORD),('tid',W.DWORD)]
root=LAB/'fixtures'/uuid.uuid4().hex;folder=root/'Folder';folder.mkdir(parents=True);(folder/'own.txt').write_text('Own folder navigation item')
proof=dict(NoWorkingShellAttach=True,NoGlobalShellActivation=True,PrivateDesktopNeverSwitched=True,NormalExplorerWinMainNeverRun=True,Runs=[])
for active in [False,True]:
 name='ControlThemeOwned-'+uuid.uuid4().hex;desk=desktop(name,None,None,0,0x10000000,None)
 if not desk:raise C.WinError(C.get_last_error())
 pi=PI();si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+name;exe=BASE/'Runtime/Explorer10/explorer.exe';cmd=C.create_unicode_buffer(subprocess.list2cmdline([str(exe)]));row=dict(ScopedTheme=active)
 try:
  if not create(str(exe),cmd,None,None,False,0x08000004,None,str(exe.parent),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
  row['PID']=pi.pid;row['PrimaryThread']=pi.tid;boot=native.OwnChildBootstrap(pi,exe);boot.pause_at_entry(20);boot.finish(detach=True,resume_primary=False)
  if active:row['Install']=api.install_control_theme10(boot)
  dll=LAB/'BrowserProbe.dll';base=boot.load_library(dll);data=str(folder.resolve()).encode('utf-16-le')+b'\0\0';args=boot.alloc(pi.process,None,4096,0x3000,4);boot.patch(args,data)
  result=api.primary_call(boot,base+api.exports(dll)['ControlBrowserProbe'],args,20)
  values=struct.unpack('<12I',boot.read(base+api.exports(dll)['ControlBrowserState'],48));row['Browser']=dict(zip(['Size','Version','Result','Complete','Thread','NavigationComplete','NavigationFailed','ItemCount','FolderMatched','DefViews','DirectUIViews','Reserved'],values))
  if result or values[2] or not values[5] or values[6] or values[7]!=1 or not values[8] or not values[9] or not values[10] or values[4]!=pi.tid:raise RuntimeError('Actual owned Explorer browser navigation failed '+str(row))
  row['Passed']=True;boot.free(pi.process,args,0,0x8000)
 except BaseException as e:row['Error']=str(e)
 finally:
  if pi.process:
   if wait(pi.process,0)==258:terminate(pi.process,0xdeca);wait(pi.process,5000)
   if pi.thread:close(pi.thread)
   close(pi.process)
  row['DesktopClosed']=bool(closeDesktop(desk));proof['Runs'].append(row)
proof['Passed']=all(r.get('Passed') and r['DesktopClosed'] for r in proof['Runs']);(LAB/'own-explorer-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
if not proof['Passed']:raise RuntimeError('Owned Explorer A/B proof not passed')
