"""Bounded shell test with graceful ExitExplorer and an independent recovery process."""
from pathlib import Path
import argparse,ctypes as C
from ctypes import wintypes as W
import subprocess,os,sys,time,json,uuid
p=argparse.ArgumentParser();p.add_argument('--profile',choices=['legacy','host-dcomp'],default='host-dcomp');p.add_argument('--seconds',type=int,default=180);p.add_argument('--run-directory');p.add_argument('--watchdog',action='store_true');p.add_argument('--parent-pid',type=int);a=p.parse_args()
base=Path(__file__).resolve().parent;win=Path(os.environ['WINDIR']);native=win/'explorer.exe';old=base/'Runtime/Explorer10/explorer.exe'
run=Path(a.run_directory).resolve() if a.run_directory else base/'state-live'/uuid.uuid4().hex;run.mkdir(parents=True,exist_ok=True)
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True);P=C.c_void_p;D=W.DWORD
def api(lib,name,result,types):f=getattr(lib,name);f.restype=result;f.argtypes=types;return f
find=api(u,'FindWindowW',P,[W.LPCWSTR,W.LPCWSTR]);owner=api(u,'GetWindowThreadProcessId',D,[P,C.POINTER(D)])
send=api(u,'SendMessageTimeoutW',P,[P,W.UINT,C.c_size_t,C.c_ssize_t,W.UINT,W.UINT,C.POINTER(C.c_size_t)])
openProcess=api(k,'OpenProcess',P,[D,W.BOOL,D]);close=api(k,'CloseHandle',W.BOOL,[P]);wait=api(k,'WaitForSingleObject',D,[P,D]);query=api(k,'QueryFullProcessImageNameW',W.BOOL,[P,D,W.LPWSTR,C.POINTER(D)])
terminate=api(k,'TerminateProcess',W.BOOL,[P,D])
def shell():
 h=find('Progman',None);pid=D()
 if h:owner(h,C.byref(pid))
 return pid.value
def imagePath(pid):
 h=openProcess(0x1000,False,pid)
 if not h:return None
 try:
  n=D(32768);b=C.create_unicode_buffer(n.value)
  return b.value if query(h,0,b,C.byref(n)) else None
 finally:close(h)
def restore():
 if shell()==0:subprocess.Popen([str(native)],creationflags=0x08000000)
if a.watchdog:
 h=openProcess(0x100000,False,a.parent_pid)
 try:
  deadline=time.monotonic()+a.seconds+70
  while time.monotonic()<deadline and not (run/'recovery.done').exists():
   if not h or wait(h,250)==0:
    (run/'stop').touch();time.sleep(2);restore();break
 finally:
  if h:close(h)
 raise SystemExit(0)
state={'profile':a.profile,'runDirectory':str(run),'phase':'preflight','registryModified':False,'systemFilesModified':False};controller=None;recovery=None;originalHandle=None
def save():
 temp=run/'live.tmp';temp.write_text(json.dumps(state,indent=2),encoding='utf-8');os.replace(temp,run/'live.json')
save()
try:
 probe=subprocess.run([sys.executable,str(base/'Launch-Explorer10-VFS.py'),'--preflight','--profile',a.profile,'--run-directory',str(run/'preflight')],timeout=30,creationflags=0x08000000)
 if probe.returncode:raise RuntimeError('Hidden preflight failed; current shell unchanged')
 original=shell();path=imagePath(original) if original else None;state.update(originalPid=original,originalPath=path)
 accepted={str(native).casefold(),str(old).casefold(),str((base.parent/'Explorer10-Xaml/explorer.exe')).casefold(),r'C:\Users\MAKSIDZE\Documents\Explorer_10\explorer.exe'.casefold()}
 if original and (path or '').casefold() not in accepted:raise RuntimeError('Unrecognized existing shell; unchanged')
 recovery=subprocess.Popen([sys.executable,__file__,'--watchdog','--parent-pid',str(os.getpid()),'--seconds',str(a.seconds),'--run-directory',str(run)],creationflags=0x08000000)
 if original:
  originalHandle=openProcess(0x100001,False,original)
  tray=find('Shell_TrayWnd',None);pid=D();owner(tray,C.byref(pid))
  if not originalHandle or not tray or pid.value!=original or shell()!=original:raise RuntimeError('Shell ownership changed; abort')
  state['phase']='graceful-exit';save();value=C.c_size_t()
  send(tray,1460,0,0,2,2000,C.byref(value))
  if wait(originalHandle,5000)!=0:
   if shell()!=0:raise RuntimeError('Graceful ExitExplorer did not release the desktop')
   if not terminate(originalHandle,0):raise C.WinError(C.get_last_error())
   if wait(originalHandle,3000)!=0:raise RuntimeError('Retired shell process did not finish')
   state['retiredShellProcessTerminated']=True
  state['gracefulExitSucceeded']=True
 if shell()!=0:raise RuntimeError('Another shell already owns desktop; abort test')
 controller=subprocess.Popen([sys.executable,str(base/'Launch-Explorer10-VFS.py'),'--profile',a.profile,'--run-directory',str(run)],creationflags=0x08000000)
 state.update(phase='starting',controllerPid=controller.pid);save();deadline=time.monotonic()+20;child=None
 while time.monotonic()<deadline:
  if controller.poll() is not None:raise RuntimeError('VFS controller exited before shell ready')
  if (run/'child-ready').exists():
   child=int((run/'child-ready').read_text());tray=find('Shell_TrayWnd',None);pid=D()
   if tray:owner(tray,C.byref(pid))
   if shell()==child and pid.value==child:break
  time.sleep(.15)
 else:raise RuntimeError('Old shell ownership timeout')
 state.update(phase='ready',childPid=child,childPath=imagePath(child));save();print(json.dumps(state),flush=True)
 end=time.monotonic()+a.seconds
 while time.monotonic()<end and controller.poll() is None and not (run/'finish').exists():time.sleep(.3)
 state['phase']='finishing';save()
except Exception as e:state.update(phase='error',error=str(e));save();print(json.dumps(state),flush=True)
finally:
 (run/'stop').touch()
 if controller:
  try:controller.wait(timeout=8)
  except subprocess.TimeoutExpired:state['controllerStopTimedOut']=True
 restore();time.sleep(2)
 state['finalShellPid']=shell();state['finalShellPath']=imagePath(shell()) if shell() else None
 if state['phase']!='error':state['phase']='finished'
 save();(run/'recovery.done').touch()
 if originalHandle:close(originalHandle)
