from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import json,os,sys,time,subprocess
from ChildJob import ChildJob
P=C.c_void_p;D=W.DWORD;k=C.WinDLL('kernel32',use_last_error=True)
def api(name,r,a):
 f=getattr(k,name);f.restype=r;f.argtypes=a;return f
times=api('GetProcessTimes',W.BOOL,[P,P,P,P,P]);close=api('CloseHandle',W.BOOL,[P]);wait=api('WaitForSingleObject',D,[P,D]);resume=api('ResumeThread',D,[P]);console=api('GetConsoleWindow',P,[])
def birth(h):
 vals=[C.c_uint64() for _ in range(4)]
 if not times(h,*(C.byref(v) for v in vals)):raise C.WinError(C.get_last_error())
 return vals[0].value
mode=sys.argv[1];root=Path(sys.argv[2]);root.mkdir(parents=True,exist_ok=True)
if mode=='user':
 (root/'user.json').write_text(json.dumps(dict(Pid=os.getpid(),Birth=birth(P(-1)),Path=sys.executable,Console=bool(console()))));time.sleep(90)
elif mode=='explorer' or mode=='tree':
 user=subprocess.Popen([sys.executable,__file__,'user',str(root)],creationflags=subprocess.CREATE_NO_WINDOW)
 (root/'explorer.json').write_text(json.dumps(dict(Pid=os.getpid(),Birth=birth(P(-1)),Path=sys.executable,Console=bool(console()))));time.sleep(90)
elif mode in ('controller','preflight-controller'):
 class SI(C.Structure):
  _fields_=[('cb',D),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',D),('y',D),('xs',D),('ys',D),('xc',D),('yc',D),('fill',D),('flags',D),('show',W.WORD),('res2',W.WORD),('pres2',P),('hin',P),('hout',P),('herr',P)]
 class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',D),('tid',D)]
 si=SI();si.cb=C.sizeof(si);pi=PI();job=ChildJob(breakaway_children=mode=='controller')
 try:
  args=[sys.executable,__file__,'explorer',str(root)]
  job.create_suspended(sys.executable,subprocess.list2cmdline(args),si,pi,root)
  if resume(pi.thread)!=1:raise RuntimeError('Bad primary suspend count')
  (root/'controller.json').write_text(json.dumps(dict(Pid=os.getpid(),Birth=birth(P(-1)),Path=sys.executable,Console=bool(console()))));time.sleep(90)
 finally:
  job.shutdown()
  if pi.thread:close(pi.thread)
  if pi.process:close(pi.process)
