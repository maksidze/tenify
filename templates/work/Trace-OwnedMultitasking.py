"""Bounded diagnosis of the exact laboratory Explorer already launched by us."""
import argparse, ctypes as C, hashlib, json, sys, time
from ctypes import wintypes as W
from pathlib import Path
root=Path(__file__).resolve().parents[1];base=root/'outputs/Windows10-Components'
sys.path[:0]=[str(base),str(root/'work/pylib')]
import pefile
from ChildDiagnostics import ChildDiagnostics
p=argparse.ArgumentParser();p.add_argument('pid',type=int);p.add_argument('--seconds',type=int,default=90);p.add_argument('--taskview',action='store_true');a=p.parse_args()
if not 5<=a.seconds<=120:raise ValueError('Bounded trace required')
states=[]
for f in (base/'state-vfs').glob('*/status.json'):
 try:s=json.loads(f.read_text(encoding='utf-8'))
 except (ValueError,OSError):continue
 if s.get('pid')==a.pid and s.get('status')=='running' and not s.get('preflight'):states.append((f,s))
if len(states)!=1 or states[0][1].get('profile')!='host-dcomp-resource':raise RuntimeError('Exact active own host-profile required')
stateFile,state=states[0];run=stateFile.parent
k=C.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
k.GetProcessTimes.argtypes=[W.HANDLE,C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME)]
k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.CloseHandle.argtypes=[W.HANDLE]
k.CheckRemoteDebuggerPresent.argtypes=[W.HANDLE,C.POINTER(W.BOOL)]
h=k.OpenProcess(0x1fffff,False,a.pid)
if not h:raise C.WinError(C.get_last_error())
trace=None
try:
 name=C.create_unicode_buffer(32768);n=W.DWORD(len(name))
 if not k.QueryFullProcessImageNameW(h,0,name,C.byref(n)):raise C.WinError(C.get_last_error())
 if name.value.casefold()!=str(base/'Runtime/Explorer10/explorer.exe').casefold():raise RuntimeError('Process image mismatch')
 times=[W.FILETIME() for _ in range(4)]
 if not k.GetProcessTimes(h,*[C.byref(t) for t in times]):raise C.WinError(C.get_last_error())
 born=((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)/1e7-11644473600
 import datetime
 recorded=datetime.datetime.fromisoformat(state['createdAt'].replace('Z','+00:00')).timestamp()
 if abs(recorded-born)>5:raise RuntimeError('PID creation time mismatch')
 configs=json.loads((base/'Lab/HostMultitaskingCompat/trace-breakpoints.json').read_text())
 dll=Path(configs[0]['path']);pe=pefile.PE(str(dll))
 if hashlib.sha256(dll.read_bytes()).hexdigest()!=configs[0]['sha256']:raise RuntimeError('Unsupported DLL')
 extras={0x1877e0:'MultitaskingView.EnsureXamlCore.Return',0x18782b:'MultitaskingView.ActualFactory.Return',
         0x18788e:'MultitaskingView.CreateHost.Return',0x490e2c:'MultitaskingView.DCompFactory.Enter',
         0x25afa8:'MultitaskingView.XamlFactory.Enter'}
 for rva,label in extras.items():
  item={'rva':rva,'label':label,'expectedByte':pe.get_data(rva,1).hex()}
  if rva==0x18782b:item['memory']=[{'register':'r14','size':8,'dereference':True}]
  configs[0]['points'].append(item)
 if a.taskview:
  # Task View uses its own service. No Alt+Tab branch patch is needed here.
  configs[0].pop('diagnosticPatches',None)
  points={0x486d50:'TaskView.ToggleService.Enter',0x486db0:'TaskView.LauncherQuery.Return',
          0x486e34:'TaskView.PerMonitorQuery.Return',0x486eb7:'TaskView.Queue.Return',
          0x486f03:'TaskView.ToggleService.Return',0x680a80:'TaskView.HostToggle.Enter',
          0x2ac10c:'TaskView.ManagerShowRequested.Enter',0x1082a0:'TaskView.HostShow.Enter',
          0x108498:'TaskView.HostShow.RegisterMonitors.Return',0x108742:'TaskView.HostShow.CreateFrames.Return',
          0x1088a2:'TaskView.HostShow.Return',0x1761d0:'TaskView.FindSwitchItem.Enter',
          0x1761fa:'TaskView.FindSwitchItem.Return',0x17625e:'TaskView.FindSwitchItem.Missing'}
  for rva,label in points.items():
   point={'rva':rva,'label':label,'expectedByte':pe.get_data(rva,1).hex()}
   if rva in (0x108742,0x1088a2):point['memory']=[{'register':'rdi','offset':0x130,'size':448}]
   if rva==0x1761d0:point['memory']=[{'register':'rcx','offset':-0x20,'size':32},{'register':'rdx','size':8,'dereference':True}]
   if rva==0x1761fa:point['memory']=[{'register':'rsp','offset':0x30,'size':8,'dereference':True}]
   configs[0]['points'].append(point)
  old=base/'Runtime/Explorer10/explorer.exe';oldpe=pefile.PE(str(old))
  digest=hashlib.sha256(old.read_bytes()).hexdigest()
  if digest!='b059f455b37047f4e2b5eae01b21715e4baa304888ac31e44905b41ff6bbcbd0':raise RuntimeError('Unsupported button Explorer')
  points={0x233990:'TaskView.Button.Click',0x2339fb:'TaskView.Button.Provider.Return',0x233699:'TaskView.Button.Queue',
          0x2336d0:'TaskView.Button.Worker',0x23371b:'TaskView.Button.QueryService.Return',
          0x23374d:'TaskView.Button.Invoke',0x233753:'TaskView.Button.Invoke.Return'}
  configs.append({'path':str(old),'sha256':digest,'points':[
      {'rva':rva,'label':label,'expectedByte':oldpe.get_data(rva,1).hex()} for rva,label in points.items()]})
  for point in configs[-1]['points']:
   if point['rva']==0x23371b:point['memory']=[{'register':'rsp','offset':0x40,'size':8,'dereference':True}]
   if point['rva']==0x23374d:point['memory']=[{'register':'rcx','size':8,'dereference':True}]
 stem='manual-taskview' if a.taskview else 'manual-multitasking'
 trace=ChildDiagnostics(h,a.pid,run/(stem+'-trace.jsonl'),configs)
 trace.emit(type='ownedTraceStart',pid=a.pid,creationTime=born,duration=a.seconds)
 print('Tracing owned PID '+str(a.pid)+' for '+str(a.seconds)+' seconds: '+str(run),flush=True)
 deadline=time.monotonic()+a.seconds
 while time.monotonic()<deadline and k.WaitForSingleObject(h,0)==258:trace.pump(100)
finally:
 if trace:trace.close()
 if h:
  debug=W.BOOL(True);ok=k.CheckRemoteDebuggerPresent(h,C.byref(debug))
  (run/(('manual-taskview' if a.taskview else 'manual-multitasking')+'-detach.json')).write_text(json.dumps({'checked':bool(ok),'debuggerPresent':bool(debug.value) if ok else None,'time':time.time()}))
  k.CloseHandle(h)
