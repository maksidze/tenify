from pathlib import Path
import ctypes as C,subprocess,json,sys,importlib.util,hashlib,struct
from ctypes import wintypes as W
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parent/'ShellAppearanceCompat'));from OwnBootstrap import OwnChildBootstrap
spec=importlib.util.spec_from_file_location('NativeDcomp',H/'Launch-NativeDcomp.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
P=C.c_void_p
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('cbReserved',W.WORD),('bytes',P),('input',P),('output',P),('error',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',W.DWORD),('tid',W.DWORD)]
k=C.WinDLL('kernel32',use_last_error=True)
def bind(name,r,a):f=getattr(k,name);f.restype=r;f.argtypes=a;return f
create=bind('CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,P,P]);terminate=bind('TerminateProcess',W.BOOL,[P,W.UINT]);wait=bind('WaitForSingleObject',W.DWORD,[P,W.DWORD]);close=bind('CloseHandle',W.BOOL,[P]);debug=bind('CheckRemoteDebuggerPresent',W.BOOL,[P,C.POINTER(W.BOOL)])
exe=H/'Fixture.exe';log=H/'fixture-main.log';log.unlink(missing_ok=True);si=SI();si.cb=C.sizeof(si);pi=PI();command=C.create_unicode_buffer(subprocess.list2cmdline([str(exe),str(log)]));assert create(str(exe),command,None,None,False,0x08000004,None,str(H),C.byref(si),C.byref(pi)),C.get_last_error();proof={}
try:
 b=OwnChildBootstrap(pi,exe);b.pause_at_entry();b.finish(detach=True,resume_primary=False)
 try:
  b.primary_suspended=False;m.install_native_dcomp_compat(b)
 except RuntimeError:proof['RunningStateRejected']=True
 else:raise RuntimeError('Running state accepted')
 b.primary_suspended=True;report=m.install_native_dcomp_compat(b);proof['Installed']=report
 try:m.install_native_dcomp_compat(b)
 except RuntimeError:proof['RepeatRejectedBeforeExtraAllocation']=True
 else:raise RuntimeError('Repeated alteration accepted')
 found=b.modules();proof['PCSCount']=sum(n.lower().endswith('\\twinui.pcshell.dll') for n in found);assert proof['PCSCount']==1
 detached=W.BOOL();assert debug(pi.process,C.byref(detached)) and not detached.value;proof['DebuggerAbsent']=True
 # Synthetic executable fixture tests the exact dispatch instruction shape without native UI calls.
 alloc=bind('VirtualAlloc',P,[P,C.c_size_t,W.DWORD,W.DWORD]);protect=bind('VirtualProtect',W.BOOL,[P,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]);free=bind('VirtualFree',W.BOOL,[P,C.c_size_t,W.DWORD]);flush=bind('FlushInstructionCache',W.BOOL,[P,P,C.c_size_t]);page=alloc(None,4096,0x3000,4);assert page
 try:
  code=b'\x83\xfa\x01\x75\x05'+m.rel(page+5,page+64)+m.rel(page+10,page+80);C.memmove(page,code,len(code));C.memmove(page+64,bytes.fromhex('b86f000000c3'),6);C.memmove(page+80,bytes.fromhex('b8de000000c3'),6);old=W.DWORD();assert protect(page,4096,0x20,C.byref(old));assert flush(k.GetCurrentProcess(),page,4096);f=C.WINFUNCTYPE(C.c_int,P,C.c_int)(page);proof['BranchResults']={str(x):f(None,x) for x in [0,1,2,3]};assert proof['BranchResults']=={'0':222,'1':111,'2':222,'3':222}
 finally:free(page,0,0x8000)
 b.resume_primary();assert wait(pi.process,5000)==0;proof['PrimaryRan']='PrimaryRan' in log.read_text();proof['NativeDiskUnchanged']=hashlib.sha256(m.PCS.read_bytes()).hexdigest()==m.SHA;assert proof['PrimaryRan'] and proof['NativeDiskUnchanged'];proof['Passed']=True
finally:
 if wait(pi.process,0)==258:terminate(pi.process,0xdeca);wait(pi.process,5000)
 close(pi.thread);close(pi.process);(H/'own-proof.json').write_text(json.dumps(proof,indent=2))
print(json.dumps(proof,indent=2))
