from pathlib import Path
import importlib.util,ctypes as C,json,sys
from ctypes import wintypes as W
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';lab=base/'Lab/FlyoutCompat/OrdinalAudit'
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
r=module('ownchild',base/'Launch-ResourceCompat.py');t=module('touchpad',base/'Launch-TouchpadCompat.py')
class SI(C.Structure):
 _fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('res2',W.WORD),('pres2',C.c_void_p),('hin',C.c_void_p),('hout',C.c_void_p),('herr',C.c_void_p)]
class PI(C.Structure):_fields_=[('process',C.c_void_p),('thread',C.c_void_p),('pid',W.DWORD),('tid',W.DWORD)]
k=C.WinDLL('kernel32',use_last_error=True);create=r.bind(k,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,W.DWORD,C.c_void_p,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
terminate=r.bind(k,'TerminateProcess',W.BOOL,[C.c_void_p,W.DWORD]);wait=r.bind(k,'WaitForSingleObject',W.DWORD,[C.c_void_p,W.DWORD]);close=r.bind(k,'CloseHandle',W.BOOL,[C.c_void_p]);exitCode=r.bind(k,'GetExitCodeProcess',W.BOOL,[C.c_void_p,C.POINTER(W.DWORD)])
exe=lab/'TouchpadPolicyChild.exe';log=lab/'touchpad-own-child.log';pi=PI();si=SI();si.cb=C.sizeof(si);si.flags=1;si.show=0
command=C.create_unicode_buffer(f'"{exe}" "{log}"');result={'ownNativeChildOnly':True,'notExplorerOrSEH':True,'noRegistryWrites':True};boot=None
try:
 if not create(str(exe),command,None,None,False,0x08000004,None,str(lab),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
 result['pid']=pi.pid;boot=r.OwnChildBootstrap(pi,exe);boot.pause_at_entry();boot.finish(detach=True,resume_primary=False)
 if '--preload-stub' in sys.argv:boot.load_library(base/'Lab/WindowGroupCompat/U32W10.dll')
 result['installer']=t.install_touchpad_compat(boot);boot.resume_primary()
 if wait(pi.process,10000)!=0:raise TimeoutError('Owned policy child')
 code=W.DWORD();exitCode(pi.process,C.byref(code));result['exitCode']=code.value;result['log']=log.read_text();result['events']=boot.events
 if code.value:raise RuntimeError('Own disabled policy test failed')
except BaseException as e:result['error']=repr(e);raise
finally:
 if pi.process:terminate(pi.process,0xdec0)
 if boot and boot.attached:boot.detach(pi.pid)
 if pi.thread:close(pi.thread)
 if pi.process:close(pi.process)
 (lab/('touchpad-own-child-reuse-result.json' if '--preload-stub' in sys.argv else 'touchpad-own-child-result.json')).write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
