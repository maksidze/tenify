"""Own non-UI test: genuine production gate, simulated shell state/launch."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import json,sys,time
from Recovery import recover_under_gate
root=Path(sys.argv[1]);k=C.WinDLL('kernel32',use_last_error=True)
def api(name,r,a):
    f=getattr(k,name);f.restype=r;f.argtypes=a;return f
P=C.c_void_p
wait=api('WaitForSingleObject',W.DWORD,[P,W.DWORD])
mutex=api('CreateMutexW',P,[P,W.BOOL,W.LPCWSTR]);release=api('ReleaseMutex',W.BOOL,[P]);close=api('CloseHandle',W.BOOL,[P])
def shell():return (root/'simulated-shell').read_text()!='empty'
def launch():
    # No native process is started. This marker is the sole fake side effect.
    (root/'simulated-fallback').write_text('Requested after gate release')
    return {'NativeStarted':False,'SimulatedFallbackRequested':True,'CleanupWasComplete':(root/'simulated-drained').exists()}
(root/'observer-waiting').write_text('Calling real production recovery gate')
started=time.monotonic()
result=recover_under_gate(wait,mutex,release,close,shell,launch)
result.update(ElapsedMs=int((time.monotonic()-started)*1000),NativeExplorerNeverStarted=True)
(root/'result.json').write_text(json.dumps(result,indent=2))
