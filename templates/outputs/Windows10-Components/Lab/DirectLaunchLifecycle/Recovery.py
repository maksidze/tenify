"""Unelevated recovery observer; never terminates a process or changes registration."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,sys,time,subprocess,os

def recover_under_gate(wait,mutex,release,close,shell,launch):
    """One shared transition/recovery gate; test uses fake shell/launch only."""
    gate=mutex(None,False,'Local\\Explorer10NativeRecovery')
    if not gate:raise C.WinError(C.get_last_error())
    owned=False
    try:
        # A newer standalone launcher holds the gate through bounded startup.
        owned=wait(gate,180000) in (0,0x80)
        if not owned:raise RuntimeError('Native recovery gate busy')
        if not shell():return launch()
        return {'ExistingShellPreserved':True,'NativeStarted':False}
    finally:
        if owned:release(gate)
        close(gate)

def main(config):
    state=json.loads(Path(config).read_text(encoding='utf-8-sig'));run=Path(state['Directory'])
    k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True)
    def api(lib,name,r,a):
        f=getattr(lib,name);f.restype=r;f.argtypes=a;return f
    p=C.c_void_p;d=W.DWORD
    op=api(k,'OpenProcess',p,[d,W.BOOL,d]);close=api(k,'CloseHandle',W.BOOL,[p])
    wait=api(k,'WaitForSingleObject',d,[p,d]);times=api(k,'GetProcessTimes',W.BOOL,[p,p,p,p,p]);query=api(k,'QueryFullProcessImageNameW',W.BOOL,[p,d,W.LPWSTR,C.POINTER(d)])
    shell=api(u,'GetShellWindow',p,[]);mutex=api(k,'CreateMutexW',p,[p,W.BOOL,W.LPCWSTR]);release=api(k,'ReleaseMutex',W.BOOL,[p])
    parent=state['Parent'];h=op(0x101000,False,parent['Pid'])
    if not h:raise C.WinError(C.get_last_error())
    try:
        c=C.c_uint64();e=C.c_uint64();a=C.c_uint64();b=C.c_uint64();name=C.create_unicode_buffer(32768);size=d(len(name))
        if not times(h,C.byref(c),C.byref(e),C.byref(a),C.byref(b)) or not query(h,0,name,C.byref(size)):raise C.WinError(C.get_last_error())
        if c.value!=int(parent['Birth']) or name.value.casefold()!=parent['Path'].casefold():raise RuntimeError('Exact recovery parent mismatch')
        (run/'recovery-ready').write_text(str(os.getpid()),encoding='ascii')
        while True:
            status=wait(h,200)
            if status==0 or (run/'launcher-finished').exists():break
            if status!=258:raise C.WinError(C.get_last_error())
        # Give the normal finally and job teardown a chance to finish first.
        time.sleep(2)
        result={'ParentExited':wait(h,0)==0,'TransitionStarted':(run/'transition-started').exists(),'NativeStarted':False}
        if result['TransitionStarted']:
            def launch():
                native=Path(state['NativePath']);expected=Path(os.environ['WINDIR'])/'explorer.exe'
                if native.resolve()!=expected.resolve() or hashlib.sha256(native.read_bytes()).hexdigest().casefold()!=state['NativeSHA256'].casefold():raise RuntimeError('Native recovery image changed')
                # This process never inherits the Explorer/controller job.
                proc=subprocess.Popen([str(native)],creationflags=subprocess.CREATE_NO_WINDOW)
                return {'NativeStarted':True,'NativePid':proc.pid}
            result.update(recover_under_gate(wait,mutex,release,close,shell,launch))
        (run/'recovery-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    finally:close(h)

if __name__=='__main__':main(sys.argv[1])
