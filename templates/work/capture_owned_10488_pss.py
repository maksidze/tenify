from pathlib import Path
import ctypes as C, ctypes.wintypes as W, datetime as dt, hashlib, importlib.util, json, sys
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/ThreadStackSnapshot'
run=root/'outputs/Windows10-Components/state-vfs/3686bba15ab24dbc80884fead8247eac'
state=json.loads((run/'status.json').read_text(encoding='utf-8-sig'))
assert state['pid']==10488 and state['profile']=='host-dcomp-resource'
image=Path(state['exe'])
assert hashlib.sha256(image.read_bytes()).hexdigest()=='b059f455b37047f4e2b5eae01b21715e4baa304888ac31e44905b41ff6bbcbd0'
k=C.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4;k.GetProcessTimes.restype=W.BOOL
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];k.QueryFullProcessImageNameW.restype=W.BOOL
k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeProcess.restype=W.BOOL
k.CheckRemoteDebuggerPresent.argtypes=[W.HANDLE,C.POINTER(W.BOOL)];k.CheckRemoteDebuggerPresent.restype=W.BOOL
h=k.OpenProcess(0x400,False,10488)
assert h,C.get_last_error()
report={}
try:
    times=[W.FILETIME() for _ in range(4)]
    assert k.GetProcessTimes(h,*[C.byref(t) for t in times]),C.get_last_error()
    birth=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
    epoch=dt.datetime(1601,1,1,tzinfo=dt.timezone.utc)
    created=epoch+dt.timedelta(microseconds=birth//10)
    assert created.isoformat()=='2026-10-05T10:54:15.185931+00:00',created
    buf=C.create_unicode_buffer(4096);size=W.DWORD(len(buf))
    assert k.QueryFullProcessImageNameW(h,0,buf,C.byref(size))
    assert buf.value.casefold()==str(image).casefold(),buf.value
    spec=importlib.util.spec_from_file_location('capture',lab/'capture.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    if '--verify-existing' in sys.argv:
        result=json.loads((run/'pss-all-threads.jsonl.status.json').read_text(encoding='utf-8'))
        events=[json.loads(line) for line in (run/'pss-all-threads.jsonl').read_text(encoding='utf-8').splitlines()]
        assert result['targetPid']==10488 and result['expectedBirth']==str(birth)
    else:
        result,events=mod.capture(10488,birth,image,'all',run/'pss-all-threads.jsonl')
    code=W.DWORD();debug=W.BOOL()
    assert k.GetExitCodeProcess(h,C.byref(code))
    assert k.CheckRemoteDebuggerPresent(h,C.byref(debug))
    report={'capture':result,'pid':10488,'birth':str(birth),'createdUTC':created.isoformat(),'path':buf.value,'afterExitCode':code.value,'afterDebuggerPresent':bool(debug.value),'snapshotFreed':any(e['event']=='snapshotFreed' and e['code']==0 for e in events)}
    assert code.value==259 and not debug.value and report['snapshotFreed'],report
    assert result['complete'] and result['complete']['ok'],result
finally:
    k.CloseHandle(h)
    (run/'pss-owned-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
