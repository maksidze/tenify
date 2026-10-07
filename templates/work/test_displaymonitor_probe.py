from pathlib import Path
import concurrent.futures, ctypes as C, ctypes.wintypes as W, hashlib, json, subprocess, time
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/DisplayMonitorCompat'
manifest=json.loads((lab/'build.json').read_text(encoding='utf-8'))
for name,digest in manifest['artifacts'].items():
    assert hashlib.sha256((lab/name).read_bytes()).hexdigest()==digest,name
assert hashlib.sha256(Path(manifest['nativePCS']).read_bytes()).hexdigest()==manifest['nativePCSSha256']
k=C.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4;k.GetProcessTimes.restype=W.BOOL
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];k.QueryFullProcessImageNameW.restype=W.BOOL
k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeProcess.restype=W.BOOL
k.CheckRemoteDebuggerPresent.argtypes=[W.HANDLE,C.POINTER(W.BOOL)];k.CheckRemoteDebuggerPresent.restype=W.BOOL
expected_path=root/'outputs/Windows10-Components/Runtime/Explorer10/explorer.exe'
shell=k.OpenProcess(0x400,False,10488)
assert shell,C.get_last_error()
def shell_state():
    times=[W.FILETIME() for _ in range(4)]
    assert k.GetProcessTimes(shell,*[C.byref(t) for t in times])
    birth=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
    buf=C.create_unicode_buffer(4096);size=W.DWORD(len(buf));code=W.DWORD();debug=W.BOOL()
    assert k.QueryFullProcessImageNameW(shell,0,buf,C.byref(size))
    assert k.GetExitCodeProcess(shell,C.byref(code))
    assert k.CheckRemoteDebuggerPresent(shell,C.byref(debug))
    assert birth==134356712551859316 and buf.value.casefold()==str(expected_path).casefold()
    return {'pid':10488,'birth':str(birth),'path':buf.value,'exitCode':code.value,'debuggerPresent':bool(debug.value)}
def probe(apartment):
    started=time.monotonic()
    p=subprocess.Popen([str(lab/'DisplayMonitorProbe.exe'),apartment,'8000'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
    expired=False
    try:out,err=p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        expired=True;p.kill();out,err=p.communicate(timeout=5)
    (lab/(apartment.lower()+'.jsonl')).write_bytes(out)
    events=[json.loads(line) for line in out.decode('utf-8').splitlines()]
    identity=next((e for e in events if e.get('event')=='identity'),None)
    assert identity and identity['pid']==p.pid,identity
    implementations=[]
    for event in events:
        if event.get('event')=='implementation' and event.get('path'):
            path=Path(event['path'])
            implementations.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    return {'apartment':apartment,'pid':p.pid,'birth':identity['birth'],'exitCode':p.returncode,'supervisorTimeout':expired,'elapsedSeconds':round(time.monotonic()-started,3),'stderr':err.decode('utf-8','replace'),'outcome':next((e for e in events if e.get('event')=='outcome'),None),'cleanupComplete':any(e.get('event')=='cleanupComplete' for e in events),'implementations':implementations}
report={}
try:
    report['before']=shell_state()
    assert report['before']['exitCode']==259 and not report['before']['debuggerPresent']
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        report['probes']=list(pool.map(probe,['STA','MTA']))
finally:
    report['after']=shell_state()
    k.CloseHandle(shell)
    (lab/'own-results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
