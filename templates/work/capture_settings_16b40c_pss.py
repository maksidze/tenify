from pathlib import Path
import ctypes as C, ctypes.wintypes as W, importlib.util,json,struct
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SettingsBrokerCompat'
prefix=lab/'broker-settings-16b40c5c5f60'
prepared=json.loads(prefix.with_suffix('.prepared.json').read_text(encoding='utf-8-sig'))
claim=Path(str(prefix)+'.log.claim').read_bytes()
assert len(claim)==16
magic,pid,birth=struct.unpack('<IIQ',claim)
assert magic==0x53434c32 and pid==11948,(hex(magic),pid)
native=prepared['NativePath'];expected_package=prepared['PackageFullName']
k=C.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4;k.GetProcessTimes.restype=W.BOOL
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];k.QueryFullProcessImageNameW.restype=W.BOOL
k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeProcess.restype=W.BOOL
k.CheckRemoteDebuggerPresent.argtypes=[W.HANDLE,C.POINTER(W.BOOL)];k.CheckRemoteDebuggerPresent.restype=W.BOOL
k.GetPackageFullName.argtypes=[W.HANDLE,C.POINTER(W.UINT),W.LPWSTR];k.GetPackageFullName.restype=W.LONG
h=k.OpenProcess(0x400,False,pid);assert h,C.get_last_error()
def state():
    times=[W.FILETIME() for _ in range(4)];assert k.GetProcessTimes(h,*[C.byref(t) for t in times])
    observed_birth=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
    assert observed_birth==birth
    path=C.create_unicode_buffer(4096);length=W.DWORD(len(path));assert k.QueryFullProcessImageNameW(h,0,path,C.byref(length))
    assert path.value.casefold()==native.casefold()
    pkg=C.create_unicode_buffer(4096);n=W.UINT(len(pkg));assert k.GetPackageFullName(h,C.byref(n),pkg)==0
    assert pkg.value==expected_package
    code=W.DWORD();debug=W.BOOL();assert k.GetExitCodeProcess(h,C.byref(code));assert k.CheckRemoteDebuggerPresent(h,C.byref(debug))
    return {'pid':pid,'birth':str(birth),'path':path.value,'package':pkg.value,'exitCode':code.value,'debuggerPresent':bool(debug.value)}
report={}
try:
    report['before']=state();assert report['before']['exitCode']==259 and not report['before']['debuggerPresent']
    module_path=root/'outputs/Windows10-Components/Lab/ThreadStackSnapshot/capture.py'
    spec=importlib.util.spec_from_file_location('capture',module_path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    result,events=mod.capture(pid,birth,native,'all',Path(str(prefix)+'.pss.jsonl'))
    report['capture']=result;report['snapshotFreed']=any(e.get('event')=='snapshotFreed' and e.get('code')==0 for e in events)
    report['after']=state()
finally:
    k.CloseHandle(h);Path(str(prefix)+'.pss-owned-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
