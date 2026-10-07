from pathlib import Path
import ctypes as C, ctypes.wintypes as W, json, subprocess, time
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/DisplayMonitorPublisher'
ps=Path(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
k=C.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4;k.GetProcessTimes.restype=W.BOOL
k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeProcess.restype=W.BOOL
report={}
for mode in ('normal','parent-death'):
    ready=lab/('job-proof-'+mode+'.json')
    # Unique filename is preferable to deleting anything from a previous run.
    ready=ready.with_name(ready.stem+'-'+str(time.time_ns())+ready.suffix)
    parent=subprocess.Popen([str(ps),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(root/'work/Test-PublisherJobGuard.ps1'),'-Mode',mode,'-Report',str(ready)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
    child=0
    try:
        limit=time.monotonic()+10
        while not ready.exists() and parent.poll() is None and time.monotonic()<limit:time.sleep(.05)
        assert ready.exists(),parent.communicate(timeout=2)
        data=json.loads(ready.read_text(encoding='utf-8-sig'))
        assert data['ParentPid']==parent.pid and data['AssignedBeforeResume']
        child=k.OpenProcess(0x101000,False,data['Pid'])
        assert child,C.get_last_error()
        times=[W.FILETIME() for _ in range(4)]
        assert k.GetProcessTimes(child,*[C.byref(t) for t in times])
        birth=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
        assert str(birth)==data['Birth']
        if mode=='parent-death':
            assert k.WaitForSingleObject(child,0)==258
            parent.kill() # Only exact own PowerShell Popen. Its job handle dies with it.
        stdout,stderr=parent.communicate(timeout=8)
        assert k.WaitForSingleObject(child,3000)==0,'Child survived job owner death/cleanup'
        code=W.DWORD();assert k.GetExitCodeProcess(child,C.byref(code))
        assert code.value!=259
        detail={'parentPid':parent.pid,'parentExitCode':parent.returncode,'childPid':data['Pid'],'childBirth':data['Birth'],'assignedBeforeResume':True,'childExited':True,'childExitCode':code.value,'stderr':stderr.decode('utf-8','replace')}
        if mode=='normal':
            done=json.loads(Path(str(ready)+'.done').read_text(encoding='utf-8-sig'))
            assert parent.returncode==0 and done['ExplicitStopSucceeded'] and done['ExitCode']==57346
        report[mode]=detail
    finally:
        if parent.poll() is None:parent.kill();parent.communicate(timeout=5)
        if child:k.CloseHandle(child)
report['ok']=True
(lab/'job-own-proof.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
