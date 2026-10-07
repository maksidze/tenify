from pathlib import Path
import ctypes as C, ctypes.wintypes as W, json, os, subprocess, time
root=Path(__file__).resolve().parent.parent
work=root/'work'
zig=work/'compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(work/'compat-research/zig-cache'))
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-O1','-municode',str(work/'NonUiFixture.c'),'-luser32','-o',str(work/'NonUiFixture.exe')],check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
ps=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
ready=work/('nonui-proof-'+str(time.time_ns())+'.json')
p=subprocess.Popen([ps,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(work/'Test-NonUiProcess.ps1'),'-Report',str(ready)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
k=C.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4;k.GetProcessTimes.restype=W.BOOL
k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];k.GetExitCodeProcess.restype=W.BOOL
k.TerminateProcess.argtypes=[W.HANDLE,W.UINT];k.TerminateProcess.restype=W.BOOL
h=0;verified=False
try:
    stdout,stderr=p.communicate(timeout=10)
    assert p.returncode==0,(p.returncode,stderr)
    data=json.loads(ready.read_text(encoding='utf-8-sig'))
    h=k.OpenProcess(0x101001,False,data['Pid']);assert h,C.get_last_error()
    times=[W.FILETIME() for _ in range(4)];assert k.GetProcessTimes(h,*[C.byref(t) for t in times])
    birth=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
    assert str(birth)==data['Birth'];verified=True
    assert k.WaitForSingleObject(h,0)==258,'Fixture must outlive parent'
    assert k.WaitForSingleObject(h,5000)==0
    code=W.DWORD();assert k.GetExitCodeProcess(h,C.byref(code));assert code.value==0
    events=[json.loads(line) for line in Path(data['Out']).read_text(encoding='utf-8').splitlines()]
    identity=events[0]
    assert identity['pid']==data['Pid'] and identity['birth']==data['Birth']
    assert identity['args']==data['Args'],(identity['args'],data['Args'])
    assert identity['consoleWindow']=='0x0' and identity['ownTopLevelWindows']==0,identity
    assert identity['args'][-2]=='Русский',identity
    assert identity['stdoutType']==1 and identity['stderrType']==1,identity
    assert events[-1]['event']=='late-output-after-launcher-exit'
    assert Path(data['Err']).read_text().strip()=='late stderr after launcher exit'
    result={'ok':True,'identity':identity,'argvExact':True,'noConsoleWindow':True,'childOutlivedLauncher':True,'stdoutAndStderrPreservedAfterLauncherExit':True,'exitCode':code.value,'parentPid':p.pid}
    (root/'outputs/Windows10-Components/nonui-own-proof.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))
finally:
    if p.poll() is None:p.kill();p.communicate(timeout=5)
    if h:
        if verified and k.WaitForSingleObject(h,0)==258:k.TerminateProcess(h,1);k.WaitForSingleObject(h,3000)
        k.CloseHandle(h)
