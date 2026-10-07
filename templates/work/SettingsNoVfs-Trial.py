from pathlib import Path
import sys,json,time,subprocess,ctypes as C
from ctypes import wintypes as W
root=Path(__file__).resolve().parents[1];base=root/'outputs/Windows10-Components';lab=base/'Lab/SettingsNoVfsSessionCompat';sys.path.insert(0,str(lab));import SessionController as S
state_path=Path((lab/'active-session.txt').read_text(encoding='utf-8-sig').strip());state=json.loads(state_path.read_text(encoding='utf-8-sig'));directory=state_path.parent
guard=subprocess.Popen([sys.executable,str(root/'work/SettingsNoVfs-TrialGuard.py'),str(state_path)],creationflags=subprocess.CREATE_NO_WINDOW)
result=dict(NoVFS=True,SystemFilesModified=False,State=str(state_path),Activations=[]);accepted=False
def activate(previous):
    if len(sys.argv)>1:
        uri=sys.argv[1]
        if uri not in ('ms-settings:taskbar','ms-settings:display','ms-settings:powersleep'):raise RuntimeError('Unsupported protocol trial URI')
        shell=C.WinDLL('shell32',use_last_error=True).ShellExecuteW;shell.restype=C.c_void_p;shell.argtypes=[C.c_void_p,W.LPCWSTR,W.LPCWSTR,W.LPCWSTR,W.LPCWSTR,C.c_int]
        code=shell(None,'open',uri,None,None,1)
        if not code or code<=32:raise RuntimeError('Protocol activation refused '+str(code))
        result['Protocol']=uri
    else:
        response=subprocess.run([str(base/'Lab/StartCompat/PackageDebugController.exe'),'activate',state['PackageFamilyName']+'!microsoft.windows.immersivecontrolpanel',''],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=15)
        if response.returncode:raise RuntimeError('Settings activation failed '+str(response.returncode))
    deadline=time.monotonic()+35;record=None
    while time.monotonic()<deadline:
        for f,pid,born in S.records(directory):
            if (pid,born) in previous:continue
            failure=f.with_suffix('.failure.json')
            if failure.exists():raise RuntimeError(failure.read_text())
            log=f.with_suffix('.log')
            if log.exists() and 'DETACH_OWNERSHIP_TRANSFER' in log.read_text():record=(f,pid,born);break
        if record:break
        time.sleep(.1)
    if not record:raise RuntimeError('Fresh Settings bootstrap absent')
    f,pid,born=record;h=S.open_process(0x101410,False,pid)
    if not h:raise RuntimeError('Settings exited before readback')
    try:
        actual=S.identity(h)
        if not actual or actual['Birth']!=born or actual['Package']!=state['PackageFullName'] or actual['Path'].casefold()!=state['NativePath'].casefold():raise RuntimeError('Settings identity differs')
        if S.wait(h,8000)!=258:
            code=W.DWORD();get=S.api('GetExitCodeProcess',W.BOOL,[C.c_void_p,C.POINTER(W.DWORD)]);get(h,C.byref(code));raise RuntimeError('Settings exited '+hex(code.value))
        ps=C.WinDLL('psapi',use_last_error=True);enum=ps.EnumProcessModulesEx;enum.restype=W.BOOL;enum.argtypes=[C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),W.DWORD];mapped=ps.GetMappedFileNameW;mapped.restype=W.DWORD;mapped.argtypes=[C.c_void_p,C.c_void_p,W.LPWSTR,W.DWORD]
        handles=(C.c_void_p*2048)();needed=W.DWORD();paths=[]
        if not enum(h,handles,C.sizeof(handles),C.byref(needed),3) or needed.value>C.sizeof(handles):raise RuntimeError('Settings module census failed')
        for module in handles[:needed.value//C.sizeof(C.c_void_p)]:
            name=C.create_unicode_buffer(4096)
            if mapped(h,module,name,len(name)):paths.append(name.value)
        (directory/('root-modules-'+str(pid)+'.json')).write_text(json.dumps(paths,indent=2),encoding='utf-8')
        if state.get('DiagnosticOnly') or state.get('XamlFactory'):
            reader=base/'Lab/SettingsNoVfsDiagnostics/Read-Diagnostic.py'
            read=subprocess.run([sys.executable,str(reader),'--state',str(state_path),'--pid',str(pid),'--birth',str(born)],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=15)
            (directory/('root-diagnostic-reader-'+str(pid)+'.txt')).write_bytes(read.stdout+read.stderr)
            if read.returncode:raise RuntimeError('Diagnostic readback failed '+str(read.returncode))
        if any('usvfs' in p.casefold() for p in paths):raise RuntimeError('Unexpected VFS module')
        for name in ('systemsettings.dll','systemsettingsviewmodel.desktop.dll'):
            matching=[p for p in paths if p.casefold().endswith('\\'+name)]
            if len(matching)!=1 or '\\image\\4\\windows\\immersivecontrolpanel\\' not in matching[0].casefold():raise RuntimeError('Old Settings image not unique '+name)
        report=dict(Pid=pid,Birth=born,AliveAfterSeconds=8,Modules=paths,Bootstrap=f.with_suffix('.log').read_text(),VisualUIConfirmed=False)
        result['Activations'].append(report);return pid,born
    finally:S.close(h)
try:
    first=activate(set())
    outcome=S.exact_stop(first[0],first[1],state)
    if outcome!='StoppedExact':raise RuntimeError('Repeat-open cleanup refused '+outcome)
    second=activate({first});result['Status']='canonical-repeat-open-runtime-pass';result['ActiveSettings']=dict(Pid=second[0],Birth=second[1]);result['VisualUIConfirmed']=False
    (directory/'root-accepted').touch();accepted=True
except Exception as error:
    result.update(Status='trial-failed',Error=str(error));(directory/'root-stop').touch()
finally:
    guard.wait(timeout=35);result['AcceptedUntilStop']=accepted;result['Guard']=(directory/'root-trial-guard.json').read_text() if (directory/'root-trial-guard.json').exists() else None
    (directory/'root-trial-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k!='Activations'},indent=2))
