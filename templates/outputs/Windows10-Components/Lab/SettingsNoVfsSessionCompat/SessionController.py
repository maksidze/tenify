"""Staged native SEH UntilStop debugger. No package activation is performed here."""
import argparse, ctypes as C, hashlib, json, os, struct, subprocess, sys, time, uuid, winreg
from ctypes import wintypes as W
from pathlib import Path

LAB=Path(__file__).resolve().parent
BASE=LAB.parent.parent
K=C.WinDLL('kernel32',use_last_error=True)
def api(name,result,args):
    f=getattr(K,name);f.restype=result;f.argtypes=args;return f
P=C.c_void_p
open_process=api('OpenProcess',P,[W.DWORD,W.BOOL,W.DWORD])
close=api('CloseHandle',W.BOOL,[P])
wait=api('WaitForSingleObject',W.DWORD,[P,W.DWORD])
terminate=api('TerminateProcess',W.BOOL,[P,W.UINT])
times=api('GetProcessTimes',W.BOOL,[P,P,P,P,P])
query=api('QueryFullProcessImageNameW',W.BOOL,[P,W.DWORD,W.LPWSTR,P])
package=api('GetPackageFullName',W.LONG,[P,P,W.LPWSTR])
tick=api('GetTickCount64',C.c_ulonglong,[])
create_mutex=api('CreateMutexW',P,[P,W.BOOL,W.LPCWSTR])
release=api('ReleaseMutex',W.BOOL,[P])

def identity(h):
    born,exit,kernel,user=(C.c_ulonglong() for _ in range(4))
    path=C.create_unicode_buffer(32768);n=W.DWORD(len(path));pkg=C.create_unicode_buffer(4096);pn=W.UINT(len(pkg))
    if not times(h,C.byref(born),C.byref(exit),C.byref(kernel),C.byref(user)) or not query(h,0,path,C.byref(n)):return None
    return dict(Birth=born.value,Path=path.value,Package=pkg.value if package(h,C.byref(pn),pkg)==0 else '')

def exact_stop(pid,birth,state):
    h=open_process(0x101001,False,pid)
    if not h:return 'Absent' if C.get_last_error()==87 else 'OpenRefused'
    try:
        if wait(h,0)==0:return 'Exited'
        i=identity(h)
        if not i or i['Birth']!=birth or i['Path'].casefold()!=state['NativePath'].casefold() or i['Package']!=state['PackageFullName']:return 'IdentityMismatchRefused'
        if not terminate(h,0xdeca):return 'StopFailed'
        return 'StoppedExact' if wait(h,5000)==0 else 'StopTimeout'
    finally:close(h)

def dump(path,value):
    p=Path(path);tmp=p.with_name(p.name+'.tmp-'+str(os.getpid()))
    tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(tmp,p)

def regtree(path):
    try:k=winreg.OpenKey(winreg.HKEY_CURRENT_USER,path)
    except FileNotFoundError:return None
    with k:
        values={};subs={};i=0
        while True:
            try:n,v,t=winreg.EnumValue(k,i);values[n]=[t,v.hex() if isinstance(v,bytes) else v];i+=1
            except OSError:break
        i=0
        while True:
            try:n=winreg.EnumKey(k,i);subs[n]=regtree(path+'\\'+n);i+=1
            except OSError:break
    return dict(Values=values,Children=subs)

def debug_snapshot(state):
    p=state['PackageFullName']
    return [regtree('Software\\Classes\\ActivatableClasses\\Package\\'+p+'\\DebugInformation'),regtree('Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\'+p)]

def registration_owned(snapshot,command):
    # Exact scalar command only; substring/PID/name matches must not authorize restore.
    def contains(x):
        if isinstance(x,dict):return any(contains(v) for v in x.values())
        if isinstance(x,list):return any(contains(v) for v in x)
        return isinstance(x,str) and x==command
    return contains(snapshot)

def control(state,mode):
    log=Path(state['Directory'])/(mode+'-'+uuid.uuid4().hex+'.log')
    cmd=[str(LAB/'SessionControl.exe'),mode,state['PackageFullName'],state['DebuggerCommand'] if mode=='enable' else '',str(log)]
    # Assign a suspended control to an anonymous kill-on-close Job BEFORE it can
    # touch package registration. Supervisor death cannot leave a late enabling
    # controller behind; the independent guard reads registration after it dies.
    class SI(C.Structure):
        _fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('cbReserved',W.WORD),('bytes',P),('input',P),('output',P),('error',P)]
    class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',W.DWORD),('tid',W.DWORD)]
    job=api('CreateJobObjectW',P,[P,W.LPCWSTR])(None,None)
    pi=PI();si=SI();si.cb=C.sizeof(si);limits=C.create_string_buffer(144)
    C.cast(C.byref(limits,16),C.POINTER(W.DWORD))[0]=0x2000 # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    try:
        if not job or not api('SetInformationJobObject',W.BOOL,[P,C.c_int,P,W.DWORD])(job,9,limits,len(limits)):raise C.WinError(C.get_last_error())
        command=C.create_unicode_buffer(subprocess.list2cmdline(cmd))
        if not api('CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,P,P])(cmd[0],command,None,None,False,0x08000004,None,str(LAB),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
        if not api('AssignProcessToJobObject',W.BOOL,[P,P])(job,pi.process):raise C.WinError(C.get_last_error())
        dump(Path(state['Directory'])/'control-pending.json',dict(Pid=pi.pid,**identity(pi.process)))
        if api('ResumeThread',W.DWORD,[P])(pi.thread)==0xffffffff:raise C.WinError(C.get_last_error())
        if wait(pi.process,10000)!=0:raise TimeoutError('Package control exceeded its bounded operation')
        code=W.DWORD()
        if not api('GetExitCodeProcess',W.BOOL,[P,P])(pi.process,C.byref(code)):raise C.WinError(C.get_last_error())
        if code.value:raise RuntimeError(f'{mode} failed ({code.value}): {log.read_text(errors="replace") if log.exists() else "no log"}')
    finally:
        if pi.process and wait(pi.process,0)!=0:terminate(pi.process,0xdeca);wait(pi.process,5000)
        if pi.thread:close(pi.thread)
        if pi.process:close(pi.process)
        if job:close(job)
        (Path(state['Directory'])/'control-pending.json').unlink(missing_ok=True)

def records(directory):
    result=[]
    for p in Path(directory).glob('a_*.record'):
        b=p.read_bytes()
        if len(b)!=16 or struct.unpack('<I',b[:4])[0]!=0x53534c31:raise RuntimeError('Invalid activation ownership record '+str(p))
        _,pid,birth=struct.unpack('<IIQ',b);result.append((p,pid,birth))
    return result

def restore(state):
    directory=Path(state['Directory']);Path(state['CancelFile']).touch(exist_ok=True)
    m=create_mutex(None,False,'Local\\SettingsSessionRestore_'+state['Nonce'])
    acquired=wait(m,20000) in (0,0x80)
    if not acquired:close(m);raise RuntimeError('Restore mutex timeout')
    try:
        if (directory/'restored.json').exists():return
        # If supervisor died during EnableDebugging, stop only its exact recorded control first.
        pending=directory/'control-pending.json'
        if pending.exists():
            q=json.loads(pending.read_text());h=open_process(0x101001,False,q['Pid'])
            if h:
                try:
                    i=identity(h)
                    if i and i['Birth']==q['Birth'] and i['Path'].casefold()==str(LAB/'SessionControl.exe').casefold():terminate(h,0xdeca);wait(h,5000)
                finally:close(h)
        snapshot=debug_snapshot(state);saved=directory/'registered.json';owned=registration_owned(snapshot,state['DebuggerCommand'])
        if saved.exists():owned=owned and snapshot==json.loads(saved.read_text())
        status='Absent' if snapshot==[None,None] else 'ForeignRegistrationRefused'
        if owned:control(state,'disable');status='DisabledOwned'
        # Cancel is durable BEFORE unregistering. Late callbacks can only stop an exact
        # target or publish a record then observe Cancel. A stable interval catches records
        # that were published after an earlier scan; never stop by process name.
        stopped={};stable=0;previous=None;deadline=time.monotonic()+8
        while time.monotonic()<deadline and stable<20:
            current=records(directory)
            signature=[(str(p),pid,born) for p,pid,born in current]
            stable=stable+1 if signature==previous else 0;previous=signature
            for p,pid,born in current:
                outcome=exact_stop(pid,born,state)
                if stopped.get(str(p))!='StoppedExact':stopped[str(p)]=outcome
            time.sleep(.1)
        if any(v in ('OpenRefused','StopFailed','StopTimeout') for v in stopped.values()):raise RuntimeError('Exact process cleanup incomplete')
        if status=='ForeignRegistrationRefused':raise RuntimeError('Registration changed; foreign configuration preserved, owned processes cancelled')
        if debug_snapshot(state)!=[None,None]:raise RuntimeError('Owned debugger key remains after DisableDebugging')
        dump(directory/'restored.json',dict(Debugger=status,Records=stopped,Complete=True))
    finally:
        release(m);close(m)

def preflight(state):
    expected=Path('C:/Windows/ImmersiveControlPanel/SystemSettings.exe')
    if Path(state['NativePath']).resolve()!=expected:raise RuntimeError('Native Settings path differs')
    if state['Seconds']!=90:raise RuntimeError('Bootstrap bound invalid')
    if len(state['DebuggerCommand'])>=260:raise RuntimeError('Debugger command exceeds verified limit')
    for item in state['Files']:
        if hashlib.sha256(Path(item['Path']).read_bytes()).hexdigest()!=item['SHA256']:raise RuntimeError('Runtime hash differs '+item['Path'])
    if debug_snapshot(state)!=[None,None]:raise RuntimeError('Existing package debugger preserved')
    if not state.get('RuntimeAclVerified',False):raise RuntimeError('Private package RX ACL not yet verified; live candidate refused')
    proof=json.loads((LAB/'own-package-access-proof.json').read_text())
    if not proof.get('Passed'):raise RuntimeError('Own actual AppContainer DLL+NT identity proof required')
    key='SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SystemSettings.exe'
    try:ifeo=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,key)
    except FileNotFoundError:ifeo=None
    if ifeo:
        with ifeo:
            if winreg.QueryInfoKey(ifeo)[:2]!=(0,1) or winreg.EnumValue(ifeo,0)!=('MitigationOptions',4294967296,winreg.REG_QWORD):raise RuntimeError('IFEO differs from verified native mitigation-only policy')

class Entry(C.Structure):
    _fields_=[('size',W.DWORD),('usage',W.DWORD),('pid',W.DWORD),('heap',C.c_size_t),('module',W.DWORD),('threads',W.DWORD),('parent',W.DWORD),('priority',W.LONG),('flags',W.DWORD),('exe',W.WCHAR*260)]

def census(state):
    snap=api('CreateToolhelp32Snapshot',P,[W.DWORD,W.DWORD])(2,0)
    if snap in (None,C.c_void_p(-1).value):raise C.WinError(C.get_last_error())
    result=[];e=Entry();e.size=C.sizeof(e)
    first=api('Process32FirstW',W.BOOL,[P,P]);nxt=api('Process32NextW',W.BOOL,[P,P])
    try:
        okay=first(snap,C.byref(e))
        while okay:
            h=open_process(0x1000,False,e.pid)
            if h:
                try:
                    i=identity(h)
                    if i and i['Package']==state['PackageFullName']:result.append(dict(Pid=e.pid,**i))
                finally:close(h)
            okay=nxt(snap,C.byref(e))
    finally:close(snap)
    return result


_pending_bootstrap_seen={}
def monitor_bootstraps(state):
    # Backend watchdog exits only after verified detach. A helper crash before
    # its watchdog starts must not leave a suspended target indefinitely.
    now=tick()
    for record,pid,birth in records(state['Directory']):
        key=str(record);_pending_bootstrap_seen.setdefault(key,now)
        log=record.with_suffix('.log')
        try:transferred='DETACH_OWNERSHIP_TRANSFER' in log.read_text(encoding='utf-8',errors='replace')
        except FileNotFoundError:transferred=False
        if not transferred and now-_pending_bootstrap_seen[key]>=90000:
            outcome=exact_stop(pid,birth,state)
            dump(record.with_suffix('.bootstrap-expired.json'),dict(Pid=pid,Birth=birth,Outcome=outcome))

def refresh_lease(state):
    # New file + atomic replace: readers observe an entire generation or the old one.
    p=Path(state['LeaseFile']);tmp=p.with_name(p.name+'.pending-'+str(os.getpid()))
    with tmp.open('wb') as f:
        f.write(struct.pack('<QQ',tick()+20000,state['Controller']['Birth']));f.flush();os.fsync(f.fileno())
    from LeaseIO import replace_lease
    replace_lease(tmp,p)

def lease_active(state):
    try:
        from LeaseIO import read_lease
        b=read_lease(state['LeaseFile'])
        if len(b)!=16:return False
        deadline,birth=struct.unpack('<QQ',b);now=tick()
        return birth==state['Controller']['Birth'] and now<deadline<=now+20000
    except OSError:return False

def guard(state):
    directory=Path(state['Directory']);owner=state['Controller']
    h=open_process(0x100000|0x1000,False,owner['Pid']);i=identity(h) if h else None
    if not i or i['Birth']!=owner['Birth']:
        if h:close(h)
        raise RuntimeError('Controller identity changed before guard ready')
    shell=None
    dump(directory/'guard-ready.json',dict(Pid=os.getpid()))
    manual=None
    try:
        while wait(h,200)==258 and (not shell or wait(shell,0)==258) and lease_active(state) and not Path(state['CancelFile']).exists():monitor_bootstraps(state)
        while True:
            # Take over the abandoned lifetime lock on supervisor death. While it
            # lives, it retains the lifetime lock until our cleanup is terminal.
            if wait(h,0)==0 and manual is None:
                manual=create_mutex(None,False,'Local\\Settings10ManualLauncher')
                if wait(manual,20000) not in (0,0x80):raise RuntimeError('Unable to retain common cleanup lifetime lock')
            try:restore(state);break
            except Exception as e:dump(directory/'cleanup-pending.json',dict(Error=str(e),GuardPid=os.getpid()));time.sleep(1)
    finally:
        if shell:close(shell)
        if manual:release(manual);close(manual)
        close(h)

def enable_registration(state):
    """Serialize the entire irreversible activation gate with restore."""
    directory=Path(state['Directory'])
    gate=create_mutex(None,False,'Local\\SettingsSessionRestore_'+state['Nonce'])
    gate_owned=wait(gate,20000) in (0,0x80)
    try:
        if not gate_owned:raise RuntimeError('Enable/restore gate timeout')
        if Path(state['CancelFile']).exists() or not lease_active(state) or (directory/'restored.json').exists():raise RuntimeError('Cancelled/expired before registration under gate')
        if debug_snapshot(state)!=[None,None]:raise RuntimeError('Debugger appeared before registration; no overwrite')
        control(state,'enable');snapshot=debug_snapshot(state)
        if not registration_owned(snapshot,state['DebuggerCommand']):raise RuntimeError('Registration ownership readback failed')
        dump(directory/'registered.json',snapshot)
        if Path(state['CancelFile']).exists() or not lease_active(state):raise RuntimeError('Cancelled during registration; restore follows')
        dump(directory/'enabled.json',dict(Mode='UntilStop',ModeUntilStop=True,NoVFS=True,ContentCompat=True,NavigationCompat=True,BootstrapSeconds=90,LeaseSeconds=20,OpensRepeatable=True,ActivationPerformed=False))
    finally:
        if gate_owned:release(gate)
        close(gate)

def session_active(state):
    return lease_active(state) and not Path(state['CancelFile']).exists()

def begin(state):
    directory=Path(state['Directory']);m=create_mutex(None,False,'Local\\Settings10ManualLauncher')
    acquired=wait(m,0) in (0,0x80)
    if not acquired:close(m);raise RuntimeError('Another manual/persistent Settings NoVFS controller is active')
    g=None;session_end=None;shell=None
    try:
        recover_stale();preflight(state)
        conflicts=census(state)
        if conflicts:raise RuntimeError('Settings NoVFS package already in use: '+json.dumps(conflicts))
        state['DeadlineTick']=tick()+20000;state['LeaseFile']=str(directory/'lease.bin');state['Mode']='UntilStop';state['ModeUntilStop']=True
        own=open_process(0x1000,False,os.getpid())
        try:state['Controller']=dict(Pid=os.getpid(),**identity(own))
        finally:close(own)
        refresh_lease(state);dump(directory/'state.json',state)
        pointer=LAB/'active-session.txt';temporary=LAB/'active-session.pending';temporary.write_text(str(directory/'state.json'),encoding='utf-8');os.replace(temporary,pointer)
        fields={'State':str(directory/'state.json'),'Python':sys.executable,'Callback':str(LAB/'Callback.py')}
        config=LAB/state['ConfigName']
        with config.open('x',encoding='utf-16',newline='') as f:f.write('[Session]\r\n'+''.join(k+'='+v+'\r\n' for k,v in fields.items()))
        output=(directory/'guard.log').open('w')
        g=subprocess.Popen([sys.executable,str(Path(__file__)), 'guard',str(directory/'state.json')],creationflags=subprocess.CREATE_NO_WINDOW,stdout=output,stderr=subprocess.STDOUT);output.close()
        ready=time.monotonic()+10
        while not (directory/'guard-ready.json').exists():
            if g.poll() is not None or time.monotonic()>ready:raise RuntimeError('Independent guard not ready')
            time.sleep(.05)
        session_end=SessionEndObserver(state['CancelFile'],directory/'restored.json');enable_registration(state)
        while session_active(state):
            if g.poll() is not None:raise RuntimeError('Independent guard exited during session')
            monitor_bootstraps(state);refresh_lease(state);time.sleep(.2)
    finally:
        try:
            if 'Controller' in state:
                while True:
                    try:restore(state);break
                    except Exception as e:
                        dump(directory/'cleanup-pending.json',dict(Error=str(e),ControllerPid=os.getpid()))
                        # Fail closed: retain registration ownership and the manual lifetime mutex.
                        # Independent guard retries too; no other Settings NoVFS session
                        # may start while exact cleanup remains unresolved.
                        time.sleep(1)
        finally:
            if g:
                g.wait() # Terminal restore exists; guard must finish before unlock.
            if session_end:session_end.close()
            if shell:close(shell)
            release(m);close(m)

from SessionEndObserver import SessionEndObserver
from ScopedRecovery import recover_previous
def recover_stale():
    manifest=json.loads((LAB/'manifest.json').read_text(encoding='utf-8-sig'))
    for item in manifest['Files']:
        if hashlib.sha256(Path(item['Path']).read_bytes()).hexdigest()!=item['SHA256']:raise RuntimeError('Recovery runtime hash differs: '+item['Path'])
    return recover_previous(sys.modules[__name__],LAB,Path('C:/Windows/ImmersiveControlPanel/SystemSettings.exe'))

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['begin','guard','restore','preflight','recover-stale']);p.add_argument('state');a=p.parse_args()
    state=json.loads(Path(a.state).read_text(encoding='utf-8-sig'))
    if a.mode=='recover-stale':print(json.dumps(recover_stale()));return
    if a.mode=='preflight':recover_stale();preflight(state);print(json.dumps(dict(Preflight=True,Conflicts=census(state),ActivationPerformed=False)))
    else:globals()[a.mode](state)
if __name__=='__main__':main()
