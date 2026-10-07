"""Repeatable Start10 broker session; UntilStop is owner/cancel lifetime, not a huge timeout.
No action occurs on import. All ordinary package-control operations remain bounded.
"""
import argparse, ctypes as C, hashlib, json, os, subprocess, sys, time
from pathlib import Path
import SessionCore as S

LAB=Path(__file__).resolve().parent
BASE=LAB.parent.parent
SESSION_MUTEX='Local\\StartMenu10Session'
U=C.WinDLL('user32',use_last_error=True)
U.GetShellWindow.restype=S.P
U.GetWindowThreadProcessId.argtypes=[S.P,C.POINTER(S.W.DWORD)]

def owner_pid():
    pid=S.W.DWORD();U.GetWindowThreadProcessId(U.GetShellWindow(),C.byref(pid));return pid.value

def exact_handle(identity,access=0x101000):
    h=S.open_process(access,False,identity['Pid'])
    if not h:return None
    now=S.identity(h)
    if not now or now['Birth']!=identity['Birth'] or now['Path'].casefold()!=identity['Path'].casefold():S.close(h);return None
    return h

def shell_live(state,h):
    return bool(h and S.wait(h,0)==258 and owner_pid()==state['Explorer']['Pid'])

def active(state):
    return not Path(state['CancelFile']).exists() and (state['UntilStop'] or S.tick()<state['DeadlineTick'])

def preflight(state):
    native=Path(state['NativePath'])
    if native.name!='StartMenuExperienceHost.exe' or native.parent.parent!=Path(os.environ['WINDIR'])/'SystemApps':raise RuntimeError('Unexpected native Start path')
    if not state['PackageFullName'].startswith('Microsoft.Windows.StartMenuExperienceHost_'):raise RuntimeError('Unexpected package identity')
    if state['PackageFamily']!='Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy':raise RuntimeError('Unexpected package family')
    if state['Proxy'].casefold()!=str(BASE/'Lab/StartCompat/wincorlib.dll').casefold():raise RuntimeError('Unexpected Start proxy path')
    if len(state['DebuggerCommand'])>=260:raise RuntimeError('Debugger command exceeds verified package API limit')
    if not 5<=state['Seconds']<=3600:raise RuntimeError('Invalid bounded duration')
    if len(state['Nonce'])!=32 or any(c not in '0123456789abcdef' for c in state['Nonce']):raise RuntimeError('Invalid nonce')
    if Path(state['Directory']).resolve()!=LAB/'sessions'/state['Nonce']:raise RuntimeError('Session directory escaped owned scope')
    if Path(state['CancelFile']).resolve()!=Path(state['Directory'])/'cancel':raise RuntimeError('Invalid cancellation path')
    if state['ConfigName']!='s_'+state['Nonce']+'.ini':raise RuntimeError('Invalid config name')
    if state['DebuggerCommand']!=str(LAB/'Start10SessionDebugger.exe')+' --session '+state['ConfigName']:raise RuntimeError('Unexpected debugger command')
    if not state['ServerArgument'].startswith('-ServerName:'):raise RuntimeError('Missing observed server argument')
    if any(c in state['ServerArgument'] for c in '\r\n\t '):raise RuntimeError('Malformed observed server argument')
    for item in state['Files']:
        if hashlib.sha256(Path(item['Path']).read_bytes()).hexdigest()!=item['SHA256']:raise RuntimeError('Hash changed: '+item['Path'])
    if S.debug_snapshot(state)!=[None,None]:raise RuntimeError('Existing package debugger; refuse overwrite')
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe'):raise RuntimeError('Pre-existing Start IFEO; refuse change')
    except FileNotFoundError:pass
    h=exact_handle(state['Explorer'])
    try:
        if not shell_live(state,h):raise RuntimeError('Expected Explorer no longer owns the shell')
    finally:
        if h:S.close(h)

def activate(state,native=False):
    # Uses the unchanged genuine activation helper; it cannot alter debug settings
    # in its activate mode. A separate recorded process handle bounds its wait.
    tool=BASE/'Lab/StartCompat/PackageDebugController.exe'
    directory=Path(state['Directory'])
    with (directory/'activate.log').open('ab') as output:
        args=[str(tool),'activate',state['PackageFamily']+'!App']
        if not native:args.append('Windows.Internal.ShellExperience.StartMenu')
        child=subprocess.Popen(args,creationflags=subprocess.CREATE_NO_WINDOW,stdout=output,stderr=subprocess.STDOUT)
    try:
        try:code=child.wait(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5);raise RuntimeError('Start activation timed out')
        if code:raise RuntimeError('Start activation failed; see activate.log')
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=5)

def enable_registration(state):
    directory=Path(state['Directory'])
    gate=S.create_mutex(None,False,'Local\\StartSessionRestore_'+state['Nonce'])
    held=S.wait(gate,20000) in (0,0x80)
    try:
        if not held:raise RuntimeError('Enable/restore gate timeout')
        if not active(state) or (directory/'restored.json').exists():raise RuntimeError('Cancelled before registration')
        if S.debug_snapshot(state)!=[None,None]:raise RuntimeError('Debugger appeared before registration')
        S.control(state,'enable');snapshot=S.debug_snapshot(state)
        if not S.registration_owned(snapshot,state['DebuggerCommand']):raise RuntimeError('Registration ownership readback failed')
        S.dump(directory/'registered.json',snapshot)
        if not active(state):raise RuntimeError('Cancelled during registration')
        S.dump(directory/'enabled.json',dict(UntilStop=state['UntilStop'],Seconds=state['Seconds'],RepeatableCallbacks=True))
    finally:
        if held:S.release(gate)
        S.close(gate)

def cleanup(state):
    # Core restore takes the same gate and disables only this exact registered
    # debugger command/snapshot, then consumes exact PID+birth ownership records.
    S.restore(state)

def cleanup_bounded(state):
    failures=[]
    for attempt in range(3):
        try:cleanup(state);return
        except Exception as e:
            failures.append(str(e));S.dump(Path(state['Directory'])/'cleanup-pending.json',dict(Errors=failures,Pid=os.getpid()))
            if 'foreign' in str(e).casefold() or 'changed' in str(e).casefold():raise
            time.sleep(.5)
    raise RuntimeError('Bounded cleanup failed: '+repr(failures))

def restore_native_if_appropriate(state,shell):
    directory=Path(state['Directory'])
    if not shell_live(state,shell) or not (directory/'restored.json').exists():return
    if 'session-end' in Path(state['CancelFile']).read_text(errors='replace'):return
    # Gate avoids two racing restores activating duplicate native instances.
    marker=directory/'native-restore-requested'
    try:marker.touch(exist_ok=False)
    except FileExistsError:return
    try:
        before=S.target_processes(state)
        if not before:activate(state,native=True)
        S.dump(directory/'native-restore.json',dict(ActivationRequested=not bool(before),Present=S.target_processes(state)))
    except Exception as e:S.dump(directory/'native-restore.json',dict(Error=str(e)))

def owned_instances(state):
    result=[]
    for record,pid,birth in S.records(state['Directory']):
        h=exact_handle(dict(Pid=pid,Birth=birth,Path=state['NativePath']))
        if not h:continue
        try:
            if S.wait(h,0)!=258:continue
            info=S.identity(h)
            if info['Package']!=state['PackageFullName']:raise RuntimeError('Recorded process package changed')
            ready=Path(str(record.with_suffix('.log'))+'.ready').exists()
            result.append(dict(Pid=pid,Birth=birth,Ready=ready,Record=str(record)))
        finally:S.close(h)
    return result

class RecoveryPolicy:
    """No time-based restart of a healthy instance. At most3 retries/60seconds."""
    def __init__(self,now):self.last=now;self.attempts=[]
    def needed(self,now,alive):
        if alive:return False
        if now-self.last<8:return False
        self.attempts=[x for x in self.attempts if now-x<60]
        if len(self.attempts)>=3:raise RuntimeError('Repeated Start startup/crash failures; native fallback required')
        self.attempts.append(now);self.last=now;return True

def guard(state):
    directory=Path(state['Directory']);h=exact_handle(state['Controller']);shell=exact_handle(state['Explorer'])
    if not h or not shell:
        if h:S.close(h)
        if shell:S.close(shell)
        raise RuntimeError('Owner identity unavailable before guard readiness')
    S.dump(directory/'guard-ready.json',dict(Pid=os.getpid(),OwnerVerified=True,ShellVerified=True))
    held=False;m=None
    try:
        while S.wait(h,200)==258 and active(state) and shell_live(state,shell):pass
        Path(state['CancelFile']).touch(exist_ok=True)
        while True:
            if S.wait(h,0)==0 and not held:
                m=S.create_mutex(None,False,SESSION_MUTEX)
                held=S.wait(m,20000) in (0,0x80)
                if not held:raise RuntimeError('Unable to take abandoned session lock')
            cleanup_bounded(state);restore_native_if_appropriate(state,shell);break
    finally:
        if m:
            if held:S.release(m)
            S.close(m)
        S.close(shell);S.close(h)

def begin(state):
    directory=Path(state['Directory']);m=S.create_mutex(None,False,SESSION_MUTEX);held=S.wait(m,0) in (0,0x80)
    if not held:S.close(m);raise RuntimeError('Another Start session owns the lifetime lock')
    g=None;shell=None;observer=None
    try:
        preflight(state);shell=exact_handle(state['Explorer']);state['NativeBaselines']=S.target_processes(state)
        from SessionEndObserver import SessionEndObserver
        observer=SessionEndObserver(state['CancelFile'],directory/'restored.json')
        state['DeadlineTick']=0 if state['UntilStop'] else S.tick()+state['Seconds']*1000
        own=S.open_process(0x1000,False,os.getpid())
        try:state['Controller']=dict(Pid=os.getpid(),**S.identity(own))
        finally:S.close(own)
        S.dump(directory/'state.json',state)
        (LAB/'active-session.txt').write_text(str(directory/'state.json'),encoding='utf-8')
        owner=state['Controller']
        fields=dict(Target=state['NativePath'],PackageFullName=state['PackageFullName'],Directory=str(directory),CancelFile=state['CancelFile'],Proxy=state['Proxy'],OwnerPid=str(owner['Pid']),OwnerBirth=str(owner['Birth']),OwnerPath=owner['Path'],DeadlineTick=str(state['DeadlineTick']),UntilStop=str(int(state['UntilStop'])),ServerArgument=state['ServerArgument'])
        config=LAB/state['ConfigName']
        with config.open('x',encoding='utf-16',newline='') as f:f.write('[Session]\r\n'+''.join(k+'='+v+'\r\n' for k,v in fields.items()))
        with (directory/'guard.log').open('w') as output:g=subprocess.Popen([sys.executable,str(Path(__file__)),'guard',str(directory/'state.json')],creationflags=subprocess.CREATE_NO_WINDOW,stdout=output,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+10
        while not (directory/'guard-ready.json').exists():
            if g.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Independent guard did not become ready')
            time.sleep(.05)
        if not shell_live(state,shell):raise RuntimeError('Explorer changed before enable')
        enable_registration(state)
        for baseline in state['NativeBaselines']:
            if not active(state):raise RuntimeError('Cancelled before initial activation')
            outcome=S.exact_stop(baseline['Pid'],baseline['Birth'],state)
            if outcome not in ('Absent','Exited','StoppedExact'):raise RuntimeError('Baseline changed; no replacement process stopped: '+outcome)
        if not active(state):raise RuntimeError('Cancelled before initial activation')
        activate(state)
        initialDeadline=time.monotonic()+35;policy=RecoveryPolicy(time.monotonic());announced=False
        # Closed/crashed Start instances do not end the session. A new broker
        # activation creates a new exact-birth record and bootstrap without VFS.
        while active(state) and shell_live(state,shell):
            if g.poll() is not None:raise RuntimeError('Independent guard exited unexpectedly')
            instances=owned_instances(state);ready=[i for i in instances if i['Ready']]
            if ready and not announced:
                S.dump(directory/'running.json',dict(UntilStop=state['UntilStop'],BootstrapReady=True,Instances=ready,VisibleUIConfirmed=False));announced=True
            if not announced and time.monotonic()>initialDeadline:raise RuntimeError('Initial Start bootstrap deadline exceeded')
            if not instances:
                if S.target_processes(state):raise RuntimeError('Unclaimed native Start appeared; preserve it and stop session')
                if policy.needed(time.monotonic(),False):
                    if not active(state) or not shell_live(state,shell):break
                    S.dump(directory/'recovery.json',dict(Attempts=policy.attempts,Reason='No live owned Start; genuine broker activation'))
                    activate(state)
            else:policy.needed(time.monotonic(),True)
            S.dump(directory/'status.json',dict(Tick=S.tick(),Instances=instances,UntilStop=state['UntilStop'],AutomaticRecoveryAttempts=len(policy.attempts)))
            time.sleep(.2)
    finally:
        try:
            if 'Controller' in state:
                Path(state['CancelFile']).touch(exist_ok=True)
                cleanup_bounded(state);restore_native_if_appropriate(state,shell)
        finally:
            if g:
                try:g.wait(timeout=45)
                except subprocess.TimeoutExpired:S.dump(directory/'guard-pending.json',dict(Pid=g.pid,Reason='Independent cleanup still pending; preserved'))
            if observer:observer.close()
            if shell:S.close(shell)
            S.release(m);S.close(m)

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['begin','guard','restore','preflight']);p.add_argument('state');a=p.parse_args()
    state=json.loads(Path(a.state).read_text(encoding='utf-8-sig'))
    if a.mode=='preflight':preflight(state);print(json.dumps(dict(Preflight=True,PackageDebuggingChanged=False,ActivationPerformed=False)))
    elif a.mode=='restore':Path(state['CancelFile']).touch(exist_ok=True);cleanup_bounded(state)
    else:globals()[a.mode](state)
if __name__=='__main__':main()
