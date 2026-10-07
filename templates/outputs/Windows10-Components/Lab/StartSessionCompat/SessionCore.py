"""Private shared mechanisms for Start session; generated from the audited Settings controller."""
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

def target_processes(state):
    class PE(C.Structure):
        _fields_=[('size',W.DWORD),('usage',W.DWORD),('pid',W.DWORD),('heap',C.c_size_t),('module',W.DWORD),('threads',W.DWORD),('parent',W.DWORD),('priority',W.LONG),('flags',W.DWORD),('name',W.WCHAR*260)]
    snap=api('CreateToolhelp32Snapshot',P,[W.DWORD,W.DWORD])(2,0)
    if snap==P(-1).value:raise C.WinError(C.get_last_error())
    result=[];entry=PE();entry.size=C.sizeof(entry)
    try:
        present=api('Process32FirstW',W.BOOL,[P,P])(snap,C.byref(entry))
        while present:
            if entry.name.casefold()==Path(state['NativePath']).name.casefold():
                h=open_process(0x101000,False,entry.pid)
                if h:
                    try:
                        i=identity(h)
                        if i and wait(h,0)==258 and i['Path'].casefold()==state['NativePath'].casefold() and i['Package']==state['PackageFullName']:result.append(dict(Pid=entry.pid,**i))
                    finally:close(h)
            present=api('Process32NextW',W.BOOL,[P,P])(snap,C.byref(entry))
    finally:close(snap)
    return result

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
    m=create_mutex(None,False,'Local\\StartSessionRestore_'+state['Nonce'])
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
