"""Root-owned bounded trial. Restores registration after 90s; no UI automation."""
from pathlib import Path
import ctypes as C,hashlib,json,subprocess,sys,time
R=Path(__file__).resolve().parent.parent
L=R/'outputs/Windows10-Components/Lab/ShellAppearanceCompat'
sys.path.insert(0,str(L))
import SessionController as S
read=lambda p:json.loads(Path(p).read_text(encoding='utf-8-sig'))
def watchdog(prepared):
    state=read(prepared);directory=Path(state['Directory'])
    (directory/'root-watchdog-ready').touch()
    end=time.monotonic()+90
    while time.monotonic()<end and not (directory/'root-stop').exists():time.sleep(.2)
    Path(state['CancelFile']).touch()
    actual=directory/'state.json'
    if actual.exists():
        for attempt in range(12):
            try:S.restore(read(actual));break
            except Exception as e:
                S.dump(directory/'root-restore-error.json',dict(Error=str(e),Attempt=attempt));time.sleep(1)
        else:raise RuntimeError('Root trial restoration did not complete')
    S.dump(directory/'root-trial-ended.json',dict(Bounded=True,Registration=S.debug_snapshot(state)))
def start(prepared):
    state=read(prepared);directory=Path(state['Directory'])
    S.preflight(state)
    baseline=S.census(state)
    for item in baseline:
        if item['Path'].casefold() not in {state['NativePath'].casefold(),'c:\\windows\\system32\\runtimebroker.exe'}:raise RuntimeError('Unexpected package process; no restart')
    with (directory/'root-watchdog.log').open('wb') as log:
        guard=subprocess.Popen([sys.executable,__file__,'watchdog',str(prepared)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while not (directory/'root-watchdog-ready').exists():
        if guard.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Root watchdog not ready')
        time.sleep(.05)
    stopped=[]
    try:
        for item in baseline:
            # Exact captured handle, birth/path/package checked by same helper.
            scoped=dict(state,NativePath=item['Path'])
            result=S.exact_stop(item['Pid'],item['Birth'],scoped)
            stopped.append(dict(**item,Outcome=result))
            if result not in ('StoppedExact','Exited','Absent'):raise RuntimeError('Baseline restart refused '+result)
        S.dump(directory/'root-baseline.json',stopped)
        with (directory/'controller.log').open('wb') as log:
            controller=subprocess.Popen([sys.executable,str(L/'SessionController.py'),'begin',str(prepared)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=log,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+15
        while not (directory/'enabled.json').exists():
            if controller.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Candidate controller not enabled: '+(directory/'controller.log').read_text(errors='replace'))
            time.sleep(.1)
        S.dump(directory/'root-trial.json',dict(Controller=controller.pid,Watchdog=guard.pid,DurationSeconds=90,NoUIActivation=True))
        print(json.dumps(dict(Directory=str(directory),Controller=controller.pid,Watchdog=guard.pid,Enabled=True)))
    except BaseException:
        (directory/'root-stop').touch();raise
if __name__=='__main__':
    {'start':start,'watchdog':watchdog}[sys.argv[1]](Path(sys.argv[2]))
