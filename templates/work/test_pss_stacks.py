from pathlib import Path
import importlib.util, json, queue, subprocess, threading, time
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/ThreadStackSnapshot'
spec=importlib.util.spec_from_file_location('pss_capture',lab/'capture.py')
cap=importlib.util.module_from_spec(spec);spec.loader.exec_module(cap)
fixture=subprocess.Popen([str(lab/'PssStacks.exe'),'--fixture'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
messages=queue.Queue()
def drain():
    for line in fixture.stdout:
        messages.put(json.loads(line))
threading.Thread(target=drain,daemon=True).start()
report={}
try:
    ready=messages.get(timeout=5)
    assert ready['event']=='ready' and ready['pid']==fixture.pid and not ready['debugger'],ready
    report['fixture']=ready
    hb=messages.get(timeout=3);assert hb['event']=='heartbeat'
    bad,bad_events=cap.capture(fixture.pid,int(ready['birth'])+1,lab/'PssStacks.exe',str(ready['tid']),lab/'own-wrong-birth.jsonl')
    assert any(e.get('stage')=='identityMismatch' for e in bad_events),bad
    assert not any(e['event']=='snapshot' for e in bad_events)
    report['wrongBirthRefusedBeforeCapture']=True
    result,events=cap.capture(fixture.pid,int(ready['birth']),lab/'PssStacks.exe','all',lab/'own-all-threads.jsonl')
    report['capture']=result
    assert result['complete'] and result['complete']['ok'],result
    assert any(e['event']=='snapshotFreed' and e['code']==0 for e in events)
    frames=[e for e in events if e['event']=='frame' and e['tid']==ready['tid']]
    names=[e['symbol'] for e in frames]
    report['workerSymbols']=names
    for name in ('FixtureLevel1','FixtureLevel2','FixtureLevel3'):
        assert any(name==s or s.endswith(name) for s in names),(name,names)
    # Discard buffered heartbeats, then require a fresh one after cleanup.
    while not messages.empty():messages.get_nowait()
    after=messages.get(timeout=3)
    assert after['event']=='heartbeat' and after['number']>hb['number']
    assert fixture.poll() is None
    report['continuedHeartbeatAfterSnapshotFree']=after
    report['ok']=True
finally:
    # Exact own Popen handle, no PID reuse or unrelated process termination.
    if fixture.poll() is None:fixture.terminate()
    fixture.wait(timeout=5)
    report['fixtureFinalExitCode']=fixture.returncode
    (lab/'own-proof.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
