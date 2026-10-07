"""Scoped recovery own process tests; package registration is a file model."""
import sys,json,uuid,subprocess,ctypes as C,os,struct
from pathlib import Path
lab=Path(__file__).resolve().parent;runtime=lab;sys.path.insert(0,str(runtime))
import SessionController as S
from ScopedRecovery import recover_previous
results=[]
for case in ['dead-owner','active-owner','foreign-registration','unregistered-owner']:
 fixture=lab/('fixture-'+uuid.uuid4().hex);nonce=uuid.uuid4().hex;directory=fixture/'sessions'/nonce;directory.mkdir(parents=True)
 child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],creationflags=subprocess.CREATE_NO_WINDOW)
 try:
  h=S.open_process(0x1000,False,child.pid);ci=S.identity(h);S.close(h)
  h=S.open_process(0x1000,False,os.getpid());oi=S.identity(h);S.close(h)
  state=dict(Nonce=nonce,Directory=str(directory),CancelFile=str(directory/'cancel'),ConfigName='s_'+nonce+'.ini',NativePath=ci['Path'],PackageFullName=ci['Package'],Controller=dict(Pid=os.getpid(),**oi),DebuggerCommand=str(fixture/'SettingsNoVfsEntry.exe')+' --session s_'+nonce+'.ini')
  if case!='active-owner':state['Controller']['Birth']+=1 # Own PID is alive, exact prior owner identity demonstrably gone.
  S.dump(directory/'state.json',state);(fixture/'active-session.txt').write_text(str(directory/'state.json'))
  snapshot=[{'Debugger':[1,state['DebuggerCommand']]},None];current=snapshot if case!='foreign-registration' else [{'Debugger':[1,'FOREIGN']},None]
  if case=='unregistered-owner':current=[None,None]
  S.dump(directory/'registered.json',snapshot);S.dump(directory/'modeled.json',current)
  (directory/'a_own.record').write_bytes(struct.pack('<IIQ',0x53534c31,child.pid,ci['Birth']))
  S.debug_snapshot=lambda _:json.loads((directory/'modeled.json').read_text())
  S.control=lambda _,mode:S.dump(directory/'modeled.json',[None,None]) if mode=='disable' else (_ for _ in ()).throw(AssertionError())
  if case=='foreign-registration':
   try:recover_previous(S,fixture,ci['Path']);raise AssertionError('Foreign registration accepted')
   except RuntimeError as e:assert 'Foreign' in str(e)
   assert child.poll() is None and not Path(state['CancelFile']).exists()
   result={'Outcome':'ForeignPreserved'}
  else:
   result=recover_previous(S,fixture,ci['Path'])
   if case=='active-owner':assert result['Outcome']=='ActiveOwnerPreserved' and child.poll() is None
   else:
    assert result['Outcome']==('RecoveredUnregisteredSession' if case=='unregistered-owner' else 'RecoveredExactStaleSession') and child.wait(timeout=5)==0xdeca
    assert (directory/'restored.json').exists()
  results.append(dict(Case=case,**result,Pass=True))
 finally:
  if child.poll() is None:child.terminate();child.wait(timeout=5)

(lab/'own-stale-recovery-proof.json').write_text(json.dumps(dict(Tests=results,ActualOwnProcessCleanup=True,ActualPackageRegistration=False,Passed=all(x['Pass'] for x in results)),indent=2));print(json.dumps(results))
