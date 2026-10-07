"""Only disposable signed-by-us GUI fixture children. No package activation."""
import ctypes as C,json,struct,sys,uuid,time,subprocess
from ctypes import wintypes as W
from pathlib import Path
from Lifecycle import *
from Callback import run
sha=lambda p:__import__("hashlib").sha256(Path(p).read_bytes()).hexdigest()
LAB=Path(__file__).resolve().parent
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('cbReserved',W.WORD),('bytes',P),('input',P),('output',P),('error',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',W.DWORD),('tid',W.DWORD)]
create=api('CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,P,P])
root=LAB/'fixtures'/uuid.uuid4().hex;root.mkdir(parents=True)
own=open_process(0x101000,False,__import__('os').getpid())
controller=dict(Pid=__import__('os').getpid(),**identity(own));close(own)
def state_for(directory):
 directory.mkdir();lease=directory/'lease.bin';lease.write_bytes(struct.pack('<QQ',tick()+20000,controller['Birth']))
 native=Path('C:/Windows/System32/version.dll');adapter=LAB/'FixtureAdapter.dll';target=LAB/'Fixture.exe'
 return dict(Nonce=uuid.uuid4().hex,OwnFixture=True,Directory=str(directory),NativePath=str(target),NativeSHA256=sha(target),PackageFullName='',StartBirth=0,
  Controller=controller,LeaseFile=str(lease),CancelFile=str(directory/'cancel'),BridgeTemplate=str(LAB/'FixtureBridge.dll'),BootstrapPackageName='OWN-UNPACKAGED-FIXTURE',
  Files=[dict(Path=str(p),SHA256=sha(p)) for p in [LAB/'FixtureBridge.dll',adapter,LAB/'OwnBootstrap.py']],
  Adapters=[dict(NativeModule=str(native),NativeSHA256=sha(native),Helper=str(adapter),HelperSHA256=sha(adapter),Initialize='FixtureInitialize')])
def child(directory):
 target=LAB/'Fixture.exe';out=directory/'primary.log';pi=PI();si=SI();si.cb=C.sizeof(si)
 command=C.create_unicode_buffer(subprocess.list2cmdline([str(target),str(out)]))
 if not create(str(target),command,None,None,False,0x08000004,None,str(LAB),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
 return pi,out
import Callback
def own_bootstrap(target,state):
 if state['Adapters'][0]['Initialize']=='MissingExport':raise RuntimeError('Owned fixture partial failure')
 from OwnBootstrap import OwnChildBootstrap
 b=OwnChildBootstrap(target,state['NativePath']);b.pause_at_entry(20);b.finish(detach=True,resume_primary=False);b.resume_primary()
 return dict(DebuggerDetached=True,NoVFS=True)
Callback.bootstrap_owned=own_bootstrap
proof=dict(NoUserUI=True,ActualSEH=False,NoRegistration=True,NoVFS=True,Checks={})
for mode in ['wrong_birth','wrong_package','wrong_thread','expired_owner','cancel','terminal_restored','success','partial_failure']:
 state=state_for(root/mode);pi,out=child(root/mode)
 try:
  if mode=='wrong_birth':state['StartBirth']=identity(pi.process)['Birth']+1
  if mode=='wrong_package':state['PackageFullName']='WRONG-PACKAGE'
  if mode in ['wrong_birth','wrong_package','wrong_thread']:
   try:t=OwnedActivation(state,pi.pid,controller['Pid'] if mode=='wrong_thread' else pi.tid)
   except (RuntimeError,OSError):proof['Checks'][mode]=not out.exists() and not list((root/mode).glob('a_*.record'))
   else:t.close();raise RuntimeError('Negative accepted '+mode)
  else:
   if mode=='expired_owner':Path(state['LeaseFile']).write_bytes(struct.pack('<QQ',tick()-1,controller['Birth']))
   if mode=='cancel':Path(state['CancelFile']).touch()
   if mode=='terminal_restored':(root/mode/'restored.json').write_text('{}')
   if mode=='partial_failure':state['Adapters'][0]['Initialize']='MissingExport'
   try:report=run(state,pi.pid,pi.tid)
   except (RuntimeError,OSError):
    if mode!='partial_failure':raise
    proof['Checks'][mode]=wait(pi.process,0)==0 and not out.exists() and bool(list((root/mode).glob('*.failure.json')))
   else:
    if wait(pi.process,7000)!=0:raise RuntimeError('Fixture did not complete')
    if mode in ['cancel','terminal_restored']:proof['Checks'][mode]=out.exists() and report['Outcome']=='OrphanResumedNative' and not list((root/mode).glob('a_*.record'))
    elif mode=='expired_owner':proof['Checks'][mode]=out.exists() and not list((root/mode).glob('a_*.record')) and report['Outcome']=='OrphanResumedNative'
    else:proof['Checks'][mode]=out.exists() and report['DebuggerDetached'] and bool(list((root/mode).glob('*.log')))
 finally:
  if wait(pi.process,0)==258:terminate(pi.process,0xdeca);wait(pi.process,5000)
  close(pi.thread);close(pi.process)
proof['Passed']=all(proof['Checks'].values());atomic(LAB/'own-lifecycle-proof.json',proof)
print(json.dumps(proof,indent=2))
if not proof['Passed']:raise RuntimeError('Lifecycle fixture failed')
