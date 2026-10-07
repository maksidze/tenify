"""Bounded own non-UI children only. Does not enable package debugging or activate Start."""
from pathlib import Path
import ctypes as C,subprocess,sys,json,time,uuid,os,threading,struct
import SessionController as D
S=D.S;H=Path(__file__).resolve().parent;R=H.parents[3];F=H/'fixtures';F.mkdir(exist_ok=True)
zig=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'work/compat-research/zig-cache'))
def compile(extra):
 p=subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-O1',*extra],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=30,env=env)
 if p.returncode:raise RuntimeError((p.stdout+p.stderr).decode(errors='replace'))
gui=['-municode','-mwindows','-Wl,--subsystem,windows']
compile(['-shared',str(H/'FixtureImports.c'),str(H/'FixtureImports.def'),'-o',str(F/'wincorlib.dll'),'-Wl,--out-implib,'+str(F/'FixtureImports.a')])
compile(['-shared',str(H/'FixtureProxy.c'),'-o',str(F/'FixtureProxy.dll')])
compile(['-shared',str(H/'FixtureBlockedProxy.c'),'-o',str(F/'FixtureBlockedProxy.dll')])
compile(gui+[str(H/'FixtureImportedChild.c'),str(F/'FixtureImports.a'),'-o',str(F/'ImportedChild.exe'),'-lshell32'])
compile(gui+[str(H/'FixtureChild.c'),'-o',str(F/'ChildFixture.exe'),'-lshell32'])
compile(gui+[str(H/'FixtureWatchdog.c'),'-o',str(F/'WatchdogFixture.exe'),'-lshell32'])
compile(gui+['-DSESSION_ENTRY_FIXTURE',str(H/'StartSessionEntry.c'),str(H/'FixtureBackend.c'),'-o',str(F/'EntryFixture.exe'),'-lshell32'])
source=(H/'StartSessionBackend.c').read_text()
needle='BOOL packageMatches=packageResult==0&&expectedPackage[0]&&!wcscmp(package,expectedPackage);'
assert source.count(needle)==1
source=source.replace(needle,'BOOL packageMatches=packageResult==APPMODEL_ERROR_NO_PACKAGE&&!wcscmp(expectedPackage,L"OWN-UNPACKAGED-FIXTURE");')
(F/'FullBackend.c').write_text(source)
entry=(H/'StartSessionEntry.c').read_text().replace('if(seconds>3600)seconds=3600;','if(seconds>3600)seconds=3600;seconds=2; /* own fixture: real watchdog accelerated */')
(F/'FullEntry.c').write_text(entry)
compile(gui+['-DSESSION_ENTRY_FIXTURE','-Dwmain=BrokerExistingWmain','-I'+str(H),str(F/'FullBackend.c'),str(F/'FullEntry.c'),'-o',str(F/'FullBackend.exe'),'-lshell32','-luser32','-ladvapi32'])

class SI(C.Structure):_fields_=[('cb',S.W.DWORD),('reserved',S.W.LPWSTR),('desktop',S.W.LPWSTR),('title',S.W.LPWSTR),('x',S.W.DWORD),('y',S.W.DWORD),('xs',S.W.DWORD),('ys',S.W.DWORD),('xc',S.W.DWORD),('yc',S.W.DWORD),('fill',S.W.DWORD),('flags',S.W.DWORD),('show',S.W.WORD),('reserved2',S.W.WORD),('bytes',S.P),('input',S.P),('output',S.P),('error',S.P)]
class PI(C.Structure):_fields_=[('process',S.P),('thread',S.P),('pid',S.W.DWORD),('tid',S.W.DWORD)]
job=S.api('CreateJobObjectW',S.P,[S.P,S.W.LPCWSTR])(None,None);limits=C.create_string_buffer(144);C.cast(C.byref(limits,16),C.POINTER(S.W.DWORD))[0]=0x2000
assert job and S.api('SetInformationJobObject',S.W.BOOL,[S.P,C.c_int,S.P,S.W.DWORD])(job,9,limits,len(limits))
children=[];tests=[]
def create(exe,args,resume=True):
 pi=PI();si=SI();si.cb=C.sizeof(si);cmd=C.create_unicode_buffer(subprocess.list2cmdline([str(exe),*args]))
 assert S.api('CreateProcessW',S.W.BOOL,[S.W.LPCWSTR,S.W.LPWSTR,S.P,S.P,S.W.BOOL,S.W.DWORD,S.P,S.W.LPCWSTR,S.P,S.P])(str(exe),cmd,None,None,False,0x08000004,None,str(F),C.byref(si),C.byref(pi))
 children.append(pi)
 assert S.api('AssignProcessToJobObject',S.W.BOOL,[S.P,S.P])(job,pi.process)
 if resume:assert S.api('ResumeThread',S.W.DWORD,[S.P])(pi.thread)!=0xffffffff
 return pi
def stop(pi):
 if S.wait(pi.process,0)!=0:S.terminate(pi.process,0xdeca);assert S.wait(pi.process,3000)==0
def exitcode(pi):
 result=S.W.DWORD();assert S.api('GetExitCodeProcess',S.W.BOOL,[S.P,S.P])(pi.process,C.byref(result));return result.value
owner=dict(Pid=os.getpid(),**S.identity(S.api('GetCurrentProcess',S.P,[])()))
def config(directory,child,until=True,ownerid=owner):
 path=F/('s_'+uuid.uuid4().hex+'.ini')
 fields=dict(Target=str(F/('ImportedChild.exe' if child[1] else 'ChildFixture.exe')),PackageFullName='OWN-UNPACKAGED-FIXTURE',Directory=str(directory),CancelFile=str(directory/'cancel'),Proxy=str(F/'FixtureProxy.dll'),OwnerPid=str(ownerid['Pid']),OwnerBirth=str(ownerid['Birth']),OwnerPath=ownerid['Path'],DeadlineTick=str(S.tick()+10000),UntilStop=str(int(until)),ServerArgument='-ServerName:OwnFixture')
 path.write_text('[Session]\r\n'+''.join(k+'='+v+'\r\n' for k,v in fields.items()),encoding='utf-16');return path
def waitfile(path,seconds=8):
 deadline=time.monotonic()+seconds
 while not path.exists():
  if time.monotonic()>deadline:raise AssertionError('Missing '+str(path))
  time.sleep(.01)
try:
 shared=F/('entry-'+uuid.uuid4().hex);shared.mkdir()
 for scenario in ['first','repeat','cancel-before','cancel-after-record','wrong-owner']:
  directory=shared if scenario in ('first','repeat') else F/(scenario+'-'+uuid.uuid4().hex);directory.mkdir(exist_ok=True)
  child=create(F/'ChildFixture.exe',[str(directory/(scenario+'.console'))]);identity=S.identity(child.process)
  identityOwner=dict(owner)
  if scenario=='wrong-owner':identityOwner['Birth']+=1
  cfg=config(directory,(child,False),ownerid=identityOwner)
  if scenario=='cancel-before':(directory/'cancel').touch()
  entry=create(F/'EntryFixture.exe',['--session',cfg.name,'-p',str(child.pid),'-tid',str(child.tid)])
  if scenario=='cancel-after-record':
   until=time.monotonic()+3
   while not list(directory.glob('*.record')):
    assert time.monotonic()<until;time.sleep(.005)
   (directory/'cancel').touch()
  assert S.wait(entry.process,8000)==0;code=exitcode(entry)
  if scenario in ('first','repeat'):
   assert code==100 and S.wait(child.process,0)==258
   own=[r for r in S.records(directory) if r[1:]==(child.pid,identity['Birth'])];assert len(own)==1
   ini=own[0][0].with_suffix('.ini');original=ini.read_bytes()
   assert S.api('SuspendThread',S.W.DWORD,[S.P])(child.thread)==0
   try:
    duplicate=create(F/'EntryFixture.exe',['--session',cfg.name,'-p',str(child.pid),'-tid',str(child.tid)])
    assert S.wait(duplicate.process,5000)==0 and exitcode(duplicate)==0 and ini.read_bytes()==original
   finally:resumeCount=S.api('ResumeThread',S.W.DWORD,[S.P])(child.thread)
   assert resumeCount==1,'Duplicate entry consumed the existing bootstrap suspend count'
   assert S.exact_stop(child.pid,identity['Birth']+1,dict(NativePath=str(F/'ChildFixture.exe'),PackageFullName=''))=='IdentityMismatchRefused'
   assert S.wait(child.process,0)==258
  elif scenario=='wrong-owner':assert code==0 and S.wait(child.process,0)==258 and not S.records(directory)
  else:assert code==0 and S.wait(child.process,3000)==0 and exitcode(child)==0xdeca
  tests.append(dict(Scenario=scenario,Pass=True,Pid=child.pid,EntryPid=entry.pid));stop(child)

 # Real original import patch, suspended main/loader flow, detach and deadline.
 for scenario in ['until-stop','bounded','owner-end','bootstrap-failed','bootstrap-stall']:
  directory=F/(scenario+'-'+uuid.uuid4().hex);directory.mkdir();console=directory/'result.json'
  child=create(F/'ImportedChild.exe',[str(console)],resume=False);testowner=owner;controller=None
  if scenario=='owner-end':
   controller=create(F/'ChildFixture.exe',[str(directory/'controller-console')]);testowner=dict(Pid=controller.pid,**S.identity(controller.process))
  cfg=config(directory,(child,True),until=scenario!='bounded',ownerid=testowner)
  if scenario in ('bootstrap-stall','bootstrap-failed'):
   # Missing proxy genuinely fails bootstrap; no fake success or deadline extension.
   replacement=F/('FixtureBlockedProxy.dll' if scenario=='bootstrap-stall' else 'does-not-exist.dll')
   txt=cfg.read_text(encoding='utf-16').replace(str(F/'FixtureProxy.dll'),str(replacement));cfg.write_text(txt,encoding='utf-16')
  entry=create(F/'FullBackend.exe',['--session',cfg.name,'-p',str(child.pid),'-tid',str(child.tid)])
  if not scenario.startswith('bootstrap'):
   waitfile(console);result=json.loads(console.read_text());assert result['FactoryResult']==0x5a and result['ArgumentsResult']==0x6a and result['Console']==0
   deadline=time.monotonic()+4
   while not list(directory.glob('*.ready')):assert time.monotonic()<deadline;time.sleep(.01)
   debugger=S.W.BOOL(True);assert S.api('CheckRemoteDebuggerPresent',S.W.BOOL,[S.P,S.P])(child.process,C.byref(debugger)) and not debugger.value
   time.sleep(2.3)
   if scenario in ('until-stop','owner-end'):
    assert S.wait(child.process,0)==258 and S.wait(entry.process,0)==258
    if controller:stop(controller)
    else:(directory/'cancel').touch()
   else:assert S.wait(child.process,1500)==0
  assert S.wait(child.process,5000)==0 and S.wait(entry.process,5000)==0
  if scenario=='bootstrap-stall':assert exitcode(entry) in (0,0xdece) and not list(directory.glob('*.ready'))
  tests.append(dict(Scenario=scenario,Pass=True,Pid=child.pid,EntryPid=entry.pid,ChildExit=exitcode(child),EntryExit=exitcode(entry),ActualIATPatch=not scenario.startswith('bootstrap')))

 directory=F/('blocked-supervisor-'+uuid.uuid4().hex);directory.mkdir();child=create(F/'ChildFixture.exe',[str(directory/'console')]);birth=S.identity(child.process)['Birth']
 watchdog=create(F/'WatchdogFixture.exe',[str(child.pid),str(birth),str(F/'ChildFixture.exe')]);assert S.wait(watchdog.process,4000)==0 and exitcode(watchdog)==0xdece and S.wait(child.process,0)==0
 tests.append(dict(Scenario='independent-watchdog-while-main-thread-blocked',Pass=True,ChildPid=child.pid,SupervisorPid=watchdog.pid))

 # Pure policy: no healthy-instance expiry; repeated failure capped, owner/birth strict.
 policy=D.RecoveryPolicy(0);assert not policy.needed(1000000,True)
 assert policy.needed(10,False) and policy.needed(20,False) and policy.needed(30,False)
 try:policy.needed(40,False);raise AssertionError('Failure loop unlimited')
 except RuntimeError:pass
 state=dict(UntilStop=True,DeadlineTick=1,CancelFile=str(F/'absent-cancel'))
 assert D.active(state);tests.append(dict(Scenario='UntilStop-no-lifetime-and-bounded-recovery',Pass=True))
 command='C:\\own\\Start10SessionDebugger.exe --session immutable.ini';assert S.registration_owned([{'Debugger':command},None],command) and not S.registration_owned([{'Debugger':command+' foreign'},None],command)
 tests.append(dict(Scenario='exact-registration-command-policy',Pass=True))

 # Actual guard and restore mechanics with only registry/activation observations
 # substituted. Processes, ownership checks, cancel file and record cleanup are real.
 directory=F/('guard-'+uuid.uuid4().hex);directory.mkdir()
 controller=create(F/'ChildFixture.exe',[str(directory/'owner-console')]);shell=create(F/'ChildFixture.exe',[str(directory/'shell-console')]);target=create(F/'ChildFixture.exe',[str(directory/'target-console')]);foreign=create(F/'ChildFixture.exe',[str(directory/'foreign-console')])
 targetIdentity=S.identity(target.process);foreignIdentity=S.identity(foreign.process)
 (directory/'a_target.record').write_bytes(struct.pack('<IIQ',0x53534c31,target.pid,targetIdentity['Birth']))
 (directory/'a_foreign.record').write_bytes(struct.pack('<IIQ',0x53534c31,foreign.pid,foreignIdentity['Birth']+1))
 state=dict(Directory=str(directory),CancelFile=str(directory/'cancel'),Nonce=uuid.uuid4().hex,UntilStop=True,DeadlineTick=0,Controller=dict(Pid=controller.pid,**S.identity(controller.process)),Explorer=dict(Pid=shell.pid,**S.identity(shell.process)),NativePath=str(F/'ChildFixture.exe'),PackageFullName='',DebuggerCommand=command)
 old=(D.SESSION_MUTEX,D.owner_pid,S.debug_snapshot,S.control,D.restore_native_if_appropriate);D.SESSION_MUTEX='Local\\StartSessionFixture_'+uuid.uuid4().hex;D.owner_pid=lambda:shell.pid
 snapshot=[{'Debugger':command},None];calls=[];errors=[];S.debug_snapshot=lambda state:snapshot.copy()
 def fake_control(state,mode):
  calls.append(mode);assert mode=='disable';snapshot[:]=[None,None]
 S.control=fake_control;D.restore_native_if_appropriate=lambda state,handle:None
 def run_guard():
  try:D.guard(state)
  except Exception as e:errors.append(str(e))
 thread=threading.Thread(target=run_guard);thread.start()
 try:
  waitfile(directory/'guard-ready.json');stop(controller);thread.join(timeout=12)
  assert not thread.is_alive() and not errors and calls==['disable'] and (directory/'restored.json').exists()
  assert S.wait(target.process,0)==0 and S.wait(foreign.process,0)==258 and S.wait(shell.process,0)==258
  S.restore(state);assert calls==['disable']
  tests.append(dict(Scenario='actual-owner-death-guard-owned-registration-record-cleanup-idempotence',Pass=True,TargetPid=target.pid,ForeignWrongBirthPreserved=foreign.pid))
 finally:
  if thread.is_alive():(directory/'cancel').touch();thread.join(timeout=10)
  D.SESSION_MUTEX,D.owner_pid,S.debug_snapshot,S.control,D.restore_native_if_appropriate=old
 (H/'own-session-proof.json').write_text(json.dumps(dict(Tests=tests,NoSystemPackageActivated=True,NoPackageDebugRegistration=True,OwnChildrenJobGuarded=True,AllChildrenExited=True),indent=2))
 print(json.dumps(tests))
finally:
 for pi in children:
  stop(pi);S.close(pi.thread);S.close(pi.process)
 S.close(job)
