"""Real disposable process handles; registration is an explicit FILE mock."""
import ctypes as C,json,struct,time,subprocess,threading,uuid,sys,os
from pathlib import Path
import SessionController as controller
LAB=Path(__file__).resolve().parent
directory=LAB/'fixtures'/uuid.uuid4().hex;directory.mkdir(parents=True)
registration=directory/'MOCK-registration.json';command='OWN-FIXTURE-COMMAND'
registration.write_text(json.dumps([{'Values':{'Debugger':[1,command]}},None]))
def snapshot(state):return json.loads(registration.read_text())
def control(state,mode):
 if mode!='disable':raise RuntimeError('Enable is forbidden in this fixture')
 registration.write_text('[null,null]')
controller.debug_snapshot=snapshot;controller.control=control
owner=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],creationflags=subprocess.CREATE_NO_WINDOW)
h=controller.open_process(0x101000,False,owner.pid);i=controller.identity(h);controller.close(h)
state=dict(OwnFixture=True,Nonce=uuid.uuid4().hex,Directory=str(directory),CancelFile=str(directory/'cancel'),LeaseFile=str(directory/'lease.bin'),Controller=dict(Pid=owner.pid,**i),NativePath=str(LAB/'Fixture.exe'),PackageFullName='',DebuggerCommand=command)
(directory/'lease.bin').write_bytes(struct.pack('<QQ',controller.tick()+20000,i['Birth']));(directory/'registered.json').write_text(registration.read_text())
errors=[]
def guarded():
 try:controller.guard(state)
 except BaseException as e:errors.append(str(e))
thread=threading.Thread(target=guarded);thread.start();end=time.monotonic()+8
while not (directory/'guard-ready.json').exists():
 if time.monotonic()>end:raise RuntimeError('Guard fixture not ready')
 time.sleep(.05)
owner.terminate();owner.wait(5);thread.join(15)
proof=dict(ActualRegistration=False,ActualSEH=False,OnlyOwnController=True,ControllerDeathCleanup=not errors and not thread.is_alive() and (directory/'restored.json').exists() and snapshot(state)==[None,None],Errors=errors)
# Foreign registration is refused; no actual registry access occurs.
other=directory/'foreign';other.mkdir();foreign=dict(state,Directory=str(other),Nonce=uuid.uuid4().hex,CancelFile=str(other/'cancel'))
registration.write_text('[{"Foreign":"OTHER-COMMAND"},null]')
try:controller.restore(foreign)
except RuntimeError:proof['ForeignRegistrationPreserved']=snapshot(foreign)==[{'Foreign':'OTHER-COMMAND'},None] and not (other/'restored.json').exists()
else:proof['ForeignRegistrationPreserved']=False
proof['Passed']=proof['ControllerDeathCleanup'] and proof['ForeignRegistrationPreserved']
(LAB/'own-guard-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
if not proof['Passed']:raise RuntimeError('Guard fixture failed')
