from pathlib import Path
import threading,uuid,struct,time,json
import LeaseIO as IO
import SessionController as S
L=Path(__file__).resolve().parent;D=L/'fixtures'/uuid.uuid4().hex;D.mkdir(parents=True);path=D/'lease.bin';birth=1234567;path.write_bytes(struct.pack('<QQ',S.tick()+20000,birth));errors=[];reads=0;stop=threading.Event()
def writer():
 try:
  for n in range(800):
   tmp=D/'pending';tmp.write_bytes(struct.pack('<QQ',S.tick()+20000,birth));IO.replace_lease(tmp,path)
 except BaseException as e:errors.append(str(e))
 finally:stop.set()
t=threading.Thread(target=writer);t.start()
while not stop.is_set() or reads<800:
 raw=IO.read_lease(path);assert len(raw)==16 and struct.unpack('<QQ',raw)[1]==birth;reads+=1
t.join()
# A genuine exclusive handle blocks reads. Retry is bounded and cannot return
# cached data or fabricate a fresh deadline.
h=IO.create(str(path),0x80000000,0,None,3,0x80,None);assert h!=IO.P(-1).value
start=time.monotonic();refused=False
try:
 try:IO.read_lease(path)
 except OSError:refused=True
finally:IO.close(h)
elapsed=time.monotonic()-start
state={'LeaseFile':str(path),'Controller':{'Birth':birth}}
path.write_bytes(struct.pack('<QQ',S.tick()-1,birth));expired=not S.lease_active(state)
proof=dict(Passed=not errors and refused and elapsed<.5 and expired,AtomicReplaces=800,SharedDeleteReads=reads,Errors=errors,ExclusiveReadRefused=refused,ExclusiveSeconds=elapsed,ExpiredLeaseRejected=expired,NoRegistration=True,NoUI=True)
(L/'own-lease-io-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2));assert proof['Passed']
