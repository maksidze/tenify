import argparse,json,hashlib
from pathlib import Path
from Lifecycle import OwnedActivation,lease_active,atomic
from Bootstrap import bootstrap_owned
def run(state,pid,tid):
 target=OwnedActivation(state,pid,tid)
 try:
  if not target.claim():
   target.resume_native()
   if not state.get('OwnFixture',False):
    from SessionController import restore
    restore(state)
   return {'Outcome':'OrphanResumedNative'}
  for item in state['Files']:
   if hashlib.sha256(Path(item['Path']).read_bytes()).hexdigest()!=item['SHA256']:raise RuntimeError('Pinned dependency changed '+item['Path'])
  if Path(state['CancelFile']).exists() or not lease_active(state):raise RuntimeError('Cancelled before bootstrap')
  report=bootstrap_owned(target,state)
  if Path(state['CancelFile']).exists() or not lease_active(state):raise RuntimeError('Cancelled at bootstrap completion')
  target.record.with_suffix('.log').write_text('DETACH_OWNERSHIP_TRANSFER\n'+json.dumps(report),encoding='utf-8');target.finished=True
  return report
 except BaseException as e:
  if target.claimed:atomic(target.record.with_suffix('.failure.json'),dict(Error=str(e),Outcome=target.stop()))
  raise
 finally:target.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--state',required=True);p.add_argument('-p',type=int,required=True);p.add_argument('-tid',type=int,required=True);a=p.parse_args();print(json.dumps(run(json.loads(Path(a.state).read_text(encoding='utf-8')),a.p,a.tid)))
