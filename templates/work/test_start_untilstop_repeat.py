"""Exercise one exact owned Start instance restart; keep the UntilStop session active."""
import sys,json,time
from pathlib import Path
root=Path(__file__).resolve().parent.parent;lab=root/'outputs/Windows10-Components/Lab/StartSessionCompat'
sys.path.insert(0,str(lab));import SessionController as SC
path=Path((lab/'active-session.txt').read_text().strip());state=json.loads(path.read_text())
if not state['UntilStop']:raise SystemExit('Expected UntilStop')
instances=SC.owned_instances(state);ready=[i for i in instances if i['Ready']]
if len(ready)!=1:raise SystemExit('One exact ready instance required')
old=ready[0];outcome=SC.S.exact_stop(old['Pid'],old['Birth'],state)
if outcome!='StoppedExact':raise SystemExit(outcome)
deadline=time.monotonic()+45
while time.monotonic()<deadline:
 ready=[i for i in SC.owned_instances(state) if i['Ready'] and (i['Pid'],i['Birth'])!=(old['Pid'],old['Birth'])]
 if ready:
  result=dict(Session=str(path),Mode='UntilStop',Previous=old,ExactStop=outcome,Repeat=ready,Pass=True,VisibleUIConfirmed=False)
  (lab/'live-repeat-proof.json').write_text(json.dumps(result,indent=2));print(json.dumps(result));break
 time.sleep(.25)
else:raise SystemExit('No repeated ready Start observed')
