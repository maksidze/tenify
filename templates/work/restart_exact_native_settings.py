"""One-time exact native Settings transition for the requested UntilStop migration."""
import sys,json,argparse
from pathlib import Path
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SettingsUntilStopCompat'
sys.path.insert(0,str(lab))
import SessionController as S
ap=argparse.ArgumentParser();ap.add_argument('--pid',type=int,required=True);ap.add_argument('--birth',type=int);ap.add_argument('--execute',action='store_true');a=ap.parse_args()
h=S.open_process(0x101001,False,a.pid)
if not h:raise SystemExit('Exact process unavailable')
try:
 i=S.identity(h)
 if not i or i['Path'].casefold()!=r'c:\windows\immersivecontrolpanel\systemsettings.exe' or not i['Package'].startswith('windows.immersivecontrolpanel_'):raise SystemExit('Native Settings identity differs')
 if a.execute:
  if a.birth!=i['Birth']:raise SystemExit('Exact birth differs')
  if not S.terminate(h,0xdeca):raise SystemExit('Stop refused')
  result=dict(Pid=a.pid,**i,Outcome='StoppedExact' if S.wait(h,5000)==0 else 'StopTimeout')
  S.dump(lab/'native-transition.json',result)
 else:result=dict(Pid=a.pid,**i,Outcome='ReadOnly')
 print(json.dumps(result))
finally:S.close(h)
