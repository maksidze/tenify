from pathlib import Path
import sys,json,time,subprocess
statePath=Path(sys.argv[1]).resolve();s=json.loads(statePath.read_text());lab=statePath.parents[2];sys.path.insert(0,str(lab));import SessionController as S
root=lab.parents[3];directory=Path(s['Directory']);deadline=time.monotonic()+130
while time.monotonic()<deadline and not (directory/'root-stop').exists():time.sleep(.25)
try:S.restore(s);result={'RegistrationRestored':True}
except Exception as e:result={'RegistrationRestored':False,'Error':str(e)}
if result['RegistrationRestored'] and (directory/'source-acl.json').exists():
 p=subprocess.run(['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(root/'work/NetworkLayout-SourceAccess.ps1'),'-StatePath',str(statePath),'-Mode','Restore'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=30);result['ACLRestoreExit']=p.returncode;result['ACLRestoreError']=p.stderr.decode(errors='replace')[-1000:]
(directory/'root-guard-result.json').write_text(json.dumps(result,indent=2))
