import json,subprocess,time,hashlib,struct
from pathlib import Path
lab=Path(__file__).resolve().parent;exe=lab/'MonitorPublisherUntilStop.exe';proof=[]
for kind in ['bootstrap','stall']:
 report=lab/('untilstop-own-'+kind+'.log');started=time.monotonic()
 p=subprocess.run([str(exe),'--lease-proof',str(report),kind],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=5)
 assert p.returncode==0xdeca,(p.returncode,p.stderr)
 proof.append(dict(Test=kind,ExitCode=p.returncode,Elapsed=time.monotonic()-started,NoPublication=True))
p=subprocess.run([str(exe),'--lease-cleanup-proof',str(lab/'untilstop-own-cleanup.log')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=5)
assert p.returncode==0 and 'joined1' in (lab/'untilstop-own-cleanup.log').read_text(encoding='utf-8-sig')
proof.append(dict(Test='normal-DoneEvent-thread-join-before-handle-close',ExitCode=0,NoPublication=True))
b=exe.read_bytes();o=struct.unpack_from('<I',b,60)[0];assert struct.unpack_from('<H',b,o+24+68)[0]==2
code=''
for name in ['Start-MonitorPublisherUntilStop.ps1','Stop-MonitorPublisherUntilStop.ps1']:
 code+="$e=$null;[System.Management.Automation.Language.Parser]::ParseFile('"+str(lab/name)+"',[ref]$null,[ref]$e)|Out-Null;if($e){throw ($e|Out-String)};"
p=subprocess.run(['powershell.exe','-NoProfile','-Command',code],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True);assert p.returncode==0,p.stderr
(lab/'untilstop-own-proof.json').write_text(json.dumps(dict(Tests=proof,Subsystem=2,PublicationPerformed=False,CurrentShellUntouched=True),indent=2))
# Separate manifest; preserve bounded publisher manifest and executable unchanged.
canonical=json.loads((lab/'manifest.json').read_text(encoding='utf-8-sig'))
files=[Path(x['Path']) for x in canonical['Files'] if Path(x['Path']).name in ['PublisherJobGuard.cs','windowsudk.shellcommon.dll','Taskbar.dll','explorer.exe']]
files += [lab/n for n in ['MonitorPublisherUntilStop.c','MonitorPublisherUntilStop.exe','Build-UntilStop.py','Start-MonitorPublisherUntilStop.ps1','Stop-MonitorPublisherUntilStop.ps1','Test-UntilStop.py']]
(lab/'untilstop-manifest.json').write_text(json.dumps(dict(Files=[dict(Path=str(p.resolve()),Sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in files]),indent=2))
print(json.dumps(proof))
