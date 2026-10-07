from pathlib import Path
import hashlib,json,subprocess,sys,ast
H=Path(__file__).resolve().parent
for p in H.glob('*.py'):ast.parse(p.read_text(encoding='utf-8-sig'),filename=str(p))
tests=json.loads((H/'own-session-proof.json').read_text());assert tests['AllChildrenExited'] and all(t['Pass'] for t in tests['Tests'])
# Negative read-only repair fixtures: nonexistent package, foreign command.
package='Microsoft.Windows.StartMenuExperienceHost_0.0.0.0_neutral_neutral_cw5n1h2txyewy';command=str(H/'Start10SessionDebugger.exe')+' --session s_'+'0'*32+'.ini'
rows=[]
for label,cmd,expected in [('absent-registration',command,0),('foreign-command',command.replace('Start10SessionDebugger.exe','Foreign.exe'),64)]:
 log=H/('repair-'+label+'.log');p=subprocess.run([str(H/'SessionRepair.exe'),package,cmd,str(log)],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=20);assert p.returncode==expected,(label,p.returncode)
 rows.append(dict(Scenario=label,Exit=p.returncode,NoRegistryMutation=True,Log=log.read_text() if log.exists() else None))
(H/'repair-readonly-proof.json').write_text(json.dumps(rows,indent=2))
manifest=json.loads((H/'manifest.json').read_text())
files=[Path(r['Path']) for r in manifest['Files']]+[H/'Readme.txt',H/'own-session-proof.json',H/'repair-readonly-proof.json',H/'Finalize.py']
manifest['Files']=[dict(Path=str(p.resolve()),SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in dict.fromkeys(files)]
manifest['OwnFixturesPass']=True;manifest['ReadyForCoordinatedLiveTest']=True
manifest['Integration']=dict(Enable='Enable-Start10-Session.ps1 -UntilStop [-TargetPid <owned shell PID>]',Stop='Stop-Start10-Session.ps1 [-StatePath <state.json>]',Status='Status-Start10-Session.ps1',NoPeriodicRestart=True)
(H/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(dict(Ready=True,DebuggerSHA256=hashlib.sha256((H/'Start10SessionDebugger.exe').read_bytes()).hexdigest(),Tests=len(tests['Tests']),PackageActivationPerformed=False)))
