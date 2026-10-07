import json,hashlib
from pathlib import Path
p=Path('outputs/Windows10-Builds/20261005-151415-b001-taskview-start-settings')
m=json.loads((p/'manifest.json').read_text(encoding='utf8'))
m['buildFiles']={n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ['Restore-Build.ps1','Start-Build.ps1','Start-Build.bat','Инструкция.txt','READY.txt']}
(p/'manifest.json').write_text(json.dumps(m,ensure_ascii=False,indent=2),encoding='utf8')
fail=[n for n,h in m['buildFiles'].items() if hashlib.sha256((p/n).read_bytes()).hexdigest()!=h]
v=json.loads((p/'verification.json').read_text(encoding='utf8'))
v['buildEntrypointsChecked']=len(m['buildFiles']);v['buildEntrypointFailures']=fail
(p/'verification.json').write_text(json.dumps(v,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'entrypoints':len(m['buildFiles']),'failures':fail,'manifestSHA256':hashlib.sha256((p/'manifest.json').read_bytes()).hexdigest()}))
