from pathlib import Path
import re,json
H=Path(__file__).resolve().parent;B=H.parent.parent;p=B/'Image/4/Windows/System32/SettingsHandlers_nt.dll';b=p.read_bytes();strings=[]
for match in re.finditer(rb'(?:[\x20-\x7e]\x00){10,}',b):
 s=match.group().decode('utf-16-le')
 if any(x in s for x in ['ms-resource:','Taskbar_Lock','SettingsHandlers-nt','SettingsAppThreshold','.pri','Taskbar_Autohide','Taskbar_Badging']):strings.append(dict(fileOffset=hex(match.start()),value=s))
(H/'nt-resource-strings.json').write_text(json.dumps(strings,indent=2));print(json.dumps(strings,indent=2))
