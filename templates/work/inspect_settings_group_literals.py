from pathlib import Path
import json,re
root=Path.cwd();x=(root/'work/settings-viewmodel-actual.xbf').read_bytes();native=Path('C:/Windows/System32/SettingsEnvironment.Desktop.dll').read_bytes();old=(root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsEnvironment.Desktop.dll').read_bytes()
# Stable UTF16 system-name strings only; avoid inferring semantics from presence alone.
names=sorted(set(re.findall(r'SettingsPageGroup[A-Za-z0-9_]+',x.decode('utf-16le',errors='ignore'))))
rows=[{'id':n,'literalInOldEnvironment':n.encode('utf-16le') in old,'literalInHostEnvironment':n.encode('utf-16le') in native} for n in names]
(root/'work/settings-old-group-literals.json').write_text(json.dumps({'limitation':'Binary string presence is not evidence of dynamic-text method support; only candidate ordering for future live call HRESULT capture.','rows':rows},indent=2));print(json.dumps(rows,indent=2))
