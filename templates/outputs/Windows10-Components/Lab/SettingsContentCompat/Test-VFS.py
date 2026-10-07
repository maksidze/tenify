"""Exercise the real repeated broker/VFS bootstrap with the content initializer."""
from pathlib import Path
import sys
import json
content=Path(__file__).resolve().parent
source=content.parent/'SettingsSessionCompat/Test-RepeatedVFS.py'
sys.path.insert(0,str(source.parent))
code=source.read_text()
assert code.count("range(4)")==1
assert code.count("lab.parent/'SettingsCaptionCompat/SettingsCaptionCompat.dll'")==1
code=code.replace('range(4)','range(2)')
code=code.replace("lab.parent/'SettingsCaptionCompat/SettingsCaptionCompat.dll'","lab.parent/'SettingsContentCompat/SettingsContentCompat.dll'")
code=code.replace("lab/'repeated-vfs-own-proof.json'","lab.parent/'SettingsContentCompat/repeated-vfs-own-proof.json'")
exec(compile(code,str(source),'exec'),{'__file__':str(source),'__name__':'__main__'})
proof=json.loads((content/'repeated-vfs-own-proof.json').read_text())
assert len(proof['Results'])==2 and all(x['VfsPrepared'] and x['Initializer'] and x['Detached'] for x in proof['Results']), 'Combined VFS initialization/detach failed; inspect proof.'
