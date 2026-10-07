"""Build the combined initializer only after each adapter's own validation."""
import hashlib,json,subprocess
from pathlib import Path
lab=Path(__file__).resolve().parent
base=lab.parent.parent
root=base.parent.parent
adapters=[('SettingsCaptionCompat','SettingsInitialize'),('SettingsControlTextCompat','SettingsControlTextInitialize'),('SettingsPowerCompat','SettingsPowerInitialize')]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
header=['typedef struct {const WCHAR* relative;const char* hash;const char* entry;} Adapter;','static const Adapter adapters[]={']
dependencies=[]
for directory,entry in adapters:
    p=lab.parent/directory/(directory+'.dll')
    digest=sha(p)
    relative='..\\'+directory+'\\'+p.name
    header.append('{L'+json.dumps(relative)+','+json.dumps(digest)+','+json.dumps(entry)+'},')
    dependencies.append({'Path':str(p),'SHA256':digest,'Export':entry})
header.append('};')
(lab/'Adapters.h').write_text('\n'.join(header),encoding='utf8')
source=(lab.parent/'SettingsCaptionCompat/SettingsCaptionCompat.c').read_text()
start=source.index('static BOOL hashMatches(');end=source.index('static BOOL sibling(',start)
(lab/'HashCheck.h').write_text(source[start:end],encoding='utf8')
cmd=[str(root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'),'cc','-target','x86_64-windows-gnu','-shared','-O2',str(lab/'SettingsContentCompat.c'),'-o',str(lab/'SettingsContentCompat.dll'),'-lbcrypt']
r=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=90)
(lab/'build.log').write_bytes(r.stdout+r.stderr)
if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace'))
files=[lab/n for n in ['SettingsContentCompat.c','SettingsContentCompat.dll','Adapters.h','HashCheck.h','Build.py']]
(lab/'manifest.json').write_text(json.dumps({'Scope':'Owned fresh Settings bootstrap; Caption, control descriptions, Power provider fallback','Dependencies':dependencies,'Files':[{'Path':str(p),'SHA256':sha(p)} for p in files]},indent=2))
print('Combined initializer built; no Settings activation.')
