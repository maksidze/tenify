from pathlib import Path
import subprocess,json,hashlib
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];ROOT=BASE.parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
for source,dll,libraries in [('PrimaryBridge.cpp','PrimaryBridge.dll',['-luser32']),('BrowserProbe.cpp','BrowserProbe.dll',['-luser32','-lole32','-luuid','-lshell32'])]:
 p=subprocess.run([str(zig),'c++','-target','x86_64-windows-gnu','-O2','-shared',str(LAB/source),'-o',str(LAB/dll),*libraries],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60)
 if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
helper=BASE/'Lab/ControlTheme10Compat';metadata=helper/'manifest.json';old=json.loads(metadata.read_text())
for x in old['Files']:
 if sha(x['Path'])!=x['SHA256']:raise RuntimeError('Scoped control helper pin differs '+x['Path'])
files=[LAB/'PrimaryBridge.dll',LAB/'PrimaryBridge.cpp',LAB/'BrowserProbe.dll',LAB/'BrowserProbe.cpp',LAB/'Launch-ControlTheme10.py',metadata,helper/'ControlTheme10.dll',BASE/'Runtime/Explorer10/explorer.exe',BASE/'Launch-TouchpadCompat.py']
(LAB/'manifest.json').write_text(json.dumps(dict(DefaultEnabled=False,Files=[dict(Path=str(p),SHA256=sha(p)) for p in files],ActualWorkingShellUntouched=True,RequiresOwnEntryHeldPrimary=True),indent=2),encoding='utf-8')
print('Built primary DPI readback + separate own browser probe')
