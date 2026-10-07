"""Build private primary-thread bridge and pin the reviewed menu adapter."""
from pathlib import Path
import subprocess, json, hashlib
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];ROOT=BASE.parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
r=subprocess.run([str(zig),'c++','-target','x86_64-windows-gnu','-O2','-shared',str(LAB/'PrimaryBridge.cpp'),'-o',str(LAB/'PrimaryBridge.dll'),'-luser32'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=60)
if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace'))
helper=BASE/'Lab/NativeThemeMenuCompat';meta=helper/'manifest.json';m=json.loads(meta.read_text());files=[]
if not m.get('OwnProofPassed'):raise RuntimeError('Menu producer proof not complete')
for n,digest in m['Files'].items():
 p=helper/n
 if sha(p)!=digest:raise RuntimeError('Menu producer pin differs '+str(p))
 files.append(p)
for n,digest in m['Dependencies'].items():
 p=Path(n)
 if sha(p)!=digest:raise RuntimeError('Menu dependency differs '+str(p))
 files.append(p)
files += [LAB/'PrimaryBridge.cpp',LAB/'PrimaryBridge.dll',LAB/'Launch-ThemeMenu.py',meta,BASE/'Launch-TouchpadCompat.py',BASE/'Lab/ControlThemeBootstrap/Launch-ControlTheme10.py']
(LAB/'manifest.json').write_text(json.dumps(dict(Version=1,OwnProofRequired=True,Files=[dict(Path=str(p),SHA256=sha(p))for p in sorted(set(files))]),indent=2))
print('Built menu primary-thread bridge and pinned dependencies')
