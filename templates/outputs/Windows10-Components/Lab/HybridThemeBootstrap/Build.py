from pathlib import Path
import subprocess,json,hashlib
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];ROOT=BASE.parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
for source,out,libs in [('PrimaryBridge.cpp','PrimaryBridge.dll',['-luser32']),('BrowserProbe.cpp','BrowserProbe.dll',['-luser32','-lole32','-luuid','-lshell32'])]:
 p=subprocess.run([str(zig),'c++','-target','x86_64-windows-gnu','-O2','-shared',str(LAB/source),'-o',str(LAB/out),*libs],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60)
 if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
helper=BASE/'Lab/ThemeFolderHybridCompat';meta=helper/'manifest.json';x=json.loads(meta.read_text());files=[]
for n,digest in x['Files'].items():
 p=helper/n
 if sha(p)!=digest:raise RuntimeError('Hybrid producer pin differs '+str(p))
 files.append(p)
for n,digest in x['Dependencies'].items():
 p=Path(n)
 if sha(p)!=digest:raise RuntimeError('Hybrid native dependency differs '+str(p))
 files.append(p)
files += [LAB/'PrimaryBridge.cpp',LAB/'PrimaryBridge.dll',LAB/'BrowserProbe.cpp',LAB/'BrowserProbe.dll',LAB/'Launch-HybridTheme10.py',meta,BASE/'Launch-TouchpadCompat.py',BASE/'Lab/ControlThemeBootstrap/Launch-ControlTheme10.py']
(LAB/'manifest.json').write_text(json.dumps(dict(DefaultEnabled=False,ProductionVisibleUnverified=True,Files=[dict(Path=str(p),SHA256=sha(p)) for p in sorted(set(files))]),indent=2),encoding='utf-8')
print('Built separate hybrid primary-DPI bootstrap and3-view own browser probe')
