from pathlib import Path
import subprocess,hashlib,json
lab=Path(__file__).resolve().parent;root=lab.parents[3]
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
for sources,name,flags in [(['ClassicContextMenu.c'],'ClassicContextMenu.dll',['-shared','-lbcrypt']),(['Probe.c'],'ClassicMenuProbe.exe',['-municode','-mwindows','-Wl,--subsystem,windows','-lole32','-lshell32','-luuid','-luser32'])]:
 p=subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-O2']+[str(lab/n) for n in sources]+['-o',str(lab/name)]+flags,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True)
 if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
files=[lab/n for n in ['ClassicContextMenu.c','ClassicContextMenu.dll','Probe.c','ClassicMenuProbe.exe','Build.py']]+[Path('C:/Windows/System32/shell32.dll'),lab.parent/'SettingsContentCompat/HashCheck.h']
(lab/'manifest.json').write_text(json.dumps(dict(Scope='Private Explorer memory: one guarded CDefView Mode=Classic path',Rva=0x2b2362,Original='39b424c00500000f85f8000000',Replacement='4489bc24c0050000e9f8000000',Files=[dict(Path=str(p),SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in files]),indent=2))
(lab/'ProbeFolder').mkdir(exist_ok=True)
(lab/'ProbeFolder/probe.txt').write_text('Owned harmless menu fixture.\n')
print('Classic context adapter and own isolated browser probe built')
