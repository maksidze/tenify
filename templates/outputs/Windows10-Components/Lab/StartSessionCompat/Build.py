"""Compile the private session files, never regenerate/mutate production adapters."""
from pathlib import Path
import subprocess,hashlib,json,os
H=Path(__file__).resolve().parent;B=H.parent.parent;R=B.parent.parent
zig=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'work/compat-research/zig-cache'))
commands=[['-Dwmain=BrokerExistingWmain',str(H/'StartSessionBackend.c'),str(H/'StartSessionEntry.c'),'-o',str(H/'Start10SessionDebugger.exe'),'-luser32','-ladvapi32','-lshell32'],[str(H/'SessionControl.c'),'-o',str(H/'SessionControl.exe'),'-lole32','-luuid','-lshell32'],[str(H/'SessionRepair.c'),'-o',str(H/'SessionRepair.exe'),'-lole32','-luuid','-lshell32','-ladvapi32']]
report=[]
for arguments in commands:
 p=subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-mwindows','-Wl,--subsystem,windows','-O1','-g',*arguments],env=env,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60)
 report.append(dict(Exit=p.returncode,Output=(p.stdout+p.stderr).decode(errors='replace')))
 if p.returncode:print(report[-1]['Output']);raise SystemExit(p.returncode)
(H/'build-report.json').write_text(json.dumps(report,indent=2))
files=list(H.glob('*.c'))+list(H.glob('*.h'))+list(H.glob('*.py'))+list(H.glob('*.ps1'))+list(H.glob('*.exe'))
start=B/'Lab/StartCompat'
files+=[start/n for n in ['wincorlib.dll','WinCorHost.dll','StartUI_.dll','StartCompat.ini','PackageDebugController.exe']]
files+=list(p for p in (start/'Resources').rglob('*') if p.is_file())
files+=[Path('C:/Windows/SystemApps/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/StartMenuExperienceHost.exe'),Path('C:/Windows/System32/wincorlib.dll'),B/'Launch-NonUiProcess.ps1',B/'Runtime/Explorer10/explorer.exe']
for p in H.glob('*.exe'):
 b=p.read_bytes();pe=int.from_bytes(b[0x3c:0x40],'little');assert int.from_bytes(b[pe+24+68:pe+24+70],'little')==2
manifest=dict(Mode='UntilStop after finite30second bootstrap; no periodic restart',LiveTestPerformed=False,Files=[dict(Path=str(p.resolve()),SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in dict.fromkeys(files)])
(H/'manifest.json').write_text(json.dumps(manifest,indent=2));print('Private GUI session helpers built; no registration or activation.')
