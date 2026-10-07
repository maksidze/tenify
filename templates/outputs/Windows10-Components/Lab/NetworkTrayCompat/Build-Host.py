import subprocess,hashlib,json,sys
from pathlib import Path
lab=Path(__file__).resolve().parent;root=lab.parents[3];zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-Wl,--subsystem,windows',str(lab/'NetworkTrayHost.c'),'-o',str(lab/'NetworkTrayHost.exe'),'-lole32','-luuid','-lshell32','-luser32']
p=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True);assert p.returncode==0,p.stderr
p=subprocess.run([str(lab/'NetworkTrayHost.exe'),str(lab/'host-factory-proof.log'),str(lab/'pnidui.dll')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=13);assert p.returncode==0,p.stderr
files=[f for f in lab.iterdir() if f.is_file() and f.suffix in ['.py','.c','.exe','.dll','.ps1']]+list(lab.glob('*/*.mui'))+[lab.parent/'DisplayMonitorPublisher/PublisherJobGuard.cs']
(lab/'manifest.json').write_text(json.dumps(dict(Files=[dict(Path=str(p.resolve()),SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in files],PniduiVersion='10.0.19041.4355',ProvenStartTested=False),indent=2));(lab/'host-own-proof.json').write_text(json.dumps(dict(ExitCode=p.returncode,StartNotCalled=True,Subsystem2=True,Log=(lab/'host-factory-proof.log').read_text()),indent=2));print((lab/'host-factory-proof.log').read_text())
