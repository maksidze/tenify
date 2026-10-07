import subprocess,json,hashlib,sys
from pathlib import Path
lab=Path(__file__).resolve().parent;root=lab.parents[3];zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-Wl,--subsystem,windows',str(lab/'NetworkTrayUntilStop.c'),'-o',str(lab/'NetworkTrayUntilStop.exe'),'-lole32','-luuid','-lshell32','-luser32','-lbcrypt','-lgdi32','-ladvapi32']
p=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True);assert p.returncode==0,p.stderr
p=subprocess.run([str(lab/'NetworkTrayUntilStop.exe'),str(lab/'factory-own-proof.log'),str(lab.parent/'NetworkTrayCompat/pnidui.dll')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=13);assert p.returncode==0,p.stderr
files=[p for p in lab.iterdir() if p.suffix in ['.ps1','.c','.h','.py','.exe']]+[lab.parent/'NetworkTrayCompat/NetworkFactoryProbe.c',lab.parent/'NetworkTrayCompat/pnidui.dll',lab.parent/'NetworkTrayCompat/ru-RU/pnidui.dll.mui',lab.parent/'DisplayMonitorPublisher/PublisherJobGuard.cs']
files += [lab.parent/'NetworkTrayVisibilityCompat'/name for name in ['Visibility.c','Visibility.exe','Set-NetworkVisibility.ps1','manifest.json']]
(lab/'manifest.json').write_text(json.dumps(dict(Files=[dict(Path=str(p.resolve()),SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in files]),indent=2))
print('Separate UntilStop GUI compiled, ownfactoryonly PASS; actual Start not called.')
