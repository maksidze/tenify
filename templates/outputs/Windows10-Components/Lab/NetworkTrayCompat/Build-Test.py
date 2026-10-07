import subprocess,hashlib,json,sys
from pathlib import Path
lab=Path(__file__).resolve().parent;root=lab.parents[3];zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-mwindows','-Wl,--subsystem,windows',str(lab/'NetworkFactoryProbe.c'),'-o',str(lab/'NetworkFactoryProbe.exe'),'-lole32','-luuid','-lshell32','-luser32']
p=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True);(lab/'build.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr
p=subprocess.run([str(lab/'NetworkFactoryProbe.exe'),str(lab/'factory-own-proof.log'),str(lab/'pnidui.dll')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=13)
(lab/'factory-own-proof.json').write_text(json.dumps(dict(ExitCode=p.returncode,NoStartOrStop=True,NoRegistryWrites=True,NoShellProcessTouched=True,Log=(lab/'factory-own-proof.log').read_text()),indent=2));print((lab/'factory-own-proof.log').read_text());assert p.returncode==0
