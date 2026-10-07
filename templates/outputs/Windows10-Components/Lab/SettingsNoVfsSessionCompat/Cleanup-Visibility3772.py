from pathlib import Path
import subprocess,json
L=Path(__file__).resolve().parent;z=L.parents[3]/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
p=subprocess.run([str(z),'cc','-target','x86_64-windows-gnu','-municode','-O2','-Wl,--subsystem,windows',str(L/'Resume-OwnedVisibility.c'),'-o',str(L/'Resume-OwnedVisibility.exe'),'-lshell32','-lbcrypt','-lpsapi'],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60)
if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
p=subprocess.run([str(L/'Resume-OwnedVisibility.exe')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=15);print((L/'visibility3772-resume-proof.json').read_text(encoding='utf-8-sig'));assert p.returncode==0
