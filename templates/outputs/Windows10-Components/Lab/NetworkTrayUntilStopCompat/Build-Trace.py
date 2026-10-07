import subprocess,json
from pathlib import Path
lab=Path(__file__).resolve().parent;root=lab.parents[3];zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-Wl,--subsystem,windows',str(lab/'NetworkTrayTrace.c'),'-o',str(lab/'NetworkTrayTrace.exe'),'-lole32','-luuid','-lshell32','-luser32','-ladvapi32','-lbcrypt'];p=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True);assert p.returncode==0,p.stderr;print('Own process trace host built; no runtime started')
