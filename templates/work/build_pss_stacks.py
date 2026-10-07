from pathlib import Path
import hashlib, json, os, subprocess
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/ThreadStackSnapshot'
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(root/'work/compat-research/zig-cache'))
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-O1','-fno-omit-frame-pointer','-municode',str(lab/'PssStacks.c'),'-ldbghelp','-lpsapi','-o',str(lab/'PssStacks.exe')],env=env,check=True)
manifest={name:hashlib.sha256((lab/name).read_bytes()).hexdigest() for name in ['PssStacks.c','PssStacks.exe']}
(lab/'build.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print(json.dumps(manifest))
