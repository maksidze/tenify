"""Rebuild the lab router. Does not regenerate controllers or start any process under test."""
from pathlib import Path
import hashlib,json,os,subprocess

root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
source=lab/'SearchRuntimeRouter.c'
output=lab/'SearchRuntimeRouter.dll'
environment=os.environ.copy()
environment['ZIG_GLOBAL_CACHE_DIR']=str(root/'work/compat-research/zig-cache')
command=[str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O1','-g',str(source),'-o',str(output)]
subprocess.run(command,env=environment,cwd=root,check=True)
record={'command':command,'controller':'Probe-SearchRuntimeRouter.py','testLauncher':'work/Test-SearchRuntimeRouter.ps1','sourceSHA256':hashlib.sha256(source.read_bytes()).hexdigest(),'dllSHA256':hashlib.sha256(output.read_bytes()).hexdigest(),'controllerRegenerated':False,'systemFilesModified':False}
(lab/'runtime-router-build.json').write_text(json.dumps(record,indent=2),encoding='utf8')
print(json.dumps(record,indent=2))
