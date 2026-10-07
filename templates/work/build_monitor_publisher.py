from pathlib import Path
import subprocess,os,json,hashlib
root=Path(__file__).resolve().parents[1];lab=root/'outputs/Windows10-Components/Lab/DisplayMonitorPublisher';zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-O1','-g','-municode',str(lab/'MonitorPublisher.c'),'-o',str(lab/'MonitorPublisher.exe'),'-lshell32','-lole32','-luser32']
r=subprocess.run(cmd,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW,env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(root/'work/compat-research/zig-cache')),timeout=90)
if r.returncode:raise RuntimeError(r.stderr)
mp=lab/'manifest.json';m=json.loads(mp.read_text(encoding='utf-8-sig'));m['Files']=[dict(Path=x['Path'],Sha256=hashlib.sha256(Path(x['Path']).read_bytes()).hexdigest()) for x in m['Files']];m['MaximumSeconds']=3600;m['DefaultSeconds']=3600;m['NativeTargetExitWait']='WaitForSingleObject(target,500), immediate wake on exact target exit';mp.write_text(json.dumps(m,indent=2),encoding='utf8')
print('Rebuilt publisher with 3600-second cap/default and refreshed full provenance manifest; no helper launch')
