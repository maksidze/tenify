import json,hashlib,subprocess
from pathlib import Path
lab=Path(__file__).resolve().parent
root=lab.parents[3]
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
exe=lab/'ChainProbe.exe'
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-mwindows','-Wl,--subsystem,windows',str(lab/'ChainProbe.c'),'-o',str(exe),'-lole32','-lshell32']
r=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60)
if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace'))
with subprocess.Popen([str(exe),str(lab/'chain.log'),str(lab/'SettingsContentCompat.dll')],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as p:
    proof={'Scope':'Own GUI-subsystem child; real COM/providers and three old VM patches; no real Settings activation','Pid':p.pid,'TimedOut':False}
    try:out,err=p.communicate(timeout=30)
    except subprocess.TimeoutExpired:p.kill();out,err=p.communicate(timeout=5);proof['TimedOut']=True
    proof['ExitCode']=p.returncode
proof['Log']=(lab/'chain.log').read_text(errors='replace')
proof['DLL_SHA256']=hashlib.sha256((lab/'SettingsContentCompat.dll').read_bytes()).hexdigest()
(lab/'chain-proof.json').write_text(json.dumps(proof,indent=2))
print(json.dumps(proof))
if proof['TimedOut'] or proof['ExitCode'] or 'COMPLETE' not in proof['Log']:raise SystemExit(1)
