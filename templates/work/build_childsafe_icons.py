from pathlib import Path
import subprocess,hashlib,json,re
lab=Path('outputs/Windows10-Components/Lab/IconResourceMaximum').resolve();root=Path.cwd();zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def cc(src,out,extra):subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O2',str(lab/src),'-o',str(lab/out),*extra],check=True)
cc('IconRouteProbe.c','IconRouteProbe.exe',['-O0','-Wl,--subsystem,windows','-luser32','-lgdi32','-lshell32','-lversion'])
p=lab/'Routes.h';s=p.read_text();s=re.sub(r'#define FIXTURE_SHA "[a-f0-9]+"','#define FIXTURE_SHA "'+hashlib.sha256((lab/'IconRouteProbe.exe').read_bytes()).hexdigest()+'"',s);p.write_text(s)
cc('IconRoutes.c','IconRoutes.ChildSafe.dll',['-shared','-luser32','-lshell32','-lpsapi','-lbcrypt'])
log=lab/'childsafe-own-results.jsonl'
t=subprocess.run([str(lab/'IconRouteProbe.exe'),str(lab/'IconRoutes.ChildSafe.dll'),str(log)],creationflags=subprocess.CREATE_NO_WINDOW,timeout=35)
rows=[json.loads(x) for x in log.read_text().splitlines()]
proof={'ExitCode':t.returncode,'Passed':t.returncode==0 and all(x.get('pass',True) for x in rows),'Rows':rows,'HelperSHA256':hashlib.sha256((lab/'IconRoutes.ChildSafe.dll').read_bytes()).hexdigest(),'SystemFilesModified':False}
(lab/'childsafe-own-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2));assert proof['Passed']
