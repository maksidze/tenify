from pathlib import Path
import subprocess,os,json,hashlib
LAB=Path(__file__).resolve().parent;ROOT=LAB.parents[3];env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'work/compat-research/zig-cache')
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
p=subprocess.run([str(zig),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-municode','-Wl,--subsystem,windows',str(LAB/'UnitFixture.cpp'),'-o',str(LAB/'UnitFixture.exe'),'-luser32','-luxtheme','-lbcrypt','-lpsapi'],capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90)
(LAB/'unit-build.txt').write_text(p.stdout+p.stderr)
if p.returncode:print(p.stderr);raise SystemExit(p.returncode)
results=[]
for mode in ['native','wrong-byte','normal','generation']:
 log=LAB/('unit-'+mode+'.txt');p=subprocess.Popen([str(LAB/'UnitFixture.exe'),str(log),mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
 try:out,err=p.communicate(timeout=22);killed=False
 except subprocess.TimeoutExpired:p.kill();out,err=p.communicate(timeout=4);killed=True
 text=log.read_text(errors='replace')if log.exists()else'';results.append(dict(mode=mode,pid=p.pid,exit=p.returncode,killed=killed,log=text,stderr=err.decode(errors='replace')));print(mode,p.pid,p.returncode,killed);print(text)
passed=all(r['exit']==0 and not r['killed'] and 'FAIL' not in r['log'] and 'COMPLETE=0' in r['log']for r in results)
(LAB/'unit-proof.json').write_text(json.dumps(dict(Pass=passed,Scope='classifier white-box with genuine native queries; separate actual production DLL popup proof is required',Files={x:hashlib.sha256((LAB/x).read_bytes()).hexdigest()for x in ['ThemeMenu.cpp','UnitFixture.cpp','UnitFixture.exe','Pins.h']},Results=results),indent=2));raise SystemExit(0 if passed else 1)
