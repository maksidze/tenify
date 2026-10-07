from pathlib import Path
import subprocess,sys,os,json,hashlib
LAB=Path(__file__).resolve().parent;ROOT=LAB.parents[3]
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'work/compat-research/zig-cache')
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90)
 with (LAB/'build.txt').open('a')as f:f.write(p.stdout+p.stderr+'\n')
 if p.returncode:print(p.stderr);raise SystemExit(p.returncode)
run([sys.executable,str(LAB/'GeneratePins.py')])
run([str(zig),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-shared',str(LAB/'ThemeMenu.cpp'),'-o',str(LAB/'ThemeMenuCompat.dll'),'-luser32','-luxtheme','-lbcrypt','-lpsapi'])
c=json.loads((LAB/'contract.json').read_text())
files={n:hashlib.sha256((LAB/n).read_bytes()).hexdigest()for n in ['ThemeMenu.cpp','ThemeMenuCompat.dll','Pins.h','GeneratePins.py','Build.py']}
c['Dependencies'][str(LAB.parent/'Theme10BrowserProbe/HashCheck.hpp')]=hashlib.sha256((LAB.parent/'Theme10BrowserProbe/HashCheck.hpp').read_bytes()).hexdigest()
manifest=dict(Version=1,ProductionLiveTested=False,OwnProofPassed=False,InitializeExport='ThemeMenuInitialize',FixtureInitializeExport='ThemeMenuFixtureInitialize',RestoreExport='ThemeMenuRestore',StateExport='ThemeMenuState',StateVersion=1,StateSize=160,CallRowSize=56,CallCount=17,IatCount=0,ThunkBytes='48b8<TargetQWORD>ffe0',Files=files,**c)
(LAB/'manifest.json').write_text(json.dumps(manifest,indent=2));print('built',files['ThemeMenuCompat.dll'])
