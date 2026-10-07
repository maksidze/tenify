from pathlib import Path
import subprocess,os,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(R/'work/compat-research/zig-cache');zig=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(zig),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-municode','-Wl,--subsystem,windows',str(H/'BrowserProbe.cpp'),'-o',str(H/'BrowserProbe.exe'),'-lole32','-luuid','-luser32','-lshell32','-luxtheme','-lbcrypt','-lgdi32']
p=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90);(H/'build.txt').write_text(p.stdout+p.stderr);print('compile',p.returncode)
if p.returncode:print(p.stderr);raise SystemExit(p.returncode)
folder=H/'OwnFolder';folder.mkdir(exist_ok=True);(folder/'fixture.txt').write_text('Read-only ExplorerBrowser item fixture.\n')
old=B/'Image/4/Windows/Resources/Themes/aero/aero.msstyles';results=[]
for mode in ['native','native-loaded','old','scoped']:
 log=H/(mode+'.txt')
 p=subprocess.Popen([str(H/'BrowserProbe.exe'),str(log),mode,str(folder),str(Path('C:/Windows/Resources/Themes/aero/aero.msstyles') if mode=='native-loaded' else old)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
 try:out,err=p.communicate(timeout=22);killed=False
 except subprocess.TimeoutExpired:p.kill();out,err=p.communicate(timeout=5);killed=True
 text=log.read_text(errors='replace') if log.exists()else'';print(mode,'pid',p.pid,'exit',p.returncode,'killed',killed);print(text)
 results.append(dict(mode=mode,pid=p.pid,exit=p.returncode,killed=killed,transcript=text,stderr=err.decode(errors='replace')))
checks=[]
for r in results:
 text=r['transcript'];mode=r['mode'];okay=not r['killed'] and 'desktopCloseAfterThreadExit=1' in text
 if mode=='old':okay=okay and r['exit']==1 and 'BrowseToIDList=80004005' in text and 'OnNavigationFailed=80004005' in text
 else:okay=okay and r['exit']==0 and 'itemCount=1' in text and 'folderMatched=1' in text
 if mode=='scoped':okay=okay and 'currentUnchangedAfterLoad=1' in text and 'currentUnchangedAfterClose=1' in text and 'oldDataSameFile=1' in text
 checks.append(dict(mode=mode,expectedResultVerified=okay))
proof={'results':results,'checks':checks,'pass':all(x['expectedResultVerified']for x in checks),'Files':{n:hashlib.sha256((H/n).read_bytes()).hexdigest()for n in ['BrowserProbe.cpp','HashCheck.hpp','ScopedTheme.hpp','BrowserProbe.exe','build_run.py']},'NoInteractiveDesktopOrInput':True}
(H/'own-proof.json').write_text(json.dumps(proof,indent=2))
print('matrix_pass',proof['pass'])
raise SystemExit(0 if proof['pass'] else 1)
