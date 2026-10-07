from pathlib import Path
import subprocess,json,hashlib
LAB=Path(__file__).resolve().parent;ROOT=LAB.parents[3];BASE=LAB.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for source,dest in [(BASE/'WindowStyle/WindowStyle.ps1',LAB/'Library.ps1'),(BASE/'Launch-NonUiProcess.ps1',LAB/'Launch-NonUiProcess.ps1'),(BASE/'NonUiProcess.cs',LAB/'NonUiProcess.cs')]:dest.write_bytes(source.read_bytes())
for name in ['Controller.ps1','Common.ps1','ElevatedCorners.ps1']:
 p=LAB/name;s=p.read_text(encoding='utf-8-sig');p.write_text(s,encoding='utf-8-sig')
guard={k:sha(LAB/n) for k,n in [('CONTROLLER_SHA','Controller.ps1'),('COMMON_SHA','Common.ps1'),('LIBRARY_SHA','Library.ps1'),('ACCESS_SHA','Access.cs'),('LAUNCHER_SHA','Launch-NonUiProcess.ps1'),('NONUI_SHA','NonUiProcess.cs')]}
(LAB/'Guard.h').write_text(''.join('#define '+k+' '+json.dumps(v)+'\n' for k,v in guard.items()),encoding='utf-8')
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O2',str(LAB/'Host.c'),'-o',str(LAB/'ElevatedCornerHost.exe'),'-Wl,--subsystem,windows','-luser32','-lshell32','-ladvapi32','-lbcrypt'],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60,check=True)
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O2',str(BASE/'Lab/WindowStyleSession/CornerFixture.c'),'-o',str(LAB/'ElevatedCornerFixture.exe'),'-Wl,--subsystem,windows','-luser32','-ldwmapi'],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60,check=True)
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O2',str(LAB/'MutexFixture.c'),'-o',str(LAB/'MutexFixture.exe'),'-Wl,--subsystem,windows','-luser32','-lshell32'],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=60,check=True)
files=[p for p in LAB.iterdir() if p.is_file() and p.suffix in ['.ps1','.cs','.c','.h','.exe']]
manifest=dict(Format=1,Source='Private elevated-only companion; no deployment',Files=[dict(Path=str(p),SHA256=sha(p)) for p in files],HighOnly=True,SystemFilesModified=False)
(LAB/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8');print(json.dumps(dict(HostSHA256=sha(LAB/'ElevatedCornerHost.exe'),Files=len(files)),indent=2))
