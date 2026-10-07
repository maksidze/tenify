from pathlib import Path
import os,subprocess,hashlib,json,shutil
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent;zig=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe';dll=H/'SettingsControlTextCompat.dll'
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'work/compat-research/zig-cache'))
build=subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O2',str(H/'SettingsControlTextCompat.c'),'-o',str(dll),'-lole32','-lbcrypt','-luuid'],env=env,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=90)
(H/'adapter-build.stdout').write_bytes(build.stdout);(H/'adapter-build.stderr').write_bytes(build.stderr);build.check_returncode()
exe=H/'ControlTextFixture.exe';csc=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
c=subprocess.run([str(csc),'/nologo','/target:winexe','/platform:x64','/out:'+str(exe),str(H/'ControlTextFixture.cs')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=30);(H/'fixture-build.log').write_bytes(c.stdout+c.stderr);c.check_returncode()
bad=H/'missing-dependency';bad.mkdir(exist_ok=True);shutil.copy2(dll,bad/dll.name)
report=[]
for mode in ['mta','sta','bad-guard','missing-dependency']:
 helper=(bad/dll.name) if mode=='missing-dependency' else dll
 with subprocess.Popen([str(exe),str(H/('fixture-'+mode+'.log')),str(helper),str(B/'Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'),mode],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
  try:o,e=child.communicate(timeout=30);timed=False
  except subprocess.TimeoutExpired:child.kill();o,e=child.communicate(timeout=5);timed=True
  report.append(dict(mode=mode,pid=child.pid,exit=child.returncode,timedOut=timed,createNoWindow=True))
(H/'own-adapter-proof.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
if any(row['exit']!=0 or row['timedOut'] for row in report):raise SystemExit(1)
