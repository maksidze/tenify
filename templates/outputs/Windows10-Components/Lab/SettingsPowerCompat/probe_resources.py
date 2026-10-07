from pathlib import Path
import subprocess,json,hashlib
HERE=Path(__file__).resolve().parent;BASE=HERE.parent.parent
CSC=Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe');GAC=Path(r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL')
refs=[Path('C:/Windows/System32/WinMetadata')/(x+'.winmd') for x in ['Windows.ApplicationModel','Windows.Foundation','Windows.Storage']]+[CSC.parent/'System.Runtime.WindowsRuntime.dll',next((GAC/'System.Runtime').rglob('*.dll')),next((GAC/'System.Runtime.InteropServices.WindowsRuntime').rglob('*.dll'))]
source=HERE/'ControlResourceProbe.cs';exe=HERE/'ControlResourceProbe.exe'
compile=subprocess.run([str(CSC),'/nologo','/target:winexe','/platform:x64','/out:'+str(exe)]+['/r:'+str(p) for p in refs]+[str(source)],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=30)
(HERE/'build.log').write_bytes(compile.stdout+compile.stderr)
if compile.returncode:raise RuntimeError(compile.stdout.decode(errors='replace'))
pri=BASE/'Image/4/Windows/SystemResources/Windows.UI.SettingsAppThreshold/Windows.UI.SettingsAppThreshold.pri'
report=[]
for mode in ['native','old']:
 directory=HERE/mode;directory.mkdir(exist_ok=True)
 with subprocess.Popen([str(exe),str(directory/'resources.log'),mode,str(pri),str(directory)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
  try:out,err=child.communicate(timeout=30);timed=False
  except subprocess.TimeoutExpired:child.kill();out,err=child.communicate(timeout=5);timed=True
  report.append(dict(Mode=mode,PID=child.pid,ExitCode=child.returncode,TimedOut=timed,NoSettingsActivation=True))
(HERE/'resource-proof.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
