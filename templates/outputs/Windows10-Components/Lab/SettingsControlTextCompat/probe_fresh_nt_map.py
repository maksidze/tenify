from pathlib import Path
import subprocess,json
H=Path(__file__).resolve().parent;B=H.parent.parent;csc=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe');exe=H/'NtMapProbe.exe'
c=subprocess.run([str(csc),'/nologo','/target:winexe','/platform:x64','/out:'+str(exe),str(H/'NtMapProbe.cs')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=30);(H/'ntmap-build.log').write_bytes(c.stdout+c.stderr);c.check_returncode()
with subprocess.Popen([str(exe),str(H/'fresh-nt-map.log'),str(B/'Image/4/Windows/SystemResources/Windows.UI.SettingsHandlers-nt/Windows.UI.SettingsHandlers-nt.pri')],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
 try:o,e=child.communicate(timeout=20);timeout=False
 except subprocess.TimeoutExpired:child.kill();o,e=child.communicate(timeout=5);timeout=True
 report=dict(pid=child.pid,exit=child.returncode,timeout=timeout,ownFreshResourceManager=True,noSettingsActivation=True)
(H/'fresh-nt-map-proof.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
