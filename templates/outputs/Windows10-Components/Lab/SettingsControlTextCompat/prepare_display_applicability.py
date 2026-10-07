from pathlib import Path
import re,json,subprocess
H=Path(__file__).resolve().parent;C=H.parent/'SettingsCaptionCompat'
s=(C/'SettingsApplicabilityProbe.cs').read_text();ids=[i for i in json.loads((H/'old/013-PCSystemDisplayPageViewModel.strings.json').read_text()) if i.startswith('SettingsGroup')]
s=re.sub(r'static readonly string\[\] ids=\{.*?\};','static readonly string[] ids={'+','.join(json.dumps(i) for i in ids)+'};',s)
(H/'DisplayApplicabilityProbe.cs').write_text(s)
csc=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe');exe=H/'DisplayApplicabilityProbe.exe'
c=subprocess.run([str(csc),'/nologo','/target:winexe','/platform:x64','/out:'+str(exe),str(H/'DisplayApplicabilityProbe.cs')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=30);(H/'display-policy-build.log').write_bytes(c.stdout+c.stderr);c.check_returncode()
report=[]
for label,mode,path,rva in [('native','public',Path('C:/Windows/System32/SystemSettings.DataModel.dll'),'16450'),('old','private',H.parent/'SettingsDynamicTextCompat/IsolatedOld/SettingsEnvironment.Desktop.dll','9f10')]:
 with subprocess.Popen([str(exe),str(H/(label+'-display-applicable.log')),mode,str(path),rva],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
  try:o,e=child.communicate(timeout=20);timeout=False
  except subprocess.TimeoutExpired:child.kill();o,e=child.communicate(timeout=5);timeout=True
  report.append(dict(mode=label,pid=child.pid,exit=child.returncode,timeout=timeout,noSettingsActivation=True))
(H/'display-applicability-proof.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
