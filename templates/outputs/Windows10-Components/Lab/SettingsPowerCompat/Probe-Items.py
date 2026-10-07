from pathlib import Path
import subprocess,json
lab=Path(__file__).resolve().parent
src=lab/'ItemProbe.cs';s=src.read_text(encoding='utf-8-sig').replace('"SystemSettings_PowerAndSleep_DisplayOffTimeoutDC"','"SystemSettings_PowerAndSleep_DisplayOffTimeoutDC","SystemSettings_Taskbar_Lock","SystemSettings_Taskbar_Autohide","SystemSettings_Taskbar_SmallButtons","SystemSettings_Taskbar_Badging","SystemSettings_Taskbar_Location"');src.write_text(s,encoding='utf8')
csc=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe');exe=lab/'ItemProbe.exe';p=subprocess.run([str(csc),'/nologo','/target:winexe','/platform:x64','/out:'+str(exe),str(src)],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=20);(lab/'item-build.log').write_bytes(p.stdout+p.stderr)
if p.returncode:raise RuntimeError(p.stdout.decode(errors='replace'))
rows=[]
for name,dll,rva in [('native','C:/Windows/System32/SystemSettings.DataModel.dll','19d00'),('old',str(lab.parents[3]/'work/settings-datamodel-image/4/Windows/System32/SystemSettings.DataModel.dll'),'3f880')]:
 with (lab/(name+'-item.stdout')).open('wb') as so,(lab/(name+'-item.stderr')).open('wb') as se:
  child=subprocess.Popen([str(exe),str(lab/(name+'-items.log')),dll,rva],stdout=so,stderr=se,creationflags=subprocess.CREATE_NO_WINDOW)
  try:code=child.wait(timeout=20);timed=False
  except subprocess.TimeoutExpired:child.kill();child.wait();code=child.returncode;timed=True
 rows.append({'mode':name,'pid':child.pid,'exitCode':code,'timedOut':timed,'noSettingsActivation':True,'noSetters':True})
(lab/'own-items-proof.json').write_text(json.dumps(rows,indent=2));print(rows)
