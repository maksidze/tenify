from pathlib import Path
import subprocess,json
lab=Path(__file__).resolve().parent;root=lab.parents[3];src=lab/'PowerAdapterFixture.cs';s=src.read_text(encoding='utf-8-sig')
for n in ['64','0','1']:s=s.replace('return'+n+';','return '+n+';')
src.write_text(s)
csc=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe');exe=lab/'PowerAdapterFixture.exe';build=subprocess.run([str(csc),'/nologo','/target:winexe','/platform:x64','/out:'+str(exe),str(src)],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=20);(lab/'fixture-build.log').write_bytes(build.stdout+build.stderr)
if build.returncode:raise RuntimeError(build.stdout.decode(errors='replace'))
report={'ownChildOnly':True,'noUI':True,'noSetters':True}
with (lab/'fixture.stdout').open('wb') as so,(lab/'fixture.stderr').open('wb') as se:
 child=subprocess.Popen([str(exe),str(lab/'own-adapter-fixture.log'),str(lab/'SettingsPowerCompat.dll'),str(root/'outputs/Windows10-Components/Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'),'normal'],stdout=so,stderr=se,creationflags=subprocess.CREATE_NO_WINDOW);report['pid']=child.pid
 try:report['exitCode']=child.wait(timeout=25);report['timedOut']=False
 except subprocess.TimeoutExpired:child.kill();child.wait();report.update(exitCode=child.returncode,timedOut=True)
(lab/'own-adapter-fixture.json').write_text(json.dumps(report,indent=2));print(report)
