"""Own non-UI ResourceMap read-only caption probe; never activates Settings."""
import hashlib,json,pathlib,subprocess
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[3]
CSC=pathlib.Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')
GAC=pathlib.Path(r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL')
refs=[pathlib.Path(r'C:\Windows\System32\WinMetadata\Windows.ApplicationModel.winmd'),pathlib.Path(r'C:\Windows\System32\WinMetadata\Windows.Foundation.winmd'),CSC.parent/'System.Runtime.WindowsRuntime.dll',next((GAC/'System.Runtime').rglob('*.dll')),next((GAC/'System.Runtime.InteropServices.WindowsRuntime').rglob('*.dll'))]
source=HERE/'SettingsCaptionProbe.cs';exe=HERE/'SettingsCaptionProbe.exe'
cmd=[str(CSC),'/nologo','/target:winexe','/out:'+str(exe)]+['/r:'+str(x) for x in refs]+[str(source)]
build=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=40)
(HERE/'compiler.stdout').write_bytes(build.stdout);(HERE/'compiler.stderr').write_bytes(build.stderr)
if build.returncode:raise RuntimeError(build.stdout.decode(errors='replace')+build.stderr.decode(errors='replace'))
pri=ROOT/'outputs/Windows10-Components/Image/4/Windows/SystemResources/Windows.UI.SettingsAppThreshold/Windows.UI.SettingsAppThreshold.pri'
report={'scope':'own nonUI process only; read-only ResourceMap; no Settings activation, VFS or registry changes','exeSHA256':hashlib.sha256(exe.read_bytes()).hexdigest(),'sourceSHA256':hashlib.sha256(source.read_bytes()).hexdigest(),'oldPri':str(pri),'runs':[]}
for mode in ('native','old'):
 args=[str(exe),str(HERE/(mode+'.log')),mode]+([str(pri)] if mode=='old' else [])
 with subprocess.Popen(args,creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
  row={'mode':mode,'pid':child.pid,'creationFlags':'CREATE_NO_WINDOW','image':str(exe)}
  try:out,err=child.communicate(timeout=25);row['timedOut']=False
  except subprocess.TimeoutExpired:child.kill();out,err=child.communicate(timeout=5);row['timedOut']=True
  row['exitCode']=child.returncode;report['runs'].append(row)
  (HERE/(mode+'.stdout')).write_bytes(out);(HERE/(mode+'.stderr')).write_bytes(err)
(HERE/'own-caption-proof.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report))
