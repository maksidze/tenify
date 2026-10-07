import hashlib,json,pathlib,subprocess,sys
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parents[3]
source=HERE/'SettingsApplicabilityProbe.cs';exe=HERE/'SettingsApplicabilityProbe.exe'
cmd=[r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe','/nologo','/target:winexe','/out:'+str(exe),str(source)]
r=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=40)
(HERE/'applicability-compiler.stdout').write_bytes(r.stdout);(HERE/'applicability-compiler.stderr').write_bytes(r.stderr)
if r.returncode:raise RuntimeError(r.stdout.decode(errors='replace'))
cases=[('old-private','private',ROOT/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsEnvironment.Desktop.dll','9f10','49fbf0c1d93064813895c88da75efbaee2054394b1c1ee32612f51e712c01a4b'),('native-private','private',pathlib.Path(r'C:\Windows\System32\SettingsEnvironment.Desktop.dll'),'1cf00',None),('native-public','public',pathlib.Path(r'C:\Windows\System32\SystemSettings.DataModel.dll'),'16450','f07bdc1334562d4ae3d5265e96cf44b8bfbde8388fd71e76cb698cc475703fbb')]
if '--old-isolated' in sys.argv:
 cases=[('old-isolated','private',ROOT/'outputs/Windows10-Components/Lab/SettingsDynamicTextCompat/IsolatedOld/SettingsEnvironment.Desktop.dll','9f10','49fbf0c1d93064813895c88da75efbaee2054394b1c1ee32612f51e712c01a4b')]
result={'scope':'own non-UI MTA read-only applicability calls; no Settings activation/registry writes/injection','runs':[]}
for label,kind,dll,rva,expected in cases:
 sha=hashlib.sha256(dll.read_bytes()).hexdigest()
 if expected and sha!=expected:raise RuntimeError('Hash mismatch: '+str(dll))
 with subprocess.Popen([str(exe),str(HERE/(label+'.log')),kind,str(dll),rva],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
  row={'label':label,'dll':str(dll),'sha256':sha,'pid':child.pid,'methodRva':rva,'creationFlags':'CREATE_NO_WINDOW'}
  try:out,err=child.communicate(timeout=20);row['timedOut']=False
  except subprocess.TimeoutExpired:child.kill();out,err=child.communicate(timeout=5);row['timedOut']=True
  row['exitCode']=child.returncode;result['runs'].append(row)
  (HERE/(label+'.stdout')).write_bytes(out);(HERE/(label+'.stderr')).write_bytes(err)
(HERE/('own-applicability-oldisolated-proof.json' if '--old-isolated' in sys.argv else 'own-applicability-proof.json')).write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result))
