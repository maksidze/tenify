from pathlib import Path
import shutil,subprocess,json,hashlib
base=Path('outputs/Windows10-Components').resolve();lab=base/'Lab/FlyoutCompat';lab.mkdir(parents=True,exist_ok=True)
pkg=base/'Image/4/Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy'
runtime=lab/'Runtime';runtime.mkdir(exist_ok=True)
inputs=[]
for p in pkg.iterdir():
 if p.is_file() and (p.suffix.lower() in ['.dll','.exe','.pri','.xml']):
  shutil.copy2(p,runtime/p.name);inputs.append({'source':str(p),'target':str(runtime/p.name),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
for name in ['wincorlib.dll','WinCorHost.dll']:
 shutil.copy2(base/'Lab/StartCompat'/name,runtime/name)
# Compatibility exports only. The Start-specific redirect is explicitly disabled.
(runtime/'StartCompat.ini').write_text('[Options]\nEnable=0\n')
s=(base/'Lab/StartCompat/StartCompatProbe.c').read_text()
old='HRESULT app=testFactory(get,L"StartUI.App",&giApp,FALSE);'
start=s.index(old)
s=s[:start]+'''const wchar_t *name=argc>4?argv[4]:L"ActionCenter.App";
 HRESULT app=testFactory(get,name,&giActivationFactory,argc>5&&!wcscmp(argv[5],L"--activate"));
 logline("SUMMARY class=%ls factory=%08lx resources=%08lx",name,app,resources);fclose(logFile);
 return FAILED(app)?4:0;
}
'''
s=s.replace('StartCompatProbe PID=','FlyoutCompatProbe PID=')
# Preserve the finalized generic probe, including native wincorlib preloading,
# metadata QI inspection and converter tests. Initial staging alone generates it.
if not (runtime/'FlyoutCompatProbe.c').exists():
 (runtime/'FlyoutCompatProbe.c').write_text(s)
zig=Path('work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe').resolve()
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(runtime/'FlyoutCompatProbe.c'),'-o',str(runtime/'FlyoutCompatProbe.exe')]
subprocess.run(cmd,check=True)
(lab/'staging.json').write_text(json.dumps({'systemFilesModified':False,'packageRegistrationChanged':False,'inputs':inputs,'command':cmd},indent=2))
print('Staged',len(inputs),'files, compiled generic DllGetActivationFactory own probe')
