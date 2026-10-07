from pathlib import Path
import sys,os,json,shutil,subprocess,hashlib
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'work/pylib'))
import pefile
out=root/'outputs/Windows10-Components/Lab/StartCompat';out.mkdir(exist_ok=True)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
image=root/'outputs/Windows10-Components/Image/4'
ui=image/'Windows/SystemApps/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/StartUI.dll'
cor=Path('C:/Windows/System32/wincorlib.dll')
pri=image/'Windows/SystemResources/Windows.UI.ShellCommon/Windows.UI.ShellCommon.pri'
shutil.copy2(cor,out/'WinCorHost.dll');shutil.copy2(ui,out/'StartUI_.dll')
shutil.copy2(pri,out/'Windows.UI.ShellCommon.pri')
resourceFolder=out/'Resources/Windows.UI.ShellCommon'
shutil.copytree(pri.parent,resourceFolder,dirs_exist_ok=True)
(out/'StartCompat.ini').write_text('[Options]\nEnable=1\n[Paths]\nStartUI='+str(out/'StartUI_.dll')+'\nShellCommonPri='+str(resourceFolder/'Windows.UI.ShellCommon.pri')+'\n',encoding='utf-16')
pe=pefile.PE(str(cor));lines=['LIBRARY wincorlib','EXPORTS']
hooks={'?GetActivationFactoryByPCWSTR@@YAJPEAXAEAVGuid@Platform@@PEAPEAX@Z':'StartCompatGetFactory','?GetCmdArguments@Details@Platform@@YAPEAPEA_WPEAH@Z':'StartCompatGetArguments'}
for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
 assert s.name,'Review anonymous export before forwarding'
 name=s.name.decode();target=hooks.get(name,'WinCorHost.'+name)
 lines.append('"'+name+'" = "'+target+'" @'+str(s.ordinal))
(out/'StartCompatProxy.def').write_text('\n'.join(lines)+'\n')
env=dict(os.environ);env['ZIG_GLOBAL_CACHE_DIR']=str(root/'work/compat-research/zig-cache')
commands=[
 [str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(out/'StartCompatProbe.c'),'-o',str(out/'StartCompatProbe.exe')],
 [str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(out/'StartCompatHostProbe.c'),'-o',str(out/'StartCompatHostProbe.exe'),'-luser32','-ladvapi32'],
 [str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(out/'PackageDebugController.c'),'-o',str(out/'PackageDebugController.exe'),'-lole32','-luuid'],
 [str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O1','-g',str(out/'StartCompatProxy.c'),str(out/'StartCompatProxy.def'),'-o',str(out/'wincorlib.dll')]
]
for command in commands:subprocess.run(command,check=True,env=env)
new=pefile.PE(str(out/'wincorlib.dll'));exports={s.name.decode():s for s in new.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
 name=symbol.name.decode();assert name in exports
 if name not in hooks:assert exports[name].forwarder.decode()=='WinCorHost.'+name
def info(path):return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':path.stat().st_size}
report={'status':'Built and export-validated; proxy activation and packaged host startup require own-child runtime tests','compiler':str(zig),'commands':commands,'originalWincorlibExports':len(pe.DIRECTORY_ENTRY_EXPORT.symbols),'proxyExports':len(exports),'inputs':[info(ui),info(cor),info(pri)],'outputs':[info(out/n) for n in ['StartUI_.dll','WinCorHost.dll','wincorlib.dll','StartCompatProbe.exe']],'enableEnvironment':'W10_STARTCOMPAT_ENABLE=1','diskPatchedMicrosoftExecutables':False,'systemFilesModified':False}
(out/'build-info.json').write_text(json.dumps(report,indent=2))
print(json.dumps({k:v for k,v in report.items() if k not in ['commands','inputs','outputs']},indent=2))
