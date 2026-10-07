"""Actual isolated USVFS mappings, own non-UI child only, no package activation."""
from pathlib import Path
import argparse,ctypes as C,json,subprocess,sys,uuid,time,hashlib
HERE=Path(__file__).resolve().parent;BASE=HERE.parent.parent
ap=argparse.ArgumentParser();ap.add_argument('--label',required=True);ap.add_argument('--mode',choices=['normal','bad-byte'],default='normal');a=ap.parse_args()
label=a.label; mode=a.mode
controller=BASE/'Probe-USVFS.py'
source=controller.read_text(encoding='utf-8-sig').split('\ntry:\n params=')[0]
sys.argv=[str(controller),'--preset','selftest'];ns={'__file__':str(controller)};exec(source,ns)
params=None;connected=False;pi=ns['PI']();desk=None
output=HERE/('vfs-'+label+'.log');dll=HERE/'SettingsCaptionCompat.dll';exe=HERE/'VfsBootstrapProof.exe'
cmd=[r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe','/nologo','/target:winexe','/platform:x64','/out:'+str(exe),str(HERE/'VfsBootstrapProof.cs')]
r=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=30)
if r.returncode:raise RuntimeError(r.stdout.decode(errors='replace'))
report={'Mode':mode,'DllSHA256':hashlib.sha256(dll.read_bytes()).hexdigest(),'NoSettingsPackageActivation':True,'ActualUSVFS':True,'CreationFlags':'CREATE_NO_WINDOW','AllOwnChildrenExited':False}
try:
 params=ns['parametersCreate']();ns['setName'](params,('CaptionFixture_'+uuid.uuid4().hex).encode());ns['setDebug'](params,False);ns['setLog'](params,1)
 assert ns['connect'](params);connected=True
 for name in ['explorer.exe','SystemSettings.exe','RuntimeBroker.exe','StartMenuExperienceHost.exe','ShellExperienceHost.exe','powershell.exe','cmd.exe']:ns['blacklist'](name)
 old=BASE/'Image/4/Windows/ImmersiveControlPanel';native=Path('C:/Windows/ImmersiveControlPanel')
 for name in ['SystemSettings.dll','SystemSettingsViewModel.Desktop.dll','Telemetry.Common.dll','resources.pri']:ns['mapFile'](old/name,native/name)
 for name in ['Assets','pris','ru-RU']:ns['mapDirectory'](old/name,native/name)
 ns['mapDirectory'](BASE/'Image/4/Windows/SystemResources/Windows.UI.SettingsAppThreshold',Path('C:/Windows/SystemResources/Windows.UI.SettingsAppThreshold'))
 name='CaptionOwn_'+uuid.uuid4().hex;desk=ns['desktopCreate'](name,None,None,0,0x1ff,None);assert desk
 si=ns['SI']();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+name
 command=subprocess.list2cmdline([str(exe),str(output),str(dll),str(old/'SystemSettingsViewModel.Desktop.dll'),mode])
 assert ns['create'](str(exe),C.create_unicode_buffer(command),None,None,False,0x08000000,None,str(HERE),C.byref(si),C.byref(pi))
 report['PID']=pi.pid
 if ns['wait'](pi.process,25000)!=0:raise TimeoutError('Own VFS child timed out')
 exitcode=ns['D']();assert ns['exitCode'](pi.process,C.byref(exitcode));report['ExitCode']=exitcode.value
 report['Output']=output.read_text(encoding='utf-8')
 logs=[];buffer=C.create_string_buffer(8192)
 while ns['getLog'](buffer,len(buffer),False):logs.append(buffer.value.decode(errors='replace'))
 (HERE/('vfs-'+label+'-usvfs.log')).write_text('\n'.join(logs),encoding='utf-8')
finally:
 if pi.process:
  if ns['wait'](pi.process,0)!=0:ns['term'](pi.process,0xdeca);ns['wait'](pi.process,5000)
  ns['close'](pi.process)
 if pi.thread:ns['close'](pi.thread)
 if connected:ns['disconnect']()
 if params:ns['parametersFree'](params)
 if desk:ns['desktopClose'](desk)
 report['AllOwnChildrenExited']=True
 (HERE/('vfs-'+label+'.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
