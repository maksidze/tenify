from pathlib import Path
import json,hashlib,shutil
H=Path(__file__).resolve().parent;L=H.parent/'SettingsNoVfsSessionCompat';S=H.parent/'ShellAppearanceCompat';L.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
for n in ['SessionController.py','Lifecycle.py','ScopedRecovery.py','SessionEndObserver.py','SessionEntry.c','EntryGuard.h','HashCheck.h','SessionControl.c','SessionControl.exe','OwnBootstrap.py','PackageAccess.py']:
 shutil.copyfile(S/n,L/n)
for n in ['SessionController.py','Lifecycle.py']:
 p=L/n;t=p.read_text();t=t.replace('ShellAppearanceRestore_','SettingsSessionRestore_').replace('ShellAppearanceLifetime','Settings10ManualLauncher').replace('C:/Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy/ShellExperienceHost.exe','C:/Windows/ImmersiveControlPanel/SystemSettings.exe')
 t=t.replace('    from ExplorerOwner import capture\n    owner=capture(state)\n    if owner:close(owner)\n','').replace('    from ExplorerOwner import capture\n    shell=capture(state)\n','    shell=None\n').replace('        from ExplorerOwner import capture\n        shell=capture(state)\n','')
 t=t.replace(" or not __import__('ExplorerOwner').alive(state)",'').replace('    from ExplorerOwner import alive\n    return alive(state) and lease_active(state)','    return lease_active(state)').replace('  from ExplorerOwner import alive\n  if not alive(state):return False\n','')
 t=t.replace('SEH appearance','Settings NoVFS').replace('Native SEH','Native Settings')
 t=t.replace("state['Mode']='UntilStop'","state['Mode']='UntilStop';state['ModeUntilStop']=True")
 p.write_text(t,encoding='utf-8')
target=Path('C:/Windows/ImmersiveControlPanel/SystemSettings.exe')
wide=lambda p:'L"'+str(p).replace('\\','\\\\')+'"'
(L/'EntryPins.h').write_text('#define ENTRY_TARGET_PATH '+wide(target)+'\n#define ENTRY_TARGET_SHA "'+sha(target)+'"\n#define ENTRY_BROKER_SHA "'+sha('C:/Windows/System32/RuntimeBroker.exe')+'"\n#define ENTRY_PACKAGE L"windows.immersivecontrolpanel_10.0.8.1000_neutral_neutral_cw5n1h2txyewy"\n')
# Entry has six 64KB arrays; move storage off its primary stack entirely.
p=L/'SessionEntry.c';t=p.read_text().replace(' WCHAR exe[32768]',' static WCHAR exe[32768]');p.write_text(t)
