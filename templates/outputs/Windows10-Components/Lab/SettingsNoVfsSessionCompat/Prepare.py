"""Prepare immutable Settings session only: no registration or activation."""
from pathlib import Path
import json,hashlib,uuid,ctypes as C
LAB=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def prepare(diagnostic=False,xaml_factory=None):
 if xaml_factory is None:xaml_factory=not diagnostic
 manifest=json.loads((LAB/'manifest.json').read_text())
 for f in manifest['Files']:
  if sha(f['Path'])!=f['SHA256']:raise RuntimeError('Manifest changed '+f['Path'])
 nonce=uuid.uuid4().hex;directory=LAB/'sessions'/nonce;directory.mkdir(parents=True)
 from PackageAccess import grant_private_runtime
 acl=grant_private_runtime(directory,'windows.immersivecontrolpanel_cw5n1h2txyewy')
 birth=C.c_ulonglong();C.WinDLL('kernel32').GetSystemTimeAsFileTime(C.byref(birth))
 target='C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe'
 state=dict(Nonce=nonce,Directory=str(directory),NativePath=target,NativeSHA256=sha(target),PackageFullName='windows.immersivecontrolpanel_10.0.8.1000_neutral_neutral_cw5n1h2txyewy',PackageFamilyName='windows.immersivecontrolpanel_cw5n1h2txyewy',CancelFile=str(directory/'cancel'),Seconds=90,ConfigName='s_'+nonce+'.ini',StartBirth=birth.value,DebuggerCommand=str(LAB/'SettingsNoVfsEntry.exe')+' --session s_'+nonce+'.ini',Files=manifest['Files'],RuntimeAclVerified=True,ACL=acl,PreparedOnly=True,ActualActivationPerformed=False,ModeUntilStop=True,ContentCompat=True,NavigationCompat=True,NoVFS=True,Bootstrap=str(LAB.parent/'SettingsContentCompat/SettingsContentCompat.dll'))
 if diagnostic or xaml_factory:
  d=LAB.parent/('SettingsNoVfsXamlCompat' if xaml_factory else 'SettingsNoVfsDiagnostics');dm=json.loads((d/'manifest.json').read_text());state['Files']+=dm['Files'];state['RouteScript']=str(d/'Launch-SettingsNoVfs.py');state['DiagnosticOnly']=not xaml_factory;state['XamlFactory']=xaml_factory
  state['CurrentProfileFiles']=dm['Files'];state['CurrentProfileManifest']=str(d/'manifest.json')
  profile=json.loads((d/'adapter-metadata.json').read_text());state['FactorySelector']=profile['Selector'];state['FactorySelectorSHA256']=profile['SelectorSHA256']
  for f in dm['Files']:
   if sha(f['Path'])!=f['SHA256']:raise RuntimeError('Diagnostic profile changed')
 p=directory/'prepared.json';p.write_text(json.dumps(state,indent=2),encoding='utf-8');return p
if __name__=='__main__':print(prepare('--diagnostic' in __import__('sys').argv,not ('--diagnostic' in __import__('sys').argv)))
