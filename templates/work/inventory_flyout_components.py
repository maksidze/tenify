from pathlib import Path
import re,json,hashlib,sys,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';lab=base/'Lab/FlyoutCompat';image=base/'Image/4'
sys.path.insert(0,str(root/'work/pylib'));import pefile
def digest(p,alg='sha256'):return hashlib.new(alg,p.read_bytes()).hexdigest()
def version(p):
 try:
  pe=pefile.PE(str(p),fast_load=True);pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]);v=pe.VS_FIXEDFILEINFO[0]
  return '.'.join(str(n) for n in [v.FileVersionMS>>16,v.FileVersionMS&65535,v.FileVersionLS>>16,v.FileVersionLS&65535])
 except Exception:return None
def classmap(p):
 result={}
 for s in ET.parse(p).getroot().iter():
  if s.tag.endswith('InProcessServer'):
   path=next((x.text for x in s if x.tag.endswith('Path')),'')
   for x in s:
    if x.tag.endswith('ActivatableClass'):result[x.attrib['ActivatableClassId']]=path
 return result
oldclasses=classmap(lab/'Runtime/AppxManifest.xml');nativeclasses=classmap(Path('C:/Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy/AppxManifest.xml'))
classdiff={'oldOnly':{k:v for k,v in oldclasses.items() if k not in nativeclasses},'nativeOnly':{k:v for k,v in nativeclasses.items() if k not in oldclasses},'relocated':{k:{'old':v,'native':nativeclasses[k]} for k,v in oldclasses.items() if k in nativeclasses and v!=nativeclasses[k]}}
(lab/'package-class-differences.json').write_text(json.dumps(classdiff,indent=2))
log=(lab/'broker-flyout-5aba9b4b6005.log').read_text();paths=list(dict.fromkeys(re.findall(r'^DLL base=[0-9A-F]+ path=\\\\\?\\(.+)$',log,re.M)))
uiwords=['actioncenter','quickaction','clockflyout','batteryflyout','networkux','devicesflow','immersive','shell.shared','xaml','mtcuvc','resources.pri','uimanager','coremessaging','inputhost']
rows=[]
for ptext in paths:
 p=Path(ptext);row={'loadedPath':ptext,'file':p.name,'version':version(p),'sha256':digest(p) if p.is_file() else None,'uiFocus':any(w in p.name.lower() for w in uiwords),'Windows10Private':str(lab/'Runtime').lower() in ptext.lower()}
 if p.name.lower()=='windows.ui.quickactions.dll':old=lab/'StagedSystem/QuickActions.dll'
 elif p.name.lower()=='networkux.dll':old=lab/'StagedSystem/NetworkUX.dll'
 elif p.name.lower()=='windows.ui.shell.sharedutilities.dll':old=lab/'StagedSystem'/p.name
 else:
  relative=ptext[3:] if ptext.lower().startswith('c:\\') else ''
  old=image/relative if relative else lab/'Runtime'/p.name
 if old.is_file():row.update(oldCandidate=str(old),oldVersion=version(old),oldSha256=digest(old))
 rows.append(row)
report={'trial':'state/broker-4c636df2e21b.json','evidence':'broker-flyout-5aba9b4b6005.log','startupStableOnly':True,'manualNotificationUIUnverified':True,'loadedModules':rows,'resourceNote':'Native resource PRI paths are virtualized to old package/System ShellCommon; exact native file hashes remain unchanged. ResourceManager old preload S_OK; candidate selection/UI still unverified.'}
(lab/'trial5-loaded-components.json').write_text(json.dumps(report,indent=2))
# Verify freshly extracted files against exact WIM record length + SHA1.
targets={'4\\Windows\\ShellExperiences\\QuickActions.dll':lab/'StagedSystem/QuickActions.dll','4\\Windows\\ShellExperiences\\NetworkUX.dll':lab/'StagedSystem/NetworkUX.dll','4\\Windows\\System32\\ShellExperiences\\Windows.UI.Shell.SharedUtilities.dll':lab/'StagedSystem/Windows.UI.Shell.SharedUtilities.dll'}
records={};record={}
with (root/'work/windows10-wim-list.txt').open(encoding='utf-8-sig') as f:
 for line in f:
  line=line.rstrip('\r\n')
  if not line:
   if record.get('Path') in targets:records[record['Path']]=record
   record={}
  elif ' = ' in line:k,v=line.split(' = ',1);record[k]=v
verify=[]
for path,p in targets.items():
 r=records[path];actual=digest(p,'sha1');expected=r.get('SHA-1',r.get('SHA1'))
 verify.append({'wimPath':path,'extracted':str(p),'size':p.stat().st_size,'expectedSize':r['Size'],'sha1':actual,'wimSha1':expected,'verified':p.stat().st_size==int(r['Size']) and actual.lower()==expected.lower()})
assert all(x['verified'] for x in verify),verify
(lab/'staged-system-wim-verification.json').write_text(json.dumps(verify,indent=2))
host=Path('C:/Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy')
mappings=[]
for name in ['ClockFlyoutExperience.dll','BatteryFlyoutExperience.dll']:
 src=lab/'Runtime'/name;dst=host/name
 mappings.append({'Kind':'File','Source':str(src),'Destination':str(dst),'SourceSha256':digest(src),'NativeSha256':digest(dst),'FactoryOnlyProof':True,'RealAppContainerPreflightPending':True})
profile={'Name':'clock-battery-candidate','Experimental':True,'PreparedOnly':True,'BaseProfile':'trial5 ActionCenter+RefinedConverter+oldPRI+lifetimeMTA','Mappings':mappings,'ClassCoverage':'Old common App/MainPage/metadata factories S_OK; metadata instances and exact custom/public IIDs match. Native extra ClockFlyout.Models/Utilities/ViewModels classes absent from old DLL. No UI instance constructed.','NotMapped':{'QuickActions':'Old DLL cannot provide native QuickActions.App or QuickActions.ControlCenter.ControlCenterView (80040111).','NetworkUX':'Old VPNUXViewProvider absent (80040111); provider ABI not verified.','Immersive':'No exact factory/COM ABI proof; keep native.','SharedUtilities':'No exact factory/interface proof; keep native.','Xaml':'Native framework remains; keep native.'},'CalendarLimitation':'Old ActionCenter.dll lacks ActionCenter.ClockCalendarView. Separate old ClockFlyoutExperience DLL does not satisfy that factory class. Notification/calendar composition needs explicit route/ABI adapter, not class aliasing.'}
(lab/'clock-battery-candidate.profile.json').write_text(json.dumps(profile,indent=2))
print('Modules',len(rows),'WIM verified',len(verify))
for x in rows:
 if x['uiFocus']:print(x['file'],x['version'],'old' if x['Windows10Private'] else 'native',x.get('oldVersion','no extracted candidate'))
