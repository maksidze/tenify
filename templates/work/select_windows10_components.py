from pathlib import Path
import json,xml.etree.ElementTree as ET
base=Path('outputs/Windows10-Components');(base/'Metadata').mkdir(parents=True,exist_ok=True)
tree=ET.parse('work/wim-metadata/[1].xml')
images=[]
for image in tree.getroot().findall('IMAGE'):
 w=image.find('WINDOWS');v=w.find('VERSION')
 images.append({'index':int(image.attrib['INDEX']),'name':image.findtext('NAME'),'edition':w.findtext('EDITIONID'),'arch':w.findtext('ARCH'),'language':w.findtext('LANGUAGES/DEFAULT'),'build':'.'.join(v.findtext(x) for x in ['MAJOR','MINOR','BUILD','SPBUILD'])})
(base/'Metadata/images.json').write_text(json.dumps(images,indent=2,ensure_ascii=False),encoding='utf-8')
index=next(x['index'] for x in images if x['edition']=='Professional')
prefix=str(index)+'\\'
dirs=['Windows\\SystemApps\\','Windows\\SystemResources\\','Windows\\ImmersiveControlPanel\\','Windows\\ShellComponents\\','Windows\\Resources\\Themes\\','Windows\\Web\\','Program Files\\WindowsApps\\','Program Files\\Windows NT\\Accessories\\','Program Files\\Common Files\\microsoft shared\\ink\\']
dirs.extend(['Windows\\Fonts\\','Windows\\Cursors\\','Windows\\Media\\'])
names='''twinui.pcshell.dll twinui.dll twinui.appcore.dll windows.immersiveshell.serviceprovider.dll Windows.UI.Xaml.dll Windows.UI.Xaml.Controls.dll Windows.UI.Shell.dll Windows.Internal.ShellCommon.dll CoreUIComponents.dll CoreMessaging.dll Windows.UI.dll ExplorerFrame.dll DUI70.dll DUser.dll AppResolver.dll StartTileData.dll StartDocked.dll ShellExperienceHost.exe ShellHost.exe sihost.exe shellexperiencehost.exe RuntimeBroker.exe ApplicationFrameHost.exe ApplicationFrame.dll SearchUI.exe SearchApp.exe TextInputHost.exe InputApp.dll InputHost.dll Windows.UI.Input.Inking.dll Windows.UI.Core.TextInput.dll Windows.UI.Immersive.dll Windows.UI.AppDefaults.dll shell32.dll shlwapi.dll shcore.dll propsys.dll themeui.dll uxtheme.dll dwmapi.dll dwmcore.dll udwm.dll dxgi.dll dcomp.dll d2d1.dll dwrite.dll windowscodecs.dll ntmarta.dll shfolder.dll user32.dll win32u.dll combase.dll ole32.dll oleaut32.dll kernel32.dll kernelbase.dll ntdll.dll advapi32.dll MrmCoreR.dll Windows.StateRepository.dll Windows.StateRepositoryClient.dll StateRepository.Core.dll StateRepository.AppModel.dll Windows.ApplicationModel.dll Windows.ApplicationModel.Activation.dll Windows.Storage.dll Windows.Storage.ApplicationData.dll Windows.System.Launcher.dll Windows.System.UserProfile.dll Windows.Management.Deployment.dll Windows.Management.DeploymentClient.dll Windows.ApplicationModel.Store.dll Windows.ApplicationModel.Resources.dll windows.immersiveshell.serviceprovider.dll settingmonitor.dll SettingsEnvironment.Desktop.dll SettingsHandlers_DesktopTaskbar.dll systemsettingsadminflows.exe SystemSettingsBroker.exe SystemSettingsThresholdAdminFlow.exe control.exe desk.cpl main.cpl appwiz.cpl timedate.cpl intl.cpl mmsys.cpl sysdm.cpl ncpa.cpl powercfg.cpl hotplug.dll notepad.exe charmap.exe cleanmgr.exe regedit.exe mstsc.exe msconfig.exe taskmgr.exe calc.exe write.exe mspaint.exe sndvol.exe DisplaySwitch.exe StikyNot.exe wmplayer.exe OptionalFeatures.exe rundll32.exe dllhost.exe'''.split()
names={x.lower() for x in names}
names.update(['snippingtool.exe','photometadatahandler.dll','oskSupport.dll'.lower()])
names.update(x.lower() for x in '''mmc.exe mmc.exe.config mmcbase.dll mmcndmgr.dll mmcshext.dll devmgmt.msc devmgr.dll taskmgr.exe taskschd.msc taskschd.dll taskcomp.dll taskschdps.dll pdh.dll perflib.dll loadperf.dll perfproc.dll perfos.dll perfmon.exe perfmon.msc dxva2.dll devrtl.dll devobj.dll DeviceManager_Execute.dll devenum.dll devdispitemprovider.dll hotplug.dll hnetmon.dll netshell.dll display.dll deskadp.dll deskmon.dll ActionCenter.dll ActionCenterCPL.dll notificationplatformcomponent.dll NotificationController.dll NotificationControllerPS.dll PCShellCommonProxyStub.dll ShellCommonCommonProxyStub.dll CoreShell.dll CoreShellAPI.dll CoreShellExtFramework.dll ComposableShellProxyStub.dll ApplicationFrame.dll Microsoft-Windows-Internal-Shell-NearShareExperience.dll SharedExperienceHost.dll Windows.CloudStore.dll Windows.CloudStore.Schema.DesktopShell.dll Windows.CloudStore.Schema.Shell.dll Windows.CloudStore.Schema.ShellCommon.dll Windows.CloudStore.Schema.DesktopShell.Ext.dll InputSwitch.dll InputLocaleManager.dll TabTip.exe osk.exe magnify.exe Narrator.exe utilman.exe Windows.Media.SpeechSynthesis.dll Windows.ApplicationModel.Search.dll Windows.ApplicationModel.Contacts.dll Windows.ApplicationModel.Background.SystemEventsBroker.dll SearchFolder.dll SearchFilterHost.exe SearchProtocolHost.exe SearchIndexer.exe edputil.dll CredentialUIBroker.exe PickerHost.exe ShellAppRuntime.exe usercpl.dll sud.dll themecpl.dll immersive.dll ActXPrxy.dll'''.split())
selected=[];all_files=[];record={}
def accept(r):
 path=r.get('Path','')
 if not path.startswith(prefix) or r.get('Folder')=='+':return
 rel=path[len(prefix):];low=rel.lower();name=rel.rsplit('\\',1)[-1].lower()
 all_files.append(rel)
 match=any(low.startswith(d.lower()) for d in dirs)
 match |= low=='windows\\explorer.exe' or low in ['windows\\ru-ru\\explorer.exe.mui','windows\\en-us\\explorer.exe.mui','windows\\system32\\config\\software']
 if low.startswith('windows\\system32\\'):
  tail=low[len('windows\\system32\\'):]
  segments=tail.split('\\')
  families=('settingshandlers','windows.ui.','windows.internal.shell','windows.shell','windows.immersiveshell','windows.applicationmodel.','windows.cloudstore','shell','coreshell','input','twinui','notification','actioncenter','systemproperties')
  match |= len(segments)==1 and (name in names or (name.startswith(families) and name.endswith(('.dll','.exe'))))
  match |= len(segments)==2 and segments[0] in ('ru-ru','en-us') and (name.removesuffix('.mui') in names or name.startswith(families))
 if low=='windows\\regedit.exe':match=True
 if low.startswith('program files\\windowsapps\\'):
  match |= any(x in low for x in ['microsoft.windowscalculator_','microsoft.windows.photos_','microsoft.windowscamera_','microsoft.windowscommunicationsapps_','microsoft.microsoftstickyNotes_'.lower()])
 if match:selected.append({'archivePath':path,'path':rel,'size':int(r.get('Size') or 0),'wimSHA1':r.get('SHA-1'),'category':category(low)})
def category(low):
 if low.startswith(('windows\\fonts\\','windows\\cursors\\','windows\\media\\')):return 'FontsCursorsAndSounds'
 if low.startswith('windows\\systemapps\\'):return 'PackagedShellApps'
 if low.startswith('windows\\systemresources\\'):return 'SystemResources'
 if low.startswith('windows\\immersivecontrolpanel\\'):return 'SettingsApp'
 if low.startswith('windows\\shellcomponents\\'):return 'ShellComponents'
 if low.startswith('windows\\resources\\') or low.startswith('windows\\web\\'):return 'ThemesAndWallpapers'
 if low.endswith('\\config\\software'):return 'OfflineRegistryReference'
 if low.startswith('program files\\windowsapps\\'):return 'PackagedApps'
 if low in ['windows\\explorer.exe','windows\\ru-ru\\explorer.exe.mui','windows\\en-us\\explorer.exe.mui']:return 'Explorer'
 return 'LibraryAndClassicToolsReference'
with Path('work/windows10-wim-list.txt').open(encoding='utf-8-sig',errors='replace') as f:
 for line in f:
  line=line.rstrip('\n\r')
  if not line:
   accept(record);record={}
  elif ' = ' in line:
   k,v=line.split(' = ',1);record[k]=v
accept(record)
(base/'Metadata/selection.json').write_text(json.dumps(selected,indent=2,ensure_ascii=False),encoding='utf-8')
(base/'Metadata/image-paths.txt').write_text('\n'.join(all_files),encoding='utf-8')
(base/'Metadata/extract-list.txt').write_text('\n'.join(x['archivePath'] for x in selected),encoding='utf-8')
print(json.dumps({'index':index,'files':len(selected),'bytes':sum(x['size'] for x in selected),'categories':{c:sum(x['category']==c for x in selected) for c in sorted({x['category'] for x in selected})}},indent=2))
