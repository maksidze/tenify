from pathlib import Path
import json
root=Path(__file__).resolve().parent.parent
p=root/'outputs/Windows10-Components/Settings10-State.txt'
s=p.read_text(encoding='utf-8-sig')
s=s.replace('A genuine old SystemSettings DLL ran for the controlled 60-second trial and created a visible CoreWindow inside the native ApplicationFrameHost window. Contents and settings operations have not been reviewed.','User confirmed the visible Windows 10 Settings interface in actual test16b40c5c5f60, PID11948. Physical old SystemSettings.dll and initializer S_OK were verified; debugger detached. Known issue: repeated About captions (О системе), although the page contents differ. Caption/resource mapping is suspected, not proven. All sections and settings operations remain unverified.')
s=s.replace('actual detached Settings awaits review.','actual detached Settings visible UI was confirmed by the user. The future persistent normal-activation route is not part of checkpoint b001.')
s+='\nCurrent visible UI evidence: Lab/SettingsBrokerCompat/visible-ui-confirmed-16b40c5c5f60.json. Settings is optional and excluded from the default Maximum launcher.\n'
p.write_text(s,encoding='utf-8-sig')
p=root/'work/settings-userlaunch-current-state.json'
d=json.loads(p.read_text(encoding='utf-8-sig'))
d['actualChildUI']={'ownPID':11948,'test':'16b40c5c5f60','visibleUIUserConfirmed':True,'physicalOldDLLVerified':True,'initializerHRESULT':'00000000','debuggerDetached':True,'reviewedFunctionality':False,'knownIssue':'Repeated О системе captions with different page contents; cause not proven.'}
d['manualLaunch']['actualDetachedSettingsTest']='User confirmed visible Windows10 Settings UI, test16b40c5c5f60/PID11948. All sections unverified; optional bounded launch.'
d['checkpointExclusions']=['Future persistent SettingsSessionCompat mode']
p.write_text(json.dumps(d,ensure_ascii=False,indent=2),encoding='utf8')
