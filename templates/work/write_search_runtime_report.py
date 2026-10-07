from pathlib import Path
import json,hashlib

root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
run=lab/'runtime-router-49996854eb0a4fc491e196020c03b55e'
state=json.loads((run/'state.json').read_text())
assert state['phase']=='factoriesObserved' and state['backgroundObservationCompleted']
assert state['cleanupComplete'] and state['ownedChildTerminated']
assert not state['ApplicationStartExecuted']
assert not state.get('accessViolations') and not state.get('stowedExceptions')
keys=['router','perfRouter','enableRouter','configurationRouter','settingsRouter','featureRouter','authRouter','headerRouter','projectedRouter']
classes=['Cortana.Telemetry.TelemetryUtils','Cortana.Internal.Search.PerfMetrics','Cortana.Settings.EnableChecker','Cortana.Settings.ConfigurationManager','Cortana.Settings.SettingsContainer','Cortana.Settings.FeatureConfiguration','Cortana.Authentication.UserAuthenticationManager','Cortana.Internal.Search.HeaderHelpers','Cortana.Internal.Search.ProjectedCortanaAPI']
routes=[]
for key,name in zip(keys,classes):
    result=state[key]
    assert result['attempts'] and result['factoryHR']=='0x0' and result['queryHR']=='0x0'
    assert result['requestedIID'] in result['factoryIIDs']
    routes.append({'class':name,**result})
report={'status':'PASS: own hidden child CRT/factories only','testState':str(run/'state.json'),'childPID':state['childPid'],'scope':'No Application.Start, no visible Search UI, no live SearchHost changes','packageIdentity':state['packageFullName'],'backgroundObservationSeconds':8,'entryRVA':'0xc8dc0','mainPauseRVA':'0x7d11c','exeFactoryIatRVA':'0x295ec8','searchApiFactoryIatRVA':'0x520288','searchCoreRoGetFactoryIatRVA':'0x4f4d0','searchCoreRoActivateIatRVA':'0x4f4c8','routes':routes,'exeFactories':state['factories'],'remaining':['Application.Start and actual UI have not been tested.','Old AppCacheMetadata files are looked up relative to current CBS package; old layout/PRI mapping needed.','Background authentication/location task logs access denied and E_NOINTERFACE; handled during this bounded observation.','Ordinary old runtime initialization may create its own HKCU/AppData values under inherited CBS identity; no package or COM registration changed.'],'cleanupComplete':True,'fileSHA256':{name:hashlib.sha256((lab/name).read_bytes()).hexdigest() for name in ['SearchRuntimeRouter.c','SearchRuntimeRouter.dll','Probe-SearchRuntimeRouter.py']}}
(lab/'runtime-router-report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print('Saved validated nine-class report:',lab/'runtime-router-report.json')
