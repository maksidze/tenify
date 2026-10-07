from pathlib import Path
import json,hashlib
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
run=lab/'container-own-b2ed47c5cfcd4cc78c760af9b80b6889'
state=json.loads((run/'state.json').read_text())
supervisor=json.loads((run/'supervisor.json').read_text())
build=json.loads((lab/'container-build.json').read_text())
events=[json.loads(line) for line in (run/'container-events.jsonl').read_text().splitlines()]
by_name={event['event']:event for event in events}
assert state['finalExitCode']=='0x0' and state['cleanupComplete'] and state['ownedChildTerminated']
assert supervisor['controller']['exitCode']=='0x0' and supervisor['child']['exitCode']=='0x0'
assert not state.get('failures')
assert not supervisor['inventoryChanges']['disappeared'] and not supervisor['inventoryChanges']['appeared']
assert not supervisor['registryDiff']['changes']
assert by_name['loaderImports']['total']==459==by_name['loaderImports']['resolvedImageTargets']
assert by_name['loaderRelocations']['passed']==1
assert by_name['originalCRTReachedMain']['crtState']==2
assert by_name['complete']['factories']==4 and by_name['complete']['queriedInterfaces']==4
assert by_name['complete']['mainUIExecuted'] is False
tls=[x for x in events if x['event']=='staticTLS']
assert len(tls)==2 and tls[0]['storage']!=tls[1]['storage'] and tls[0]['index']==tls[1]['index']
assert all(int(x['storage'],16)!=0 for x in tls)
assert build['tlsCallbacks']==[]
factories=[x for x in events if x['event'] in ['oldExeFactory','factoryGetIids','factoryQI']]
assert all(x['hr']=='00000000' for x in factories)
report={'status':'PASS','scope':'Own hidden ordinary test EXE only; no main UI and no genuine broker UI tested','run':str(run),'build':build,'normalLoaderCall':by_name['normalLoadLibraryReturned'],'loaderDebugEventPathAvailable':False,'normalLoaderImports':by_name['loaderImports'],'normalLoaderRelocations':by_name['loaderRelocations'],'staticTLS':tls,'tlsCallbacks':[],'tlsExplanation':'Original TLS callback array is empty. The Windows loader assigned a static TLS index and distinct storage for each thread; no callback invocation is claimed.','originalCRT':by_name['originalCRTReachedMain'],'factories':factories,'backgroundObservation':by_name['backgroundObservationBegin'],'completion':by_name['complete'],'registryChanges':supervisor['registryDiff']['changes'],'nativeProcessChanges':supervisor['inventoryChanges'],'cleanup':{'childExitCode':state['finalExitCode'],'controllerExitCode':supervisor['controller']['exitCode'],'allChildThreadsEndedWithProcess':True,'supervisorFinished':supervisor['finished']},'sourceHashes':{name:hashlib.sha256((lab/name).read_bytes()).hexdigest() for name in ['SearchContainerProbe.c','Probe-SearchContainer.py','Supervise-SearchRuntime.py','SearchRuntimeRouter.c']}}
(lab/'container-proof-report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print('Saved container proof PASS:',lab/'container-proof-report.json')
