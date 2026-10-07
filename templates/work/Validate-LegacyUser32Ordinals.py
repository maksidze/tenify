"""Record semantic entry-point audit; does not invoke any private USER32 API."""
from pathlib import Path
import hashlib,json,sys
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';sys.path.insert(0,str(root/'work/pylib'))
import pefile
source=base/'Lab/FlyoutCompat/OrdinalAudit/loaded-old-user32-ordinals.json'
audit=json.loads(source.read_text(encoding='utf8'))
host=Path('C:/Windows/System32/user32.dll');old=base/'Image/4/Windows/System32/user32.dll'
for folder,path in [('old-user32',old),('host-user32',host)]:
    metadata=json.loads((root/'work/compat-research'/folder/'symbols.json').read_text(encoding='utf8'))
    assert metadata['pdbMatch'] and metadata['sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
native=pefile.PE(str(host));exports={e.ordinal:e for e in native.DIRECTORY_ENTRY_EXPORT.symbols}
named={e.name.decode():e for e in exports.values() if e.name}
result=[]
for row in audit['ordinalMappings']:
    ordinal=row['oldOrdinal'];matches=row['exactHostExportCandidates'];decision=None
    if len(matches)==1:
        match=matches[0];target=exports[match['ordinal']]
        assert target.address==int(match['rva'],16)
        decision={'kind':'matching-public-PDB-symbol','nativeOrdinal':target.ordinal,'nativeRva':hex(target.address),'symbol':match['matchedSymbol']}
    elif ordinal==2521:
        target=named['GetProcessUIContextInformation']
        assert target.ordinal==2521 and target.address==0x73370
        decision={'kind':'matching-PE-export-name','nativeOrdinal':target.ordinal,'nativeRva':hex(target.address),'symbol':'GetProcessUIContextInformation'}
    elif ordinal==2511:
        target=exports[2511];assert target.address==0x93c30
        # Matched old/native PCShell public symbols identify the same wrapper and
        # its argument forwarding, return-type and error handling. No call here.
        decision={'kind':'replacement-used-by-native-wrapper','nativeOrdinal':2511,'nativeRva':hex(target.address),'symbol':'SetShellSpecialWindow','proof':{'oldPCShellWrapper':'CPrivilegedDesktopOperations::SetFallbackForeground','oldRva':'0x29e1e0','nativeRva':'0x3ea020','oldCallRva':'0x29e23b','nativeCallRva':'0x3ea043','arguments':'HWND, DWORD flags','return':'BOOL with GetLastError on FALSE'}}
    elif ordinal==2542:
        decision={'kind':'removed-API-ordinal-reused','symbol':'NtUserRegisterShellPTPListener','hostDifferentOperation':'SetCoveredWindowStates','action':'must not forward; existing ComponentEnabled=0 path can be used only for explicit no-touchpad profile'}
    elif ordinal in range(2628,2633):
        decision={'kind':'removed-WindowGroup-operation','symbol':row['oldNames'][0],'action':'existing BOOL FALSE/ERROR_NOT_SUPPORTED adapter'}
    else:raise RuntimeError('Unclassified legacy ordinal '+str(ordinal))
    result.append({'oldOrdinal':ordinal,'oldNames':row['oldNames'],'decision':decision,'uses':row['uses']})
report={'sourceAuditSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'hostUser32Sha256':hashlib.sha256(host.read_bytes()).hexdigest(),'oldUser32Sha256':hashlib.sha256(old.read_bytes()).hexdigest(),'distinctOrdinals':len(result),'uses':sum(len(r['uses']) for r in result),'classification':result,'scope':'Actual legacy run f917b22fe7ea4468866915f04bb96405 only; private argument layouts beyond these callsites are not generally proven','entryPointsCalled':False,'filesModified':False}
folder=base/'Lab/User32OrdinalCompat';folder.mkdir(exist_ok=True);(folder/'validated-ordinal-contracts.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({'distinctOrdinals':len(result),'uses':report['uses'],'mapped':sum('nativeOrdinal' in r['decision'] for r in result),'changedSemanticOrdinal':[r['oldOrdinal'] for r in result if r['decision']['kind']=='removed-API-ordinal-reused'],'report':str(folder/'validated-ordinal-contracts.json')}))
