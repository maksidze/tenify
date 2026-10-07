"""Pure artifact verification; no processes or UI are activated."""
from pathlib import Path
import hashlib,json
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1];OWN=BASE/'Lab/FolderIconCompat'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
manifest=json.loads((LAB/'manifest.json').read_text());proof=json.loads((LAB/'own-proof.json').read_text())
assert proof['Passed'] and all(proof['Checks'].values())
assert sha(manifest['Helper'])==proof['DLLSHA']
for path,value in manifest['Dependencies'].items():assert sha(path)==value,path
for name in ['FolderCacheProbe.cpp','FolderCacheProbe.exe']:
 manifest['Dependencies'][str(OWN/name)]=sha(OWN/name)
manifest['OwnNumericIconRoutesPainted']=sum(row['type']=='extract' for row in proof['Results'][0]['Report'])
manifest['NamedOnlyRoutesNotPainted']=manifest['RouteCount']-manifest['OwnNumericIconRoutesPainted']
manifest['CacheKeyContract']=dict(Module='C:\\Windows\\System32\\windows.storage.dll',SHA256=sha('C:/Windows/System32/windows.storage.dll'),VTableRva=0x652538,Slot=3,SlotRva=0x652550,OriginalFunctionRva=0x257930,ScopedIndices=[-3,-4],ScopedResource='C:\\Windows\\System32\\imageres.dll')
manifest['OwnFixtureHashes']={str(OWN/'FolderCacheProbe.exe'):sha(OWN/'FolderCacheProbe.exe'),str(LAB/'RouteProof.exe'):sha(LAB/'RouteProof.exe')}
manifest['Files']={str(p.relative_to(LAB)):sha(p)for p in LAB.iterdir()if p.is_file()and p.name not in ['manifest.json','build.txt','seed-routes.json']and not p.name.endswith(('.stdout.txt','.stderr.txt'))}
(LAB/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(dict(DLLSHA=proof['DLLSHA'],ManifestSHA=sha(LAB/'manifest.json'),OwnProofPassed=True,Routes=manifest['RouteCount'],Painted=manifest['OwnNumericIconRoutesPainted'])))
