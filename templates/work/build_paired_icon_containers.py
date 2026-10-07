from pathlib import Path
import json,hashlib
LAB=Path("outputs/Windows10-Components/Lab/FolderIconCompat").resolve();BASE=LAB.parents[1];ROOT=LAB.parents[3];routeLab=LAB/"ResourceRoutesNoVfs";routeLab.mkdir(parents=True,exist_ok=True)
original=BASE/"Lab/IconResourceMaximum"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
records=json.loads((original/'manifest.json').read_text())['Records'];routes={};missing=[];pairProof=[]
resourceNs={'__file__':str(original/'Build.py')};exec((original/'Build.py').read_text().split('inventory=json.loads')[0],resourceNs)
readResources=resourceNs['resources'];serialize=resourceNs['serialize']
storage=Path('C:/Windows/System32/windows.storage.dll');pe=resourceNs['pefile'].PE(str(storage));code=pe.get_data(0x257930,32)
(routeLab/'CacheKeyPins.h').write_text('#define STORAGE_SHA '+json.dumps(sha(storage))+'\nstatic const unsigned char locationBytes[]={'+','.join(str(x)for x in code)+'};\n')
for r in records:
 assert sha(r['Host'])==r['HostSHA256'] and sha(r['Private'])==r['PrivateSHA256']
 host=Path(r['Host']);private=Path(r['Private']);routes[str(host).lower()]=(host,private)
 if r['Mode']=='DataOnlyMUNVFS':
  name=host.name[:-4];paired=Path('C:/Windows/System32')/name
  if not paired.exists():paired=Path('C:/Windows')/name
  if paired.exists():
   # Preserve paired DLL's own non-icon resources as well as MUN resources.
   # The container stays data-only; no executable code is mapped from it.
   try:own=readResources(paired)
   except (KeyError,IndexError,AttributeError):own={}
   merged=readResources(private);combined=dict(merged);preserved={key:value for key,value in own.items()if key[0]not in (3,14)}
   collision=sum(key in merged and merged[key]!=value for key,value in preserved.items())
   combined.update(preserved)
   absentIcons={key:value for key,value in own.items()if key[0]in (3,14)and key not in merged};combined.update(absentIcons)
   pairedPrivate=routeLab/'PairedContainers'/(paired.name+'.mun')
   serialize(private,pairedPrivate,combined)
   actual=readResources(pairedPrivate);assert all(actual[key]==value for key,value in preserved.items())
   assert all(actual[key]==value for key,value in merged.items()if key[0]in(3,14))
   pairProof.append(dict(Host=str(paired),Container=str(pairedPrivate),NativeNonIconResourcesPreserved=len(preserved),NativeNonIconCollisions=collision,AllMergedIconResourcesPreserved=True))
   routes[str(paired).lower()]=(paired,pairedPrivate)
  else:missing.append(name)
