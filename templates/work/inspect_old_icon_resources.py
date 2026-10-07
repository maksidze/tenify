from pathlib import Path
import sys,json,hashlib
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'));import pefile
out={}
for n in ['shell32.dll.mun','imageres.dll.mun']:
 d={}
 for label,base in [('old',root/'outputs/Windows10-Components/Image/4/Windows/SystemResources'),('host',Path('C:/Windows/SystemResources'))]:
  p=base/n;pe=pefile.PE(str(p));groups={}
  for typ in pe.DIRECTORY_ENTRY_RESOURCE.entries:
   if typ.id!=14:continue
   for e in typ.directory.entries:
    ds=[]
    for lang in e.directory.entries:
     v=lang.data.struct;b=pe.get_data(v.OffsetToData,v.Size);ds.append({'lang':lang.id,'size':v.Size,'sha256':hashlib.sha256(b).hexdigest()})
    groups[str(e.name) if e.name else str(e.id)]=ds
  d[label]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'groups':groups}
 d['hostOnlyGroupIds']=sorted(set(d['host']['groups'])-set(d['old']['groups']));d['oldOnlyGroupIds']=sorted(set(d['old']['groups'])-set(d['host']['groups']))
 out[n]=d;print(n,'host',len(d['host']['groups']),'old',len(d['old']['groups']),'hostOnly',len(d['hostOnlyGroupIds']),'sample',d['hostOnlyGroupIds'][:25])
(root/'work/old-icon-resource-coverage.json').write_text(json.dumps(out,indent=2),encoding='utf8')
