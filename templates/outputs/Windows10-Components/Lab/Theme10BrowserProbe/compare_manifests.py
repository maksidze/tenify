from pathlib import Path
import sys,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path.insert(0,str(R/'work/pylib'))
import pefile
paths={'Taskmgr':Path('C:/Windows/System32/Taskmgr.exe'),'Explorer10':H.parent.parent/'Runtime/Explorer10/explorer.exe'}
out=[]
for name,path in paths.items():
 p=pefile.PE(str(path));entry=next(x for x in p.DIRECTORY_ENTRY_RESOURCE.entries if x.id==24)
 for rid in entry.directory.entries:
  for lang in rid.directory.entries:
   raw=p.get_data(lang.data.struct.OffsetToData,lang.data.struct.Size);text=raw.decode('utf-8',errors='replace');(H/(name+'.manifest.xml')).write_text(text)
   out.append(dict(name=name,path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),manifest=text))
(H/'manifest-comparison.json').write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
