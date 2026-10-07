from pathlib import Path
import sys,json
LAB=Path(__file__).resolve().parent;ROOT=LAB.parents[3];sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile
out=[]
for name in ['shell32.dll','windows.storage.dll','user32.dll','kernelbase.dll','imageres.dll','shcore.dll']:
 p=pefile.PE('C:/Windows/System32/'+name);entries=[]
 for kind,table in [('import',getattr(p,'DIRECTORY_ENTRY_IMPORT',[])),('delay',getattr(p,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))]:
  for d in table:
   for i in d.imports:
    s=i.name.decode() if i.name else '#'+str(i.ordinal)
    if any(t.lower() in s.lower() for t in ['Icon','Resource','Library','GetProcAddress','ImageList']):entries.append(dict(Type=kind,From=d.dll.decode(),Name=s,Iat=hex(i.address-p.OPTIONAL_HEADER.ImageBase)))
 out.append(dict(Module=name,Entries=entries))
(LAB/'native-imports.json').write_text(json.dumps(out,indent=2))
