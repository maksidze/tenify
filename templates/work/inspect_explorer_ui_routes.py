from pathlib import Path
import json,sys,uuid,hashlib
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'));import pefile
out={}
guids=['86ca1aa0-34aa-4e8b-a509-50c905bae2a2','6480100b-5a83-4d1e-9f69-8ae5a88e9a33','2aa9162e-c906-4dd9-ad0b-3d24a8eef5a0','dc1c5a9c-e88a-4dde-a5a1-60f82a20aef7','c0b4e2f3-ba21-4773-8dba-335ec946eb8b']
for label in ['shell32','explorerframe']:
 path=Path('C:/Windows/System32')/(label+'.dll');pe=pefile.PE(str(path));data=path.read_bytes();syms=json.loads((root/'work/compat-research'/('host-'+label)/'all-public-symbols.json').read_text())
 rows=[s for s in syms if any(x.lower() in s['name'].lower() for x in ['ContextMenu','FileDialog','Ribbon','CommandBar','XamlIslandView','FileExplorerFolderView','CanDisplayWin8CopyDialog','ImmersiveMenu','CompactMenu','SimplifiedMenu'])]
 found={}
 for g in guids:
  needle=uuid.UUID(g).bytes_le;start=0;hits=[]
  while (i:=data.find(needle,start))>=0:
   rva=pe.get_rva_from_offset(i);hits.append({'rva':rva,'symbol':[s['name'] for s in syms if s['rva']==rva]});start=i+16
  found[g]=hits
 out[label]={'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'guidHits':found,'symbols':rows}
 print(label, 'interestingSymbols',len(rows))
 for s in rows:
  n=s['name'];low=n.lower()
  if any(x in low for x in ['modern','classic','simplif','compact','should','showcontext','createcontext','xamlisland','candisplaywin8','useribbon','createcommand','filedialog_create']):print(hex(s['rva']),n)
 print('GUID',json.dumps(found))
(root/'work/explorer-ui-routes.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
