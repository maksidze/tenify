from pathlib import Path
import json,sys,struct,re,bisect
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'));import pefile
routes=json.loads((root/'work/explorer-ui-routes.json').read_text());out={}
for label,info in routes.items():
 pe=pefile.PE(info['path']);syms=sorted(json.loads((root/'work/compat-research'/('host-'+label)/'all-public-symbols.json').read_text()),key=lambda s:s['rva']);rvas=[s['rva'] for s in syms];refs=[]
 for sec in pe.sections:
  if not sec.Characteristics&0x20000000:continue
  b=sec.get_data()
  for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....',b,re.S):
   rva=sec.VirtualAddress+m.start();target=rva+7+struct.unpack_from('<i',m.group(),3)[0]
   for guid,hits in info['guidHits'].items():
    if any(h['rva']==target for h in hits):
     fn=next((e.struct.BeginAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=rva<e.struct.EndAddress),None);s=syms[bisect.bisect_right(rvas,fn or rva)-1]
     row={'guid':guid,'xref':rva,'function':fn,'symbol':s['name']};refs.append(row);print(label,guid,hex(rva),hex(fn or 0),s['name'])
 out[label]=refs
(root/'work/explorer-ui-guid-refs.json').write_text(json.dumps(out,indent=2),encoding='utf8')
