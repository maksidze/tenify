from pathlib import Path
import sys, struct, json, uuid, urllib.request, hashlib, argparse
root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(root/'work/pylib'))
import pefile, capstone
parser=argparse.ArgumentParser();parser.add_argument('--module',default='C:/Windows/System32/twinui.pcshell.dll');parser.add_argument('--folder',default='host-twinui');args=parser.parse_args()
out=Path(__file__).resolve().parent/'Symbols'
out.mkdir(exist_ok=True)
src=Path(args.module); data=src.read_bytes(); pe=pefile.PE(data=data)
for ent in pe.DIRECTORY_ENTRY_DEBUG:
 raw=data[ent.struct.PointerToRawData:ent.struct.PointerToRawData+ent.struct.SizeOfData]
 if raw[:4]==b'RSDS':
  guid=uuid.UUID(bytes_le=raw[4:20]);age=struct.unpack_from('<I',raw,20)[0];name=raw[24:].split(b'\0')[0].decode().replace('\\','/').rsplit('/',1)[-1];break
key=guid.hex.upper()+format(age,'X');url=f'https://msdl.microsoft.com/download/symbols/{name}/{key}/{name}'
pdb=out/name
if not pdb.exists():
 with urllib.request.urlopen(url,timeout=45) as response:pdb.write_bytes(response.read())
def streams(data):
 b,_,_,nb,_,bm=struct.unpack_from('<6I',data,32);count=(nb+b-1)//b
 blocks=struct.unpack_from('<'+str(count)+'I',data,bm*b);d=b''.join(data[x*b:(x+1)*b] for x in blocks)[:nb]
 n=struct.unpack_from('<I',d)[0];sizes=struct.unpack_from('<'+str(n)+'I',d,4);pos=4+4*n;result=[]
 for size in sizes:
  count=0 if size==0xffffffff else (size+b-1)//b
  blocks=struct.unpack_from('<'+str(count)+'I',d,pos) if count else [];pos+=count*4
  result.append(b''.join(data[x*b:(x+1)*b] for x in blocks)[:size])
 return result
ss=streams(pdb.read_bytes()); pguid=uuid.UUID(bytes_le=ss[1][12:28]);page=struct.unpack_from('<I',ss[3],8)[0]
assert pguid==guid and page==age,(guid,pguid,age,page)
records=ss[struct.unpack_from('<H',ss[3],20)[0]];pos=0;symbols=[]
while pos+4<=len(records):
 length,kind=struct.unpack_from('<HH',records,pos);end=pos+length+2
 if end>len(records) or length<2:break
 if kind==0x110e and length>=12:
  flags,offset,segment=struct.unpack_from('<IIH',records,pos+4);s=records[pos+14:end].split(b'\0')[0].decode(errors='replace')
  if 0<segment<=len(pe.sections):symbols.append({'rva':pe.sections[segment-1].VirtualAddress+offset,'name':s})
 pos=end
selected=[x for x in symbols if any(w in x['name'] for w in ['_CreateXamlMTVHost','_CreateDCompMTVHost','_CreateMTVHost','GetMTVHostKind','MultitaskingViewManager','SwitchDesktop'])]
(out/'all-public-symbols.json').write_text(json.dumps(symbols,indent=2),encoding='utf8')
report={'file':str(src),'sha256':hashlib.sha256(data).hexdigest(),'pdb':str(pdb),'pdbUrl':url,'guid':str(guid),'age':age,'pdbMatch':True,'symbols':selected}
(out/'symbols.json').write_text(json.dumps(report,indent=2),encoding='utf8')
c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
lines=[]
for s in selected:
 if not any(w in s['name'] for w in ['_CreateXamlMTVHost','_CreateDCompMTVHost','_CreateMTVHost','GetMTVHostKind']):continue
 lines.append(f"{s['rva']:x} {s['name']}")
 fn=next((r.struct for r in pe.DIRECTORY_ENTRY_EXCEPTION if r.struct.BeginAddress==s['rva']),None)
 size=(fn.EndAddress-s['rva']) if fn else 400
 lines.extend(f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in c.disasm(pe.get_data(s['rva'],size),s['rva']))
(out/'multitasking-disassembly.txt').write_text('\n'.join(lines),encoding='utf8')
print(json.dumps({k:v for k,v in report.items() if k!='symbols'},indent=2));print('\n'.join(lines[:110]))
