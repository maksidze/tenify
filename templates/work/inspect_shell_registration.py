from pathlib import Path
import json,sys,struct,csv
sys.path.insert(0,str(Path('work/pylib').resolve()))
from Registry import Registry
base=Path('outputs/Windows10-Components');meta=base/'Metadata'
registry=Registry.Registry(str(base/'Image/4/Windows/System32/config/SOFTWARE'))
matches=[]
for path in ['Classes\\CLSID','Microsoft\\WindowsRuntime\\ActivatableClassId']:
 try:root=registry.open(path)
 except Registry.RegistryKeyNotFoundException:continue
 for key in root.subkeys():
  keys=[key]
  try:keys+=key.subkeys()
  except Exception:pass
  for k in keys:
   for v in k.values():
    value=v.value()
    if isinstance(value,str) and any(t in value.lower() for t in ['twinui','immersiveshell.serviceprovider','windows.ui.xaml','systemsettings']):
     matches.append({'key':k.path(),'valueName':v.name(),'value':value})
(meta/'offline-shell-registration.json').write_text(json.dumps(matches,indent=2,ensure_ascii=False),encoding='utf-8')
downloads=json.loads((meta/'symbol-downloads.json').read_text(encoding='utf-8'));core=json.loads((meta/'core-binary-analysis.json').read_text(encoding='utf-8'))
import pefile
symbols=[]
def pdbStreams(data):
 b,_,_,directoryBytes,_,blockMap=struct.unpack_from('<6I',data,32);count=(directoryBytes+b-1)//b
 blocks=struct.unpack_from('<'+str(count)+'I',data,blockMap*b)
 d=b''.join(data[x*b:(x+1)*b] for x in blocks)[:directoryBytes]
 n=struct.unpack_from('<I',d)[0];sizes=struct.unpack_from('<'+str(n)+'I',d,4);pos=4+4*n;streams=[]
 for size in sizes:
  cnt=0 if size==0xffffffff else (size+b-1)//b
  blocks=struct.unpack_from('<'+str(cnt)+'I',d,pos) if cnt else [];pos+=cnt*4
  streams.append(b''.join(data[x*b:(x+1)*b] for x in blocks)[:size])
 return streams
for s in downloads:
 if not s.get('codeviewMatch'):continue
 streams=pdbStreams(Path(s['path']).read_bytes());symIndex=struct.unpack_from('<H',streams[3],20)[0]
 records=streams[symIndex];pe=pefile.PE(str(base/'Image/4'/s['image']));pos=0
 while pos+4<=len(records):
  length,kind=struct.unpack_from('<HH',records,pos);end=pos+length+2
  if end>len(records) or length<2:break
  if kind==0x110e and length>=12:
   flags,offset,segment=struct.unpack_from('<IIH',records,pos+4);name=records[pos+14:end].split(b'\0')[0].decode('utf-8',errors='replace')
   if any(t in name.lower() for t in ['multitask','taskswitch','desktopandtray','trayimmersive','startimmersiveshell','altab','alttab','createallupview','multitaskingviewhost','immersiveshellproxy']):
    if 0<segment<=len(pe.sections):symbols.append({'image':s['image'],'rva':hex(pe.sections[segment-1].VirtualAddress+offset),'name':name,'pdbCodeviewMatch':True})
  pos=end
(meta/'multitasking-public-symbols.json').write_text(json.dumps(symbols,indent=2),encoding='utf-8')
print('Offline registration matches:',len(matches),'matching public symbols:',len(symbols))
print(json.dumps(matches[:6],indent=2))
