from pathlib import Path
import json,sys,uuid,struct
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile,capstone
known={'VideoSubgroup':'7516b95f-f776-4464-8c53-06167f40cc99','DisplayTimeout':'3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e','SleepSubgroup':'238c9fa8-0aad-41ed-83f4-97be242c8f20','SleepTimeout':'29f6c1db-86da-48c5-9fdb-f2b67b1f44da'}
out={};cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
for mode,file in [('old',root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'),('host',Path('C:/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'))]:
 p=pefile.PE(str(file));raw=file.read_bytes();base=p.OPTIONAL_HEADER.ImageBase;rows=[];imports={i.address-base:(d.dll.decode()+'.'+(i.name.decode() if i.name else '#'+str(i.ordinal))) for d in p.DIRECTORY_ENTRY_IMPORT for i in d.imports}
 for name,guid in known.items():
  blob=uuid.UUID(guid).bytes_le;locs=[];start=0
  while True:
   at=raw.find(blob,start)
   if at<0:break
   start=at+1;locs.append(p.get_rva_from_offset(at))
  refs=[]
  for section in p.sections:
   if not section.Characteristics&0x20000000:continue
   for ins in cs.disasm(section.get_data(),section.VirtualAddress):
    if any(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP and ins.address+ins.size+o.mem.disp in locs for o in ins.operands):refs.append({'rva':hex(ins.address),'instruction':ins.mnemonic+' '+ins.op_str})
  rows.append({'name':name,'guid':guid,'rvas':[hex(x) for x in locs],'codeRefs':refs})
 calls=[]
 for section in p.sections:
  if not section.Characteristics&0x20000000:continue
  for ins in cs.disasm(section.get_data(),section.VirtualAddress):
   for o in ins.operands:
    if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP:
     name=imports.get(ins.address+ins.size+o.mem.disp,'')
     if any(t in name for t in ['PowerRead','PowerWrite','PowerGetActive','PowerSetActive']):calls.append({'rva':hex(ins.address),'import':name})
 out[mode]={'path':str(file),'guids':rows,'powerApiCallsites':calls};print(mode,[(r['name'],r['rvas'],len(r['codeRefs'])) for r in rows]);print(calls[:25])
(Path(__file__).parent/'power-guid-api-evidence.json').write_text(json.dumps(out,indent=2))
