from pathlib import Path
import sys,struct,json,uuid
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile,capstone
lab=Path(__file__).parent;mapping=json.loads((lab/'power-exact-id-guid-map.json').read_text());pe=pefile.PE('C:/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll');cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;regs={};writes={};trace=[]
for i in cs.disasm(pe.get_data(0x2000,0x900),0x2000):
 if i.mnemonic not in ['movups','movdqu','movaps']:continue
 d,s=i.operands
 if d.type==capstone.x86.X86_OP_REG and s.type==capstone.x86.X86_OP_MEM and s.mem.base==capstone.x86.X86_REG_RIP:regs[d.reg]=pe.get_data(i.address+i.size+s.mem.disp,16)
 if d.type==capstone.x86.X86_OP_MEM and d.mem.base==capstone.x86.X86_REG_RIP and s.type==capstone.x86.X86_OP_REG and s.reg in regs:
  target=i.address+i.size+d.mem.disp;writes[target]=regs[s.reg];trace.append({'instructionRVA':hex(i.address),'targetRVA':hex(target),'data':regs[s.reg].hex()})
checks=[]
for old,native in zip(mapping['old'],mapping['native']):
 ctx=int(native['contextRVA'],16);sub=writes[ctx];setting=writes[ctx+16];native['subgroup']=str(uuid.UUID(bytes_le=sub));native['setting']=str(uuid.UUID(bytes_le=setting));raw=pe.get_data(ctx+32,4);native['acDcFlag']=struct.unpack('<I',raw)[0] if len(raw)==4 else 0
 old['acDcFlag']=old['flags'][0];checks.append({'oldId':old['id'],'nativeId':native['id'],'subgroupEqual':old['subgroup']==native['subgroup'],'settingGuidEqual':old['setting']==native['setting'],'acDcFlagEqual':old['acDcFlag']==native['acDcFlag']})
assert all(all(row[k] for k in ['subgroupEqual','settingGuidEqual','acDcFlagEqual']) for row in checks)
(lab/'power-semantic-guid-proof.json').write_text(json.dumps({'mapping':mapping,'checks':checks,'crtDataAssignments':trace,'staticOnly':True,'settersCalled':False},indent=2));print(checks)
