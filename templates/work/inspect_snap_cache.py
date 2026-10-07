from pathlib import Path
import sys,json,struct
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile,capstone
from capstone.x86_const import X86_OP_MEM,X86_REG_RIP,X86_OP_IMM
pe=pefile.PE('C:/Windows/System32/twinui.dll')
syms=json.loads((ROOT/'work/compat-research/host-twinui-base/all-public-symbols.json').read_text())
names={x['rva']:x['name'] for x in syms}
patterns=['?OnSettingChanged@CImmersiveSettingsCache','?_OnSettingChanged@CImmersiveSettingsCache','?_LoadSetting@CImmersiveSettingsCache','?GetBOOL@CImmersiveSettingsCache','?s_BoolSettingDefaultHandling@CImmersiveSettingsCache','??0CImmersiveSettingsCache','?Initialize@CImmersiveSettingsCache']
selected=[x for x in syms if any(x['name'].startswith(p) for p in patterns)]
selected += [x for x in syms if x['name'].startswith('?QueryInterface@?$RuntimeClassImpl') and 'UIImmersiveSettingsCache@@VFtmBase' in x['name'] and '@WDA@' in x['name']][:1]
selected += [x for x in syms if x['rva']==0x307e0][:1]
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
lines=[]
for x in selected:
    start=x['rva'];ends=[r.struct.EndAddress for r in pe.DIRECTORY_ENTRY_EXCEPTION if r.struct.BeginAddress==start];end=ends[0] if ends else start+128
    lines.append(f'\n{start:x} {x["name"]}')
    for i in md.disasm(pe.get_data(start,end-start),start):
        extra=[]
        for o in i.operands:
            if o.type==X86_OP_IMM and o.imm in names:extra.append(names[o.imm])
            if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP:
                r=i.address+i.size+o.mem.disp
                if r in names:extra.append(names[r])
        lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str} '+';'.join(extra))
for table,count in [(0x3b1698,9),(0x3dcbb0,5)]:
    lines.append(f'\ntable {table:x}')
    for j in range(count):
        v=struct.unpack('<Q',pe.get_data(table+8*j,8))[0];r=v-pe.OPTIONAL_HEADER.ImageBase
        b=pe.get_data(r,16) if 0<=r<pe.OPTIONAL_HEADER.SizeOfImage else b''
        lines.append(f'{table+8*j:x}: {v:x} {names.get(r,"")} {b.hex()}')
(ROOT/'work/snap-cache-code.txt').write_text('\n'.join(lines),encoding='utf8')
print('\n'.join(lines))
