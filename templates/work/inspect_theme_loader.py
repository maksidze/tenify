from pathlib import Path
import sys,json
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile,capstone
from capstone.x86_const import X86_OP_MEM,X86_REG_RIP,X86_OP_IMM
pe=pefile.PE('C:/Windows/System32/uxtheme.dll')
syms=json.loads((ROOT/'work/compat-research/host-uxtheme/all-public-symbols.json').read_text())
names={x['rva']:x['name'] for x in syms}
for d in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in d.imports: names[imp.address-pe.OPTIONAL_HEADER.ImageBase]='IAT '+d.dll.decode()+'!'+(imp.name.decode() if imp.name else '#'+str(imp.ordinal))
patterns=['?LoadThemeForTesting@CThemeLoader','?InstallPrivateThemeFileForTesting@','?LoadTheme@CThemeLoader']
selected=[x for x in syms if any(x['name'].startswith(p) for p in patterns)]
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
(ROOT/'work/theme-loader-code.txt').write_text('\n'.join(lines),encoding='utf8')
print('\n'.join(lines))
