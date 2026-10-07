from pathlib import Path
import sys,json
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
pe=pefile.PE('C:/Windows/ImmersiveControlPanel/SystemSettings.exe')
symbols=json.loads((root/'work/compat-research/host-settings-exe/all-public-symbols.json').read_text())
names={s['rva']:s['name'] for s in symbols}
rva=next(s['rva'] for s in symbols if s['name']=='wWinMain')
fn=next(x.struct for x in pe.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==rva)
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
lines=[]
for ins in cs.disasm(pe.get_data(rva,fn.EndAddress-rva),rva):
    notes=[]
    for operand in ins.operands:
        if operand.type==capstone.x86.X86_OP_IMM:notes.append(names.get(operand.imm,''))
        elif operand.type==capstone.x86.X86_OP_MEM and operand.mem.base==capstone.x86.X86_REG_RIP:
            target=ins.address+ins.size+operand.mem.disp
            notes.append(hex(target)+' '+names.get(target,''))
            if ins.mnemonic=='lea':
                data=pe.get_data(target,256)
                for encoding in ['utf-16le','ascii']:
                    try:
                        value=data.decode(encoding,errors='ignore').split('\0')[0]
                        if len(value)>3 and all(c.isprintable() for c in value):notes.append(repr(value))
                    except UnicodeError:pass
    lines.append(f'{ins.address:x}: {ins.mnemonic} {ins.op_str} '+ '; '.join(n for n in notes if n))
out=root/'outputs/Windows10-Components/Lab/SettingsIdentity/native-entry-disassembly.txt'
out.write_text('\n'.join(lines),encoding='utf8')
print('\n'.join(lines).encode('ascii',errors='backslashreplace').decode())
