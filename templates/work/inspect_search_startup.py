from pathlib import Path
import sys,json
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
items=[('old',root/'outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy/SearchApp.exe',root/'work/compat-research/old-search-exe/all-public-symbols.json',[0xc9ab4,0x7d11c,0xc9fd0]),('host',Path('C:/Windows/SystemApps/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/SearchHost.exe'),root/'work/compat-research/host-search-exe/all-public-symbols.json',[0x7388])]
results=[]
for kind,file,symbolpath,sites in items:
    image=pefile.PE(str(file));symbols=json.loads(symbolpath.read_text());names={x['rva']:x['name'] for x in symbols}; cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    for site in sites:
        runtime=next((x.struct for x in image.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=site<x.struct.EndAddress),None)
        length=runtime.EndAddress-site if runtime else 24
        instructions=[]
        for instruction in cs.disasm(image.get_data(site,min(length,4096)),site):
            references=[]
            for operand in instruction.operands:
                if operand.type==capstone.x86.X86_OP_IMM:references.append({'rva':hex(operand.imm),'symbol':names.get(operand.imm)})
                elif operand.type==capstone.x86.X86_OP_MEM and operand.mem.base==capstone.x86.X86_REG_RIP:
                    target=instruction.address+instruction.size+operand.mem.disp;references.append({'rva':hex(target),'symbol':names.get(target)})
            instructions.append({'rva':hex(instruction.address),'asm':instruction.mnemonic+' '+instruction.op_str,'references':references})
        results.append({'kind':kind,'file':str(file),'site':hex(site),'symbol':names.get(site),'instructions':instructions})
(lab/'startup-disassembly.json').write_text(json.dumps(results,indent=2),encoding='utf8')
print('Saved exact startup/factory disassembly, no foreign code executed.')
