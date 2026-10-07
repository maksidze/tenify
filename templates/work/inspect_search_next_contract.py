from pathlib import Path
import sys,json,uuid
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
exe=root/'outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy/SearchApp.exe'
core='--core' in sys.argv
if core:exe=exe.with_name('Search.Core.dll')
pe=pefile.PE(str(exe));symbols=json.loads((root/'work/compat-research'/('old-search-core' if core else 'old-search-exe')/'all-public-symbols.json').read_text());names={x['rva']:x['name'] for x in symbols}
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
results=[]
for site in ([0x23faf,0xb0c1,0xbdf0] if core else [0xa6a53,0xb0575,0xbb6f9,0x1cb6cf,0xbf56d,0x5a458,0xb5f1d]):
    f=next(x.struct for x in pe.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=site<x.struct.EndAddress)
    rows=[]
    for ins in cs.disasm(pe.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):
        refs=[]
        for op in ins.operands:
            if op.type==capstone.x86.X86_OP_IMM: refs.append({'rva':hex(op.imm),'symbol':names.get(op.imm)})
            elif op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                target=ins.address+ins.size+op.mem.disp;data=pe.get_data(target,256)
                refs.append({'rva':hex(target),'symbol':names.get(target),'guid':str(uuid.UUID(bytes_le=data[:16])) if len(data)>=16 else None,'text':data.decode('utf-16le',errors='replace').split('\0')[0]})
        rows.append({'rva':hex(ins.address),'asm':ins.mnemonic+' '+ins.op_str,'refs':refs})
    results.append({'site':hex(site),'begin':hex(f.BeginAddress),'symbol':names.get(f.BeginAddress),'rows':rows})
(lab/('core-runtime-contract-disassembly.json' if core else 'next-runtime-contract-disassembly.json')).write_text(json.dumps(results,indent=2),encoding='utf8')
for f in results:
    print(f['site'],f['begin'],f['symbol'])
    for r in f['rows']:
        print(r['rva'],r['asm'],json.dumps(r['refs'],ensure_ascii=True))
