from pathlib import Path
import sys,json,struct,hashlib
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
exe=root/'outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy/SearchApp.exe'
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
pe=pefile.PE(str(exe));symbols=json.loads((root/'work/compat-research/old-search-exe/all-public-symbols.json').read_text());names={x['rva']:x['name'] for x in symbols};rv={x['name']:x['rva'] for x in symbols}
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
result={'image':str(exe),'sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'imageBase':hex(pe.OPTIONAL_HEADER.ImageBase),'characteristics':hex(pe.FILE_HEADER.Characteristics),'entryRVA':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'relocationDirectory':{'rva':hex(pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress),'size':pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size},'tlsDirectory':{'rva':hex(pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress),'size':pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size},'crtArrays':{},'functions':[]}
for prefix in ['xi','xc']:
    first=rv['__'+prefix+'_a'];last=rv['__'+prefix+'_z'];items=[]
    for offset in range(first,last,8):
        pointer=struct.unpack('<Q',pe.get_data(offset,8))[0]
        if pointer:items.append({'slot':hex(offset),'rva':hex(pointer-pe.OPTIONAL_HEADER.ImageBase),'symbol':names.get(pointer-pe.OPTIONAL_HEADER.ImageBase)})
    result['crtArrays'][prefix]={'startRVA':hex(first),'endRVA':hex(last),'items':items}
sites=[0xc8dc0,0xc9c64]
seen=set()
while sites:
    site=sites.pop(0)
    if site in seen:continue
    seen.add(site)
    f=next((x.struct for x in pe.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=site<x.struct.EndAddress),None)
    start=f.BeginAddress if f else site;length=f.EndAddress-start if f else 64;rows=[]
    for ins in cs.disasm(pe.get_data(start,length),start):
        refs=[]
        for op in ins.operands:
            if op.type==capstone.x86.X86_OP_IMM:
                refs.append({'rva':hex(op.imm),'symbol':names.get(op.imm)})
                if site==0xc8dc0 and ins.mnemonic=='jmp':sites.append(op.imm)
            elif op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                target=ins.address+ins.size+op.mem.disp;refs.append({'rva':hex(target),'symbol':names.get(target)})
        rows.append({'rva':hex(ins.address),'asm':ins.mnemonic+' '+ins.op_str,'references':refs})
    result['functions'].append({'rva':hex(start),'symbol':names.get(start),'instructions':rows})
(lab/'container-startup-analysis.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(json.dumps({key:value for key,value in result.items() if key!='functions'},indent=2))
for f in result['functions']:
    print(f['rva'],f['symbol'])
    for r in f['instructions']:print(r['rva'],r['asm'],json.dumps(r['references']))
