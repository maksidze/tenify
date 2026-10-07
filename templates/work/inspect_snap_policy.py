from pathlib import Path
import sys, json, struct, bisect
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile, capstone
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
out=ROOT/'work/snap-policy-static.txt'
lines=[]
for module,folder in [('twinui.dll','host-twinui-base'),('twinui.pcshell.dll','host-twinui'),('SystemSettings.DataModel.dll','host-settings-datamodel')]:
    src=Path('C:/Windows/System32')/module
    data=src.read_bytes(); pe=pefile.PE(data=data)
    targets={}
    for key in ('EnableSnapAssistFlyout','EnableSnapBar'):
        raw=(key+'\0').encode('utf-16-le'); p=0
        while (p:=data.find(raw,p))>=0:
            targets[pe.get_rva_from_offset(p)]=key; p+=len(raw)
    lines.append(f'{module} strings={targets}')
    if not targets:continue
    ranges=sorted((r.struct.BeginAddress,r.struct.EndAddress) for r in pe.DIRECTORY_ENTRY_EXCEPTION)
    starts=[r[0] for r in ranges]
    symbols_path=ROOT/'work/compat-research'/folder/'all-public-symbols.json'
    symbols={x['rva']:x['name'] for x in json.loads(symbols_path.read_text())} if symbols_path.exists() else {}
    for target,key in targets.items():
        needle=struct.pack('<Q',pe.OPTIONAL_HEADER.ImageBase+target);off=0
        while (off:=data.find(needle,off))>=0:
            rva=pe.get_rva_from_offset(off)
            prior=max((x for x in symbols if x<=rva),default=0)
            lines.append(f'dataref {key} at {rva:x} nearest {prior:x} {symbols.get(prior,"?")}')
            for a in range(max(0,rva-32),rva+48,8):
                value=struct.unpack('<Q',pe.get_data(a,8))[0]
                vrva=value-pe.OPTIONAL_HEADER.ImageBase
                text=''
                if 0<=vrva<pe.OPTIONAL_HEADER.SizeOfImage:
                    raw=pe.get_data(vrva,300)
                    text=raw.decode('utf-16-le',errors='replace').split('\0')[0]
                    if not text.isprintable():text=symbols.get(vrva,'')
                lines.append(f'  {a:x}: {value:x} {text}')
            off+=8
    refs=set()
    # Scan RIP-relative displacement candidates, then validate with Capstone.
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:continue
        raw=section.get_data(); base=section.VirtualAddress
        for i in range(3,len(raw)-4):
            disp=struct.unpack_from('<i',raw,i)[0]
            target=base+i+4+disp
            if target not in targets:continue
            j=bisect.bisect_right(starts,base+i)-1
            if j<0 or not ranges[j][0]<=base+i<ranges[j][1]:continue
            refs.add((ranges[j],target))
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    for (start,end),target in sorted(refs):
        instructions=list(md.disasm(pe.get_data(start,end-start),start))
        matching=[n for n,x in enumerate(instructions) if any(o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP and x.address+x.size+o.mem.disp==target for o in x.operands)]
        if not matching:continue
        lines.append(f'\n{start:x} {symbols.get(start,"?")} references {targets[target]} at {target:x}')
        for n in matching:
            for x in instructions[max(0,n-12):min(len(instructions),n+28)]:
                lines.append(f'{x.address:x}: {x.mnemonic} {x.op_str}')
out.write_text('\n'.join(lines),encoding='utf8')
print('\n'.join(lines))
