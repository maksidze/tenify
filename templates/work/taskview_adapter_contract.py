import sys,json
sys.path.insert(0,'work/pylib');import pefile,capstone
s=json.load(open('work/compat-research/host-twinui/all-public-symbols.json'));ns={x['rva']:x['name'] for x in s};p=pefile.PE('outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll');d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
a=0x176284;f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress);print(hex(f.BeginAddress),ns.get(f.BeginAddress));lst=list(d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress));idx=next(i for i,v in enumerate(lst) if v.address==a)
for i in lst:print(hex(i.address),i.mnemonic,i.op_str,ns.get(int(i.op_str,16),'') if i.mnemonic=='call' and i.op_str.startswith('0x') else '')


