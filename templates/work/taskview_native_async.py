import sys,json,struct
sys.path.insert(0,'work/pylib');import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll');s=json.load(open('work/compat-research/host-twinui/all-public-symbols.json'));ns={r['rva']:r['name'] for r in s};d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for a in (0xa9ffc,0x247afc,0x247294,0x246f98):
 f=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress),None);print('FUNC',hex(f.BeginAddress if f else a))
 for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress) if f else p.get_data(a,32),f.BeginAddress if f else a):print(hex(i.address),i.mnemonic,i.op_str,ns.get(int(i.op_str,16),'') if i.mnemonic=='call' and i.op_str.startswith('0x') else '')






















