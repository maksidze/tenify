import sys,json,struct
sys.path.insert(0,'work/pylib');import pefile,capstone
p=pefile.PE('C:/Windows/System32/windowsudk.shellcommon.dll');s=json.load(open('work/compat-research/host-udkshellcommon/all-public-symbols.json'));ns={r['rva']:r['name'] for r in s};d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for a in (0x38fd0,0x38ffc):
 f=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress),None);print('FUNC',hex(f.BeginAddress if f else a))
 for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress) if f else p.get_data(a,32),f.BeginAddress if f else a):print(hex(i.address),i.mnemonic,i.op_str,ns.get(int(i.op_str,16),'') if i.mnemonic=='call' and i.op_str.startswith('0x') else '')


































