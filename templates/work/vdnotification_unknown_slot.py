import sys,json
sys.path.insert(0,'work/pylib');import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll');d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for i in d.disasm(p.get_data(0x4bf3f0,100),0x4bf3f0):
 print(hex(i.address),i.mnemonic,i.op_str)
 if i.mnemonic=='ret':break
s=json.load(open('work/compat-research/old-twinui/all-public-symbols.json'))
print([x for x in s if 0x541190<x['rva']<=0x5411d0])
