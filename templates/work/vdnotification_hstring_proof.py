import sys
sys.path.insert(0,'work/pylib');import pefile,capstone
for label,path,rva in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll',0x4beef0),('host','C:/Windows/System32/twinui.pcshell.dll',0x235b10)]:
 p=pefile.PE(path);d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);exports={i.address-p.OPTIONAL_HEADER.ImageBase:i.name for e in p.DIRECTORY_ENTRY_IMPORT for i in e.imports};print(label)
 for i in d.disasm(p.get_data(rva,70),rva):
  print(hex(i.address),i.mnemonic,i.op_str)
  if i.mnemonic=='jmp' and 'rip' in i.op_str:
   x=int(i.op_str.split(' + ')[1].split(']')[0],16);print(exports.get(i.address+i.size+x));break
  if i.mnemonic=='ret':break
