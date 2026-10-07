exec(open('work/taskview_button_disassembly.py').read().split('lines=[]')[0]);import struct
for a in (0x2335e0,):
 f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress)
 for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):
  print(f'{i.address:x}: {i.mnemonic} {i.op_str}')
  if i.mnemonic=='lea' and 'rip + ' in i.op_str:
   v=i.address+i.size+int(i.op_str.split('rip + ')[1].split(']')[0],16);print('ref',hex(v),s.get(v))
   if 'rax' in i.op_str:
    for k in range(10):
     b=struct.unpack('<Q',p.get_data(v+k*8,8))[0]-p.OPTIONAL_HEADER.ImageBase;print(k,hex(b),s.get(b,''))
