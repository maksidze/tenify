exec(open('work/taskview_button_disassembly.py').read().split('lines=[]')[0])
for a in (0x233644,):
 f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress)
 for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):
  line=f'{i.address:x}: {i.mnemonic} {i.op_str}'
  if i.mnemonic=='call' and i.op_str.startswith('0x'):line+=' '+s.get(int(i.op_str,16),'')
  if 'rip + ' in i.op_str:
   v=int(i.op_str.split('rip + ')[1].split(']')[0],16);line+=' '+str(imports.get(i.address+i.size+v,s.get(i.address+i.size+v,'')))
  print(line)
