exec(open('work/taskview_native_async.py').read().split('for a in')[0])
imports={i.address-p.OPTIONAL_HEADER.ImageBase:i.name for e in p.DIRECTORY_ENTRY_IMPORT+getattr(p,'DIRECTORY_ENTRY_DELAY_IMPORT',[]) for i in e.imports}
for start in (0x485cb0,0x155870,0x2597fc,0xd1740):
 f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==start);a=list(d.disasm(p.get_data(start,f.EndAddress-start),start));print(hex(start),ns.get(start,''))
 for k,i in enumerate(a):
  hit='0x100]' in i.op_str
  if i.mnemonic=='call' and 'rip + ' in i.op_str:
   target=i.address+i.size+int(i.op_str.split('rip + ')[1].split(']')[0],16);name=imports.get(target,b'')
   if any(x in name for x in (b'SHTaskPool',b'SHCreateThread',b'SHGetThread',b'SHSetThread',b'CreateThread')):hit=True
  if hit:
   for j in a[max(0,k-4):k+3]:print(hex(j.address),j.mnemonic,j.op_str)
   print('API',locals().get('name'))
