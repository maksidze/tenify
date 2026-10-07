exec(open('work/taskview_native_async.py').read().split('for a in')[0])
for addr in (0x486966+7+0x2d5753,0x4869dc+7+0x2d7e55): print(hex(addr),ns.get(addr))
for r in s:
 if r['name'].startswith('??_7TaskViewHost@@'):
  print(hex(r['rva']),r['name'])
  for k in range(9):
   a=struct.unpack('<Q',p.get_data(r['rva']+k*8,8))[0]-p.OPTIONAL_HEADER.ImageBase
   print(k,hex(a),ns.get(a,''))
