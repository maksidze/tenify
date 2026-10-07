exec(open('work/taskview_native_async.py').read().split('for a in')[0])
for vt in (0x48674d+7+0x296734,0x486757+7+0x29670a):
 print('table',hex(vt))
 for k in range(6):
  a=struct.unpack('<Q',p.get_data(vt+k*8,8))[0]-p.OPTIONAL_HEADER.ImageBase;print(k,hex(a),ns.get(a,''))
