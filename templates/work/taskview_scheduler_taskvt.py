exec(open('work/taskview_native_async.py').read().split('for a in')[0])
for k in range(5):
 a=struct.unpack('<Q',p.get_data(0x6f59e0+k*8,8))[0]-p.OPTIONAL_HEADER.ImageBase;print(k,hex(a),ns.get(a,''))
