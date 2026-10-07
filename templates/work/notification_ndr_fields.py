from pathlib import Path
import struct,json,difflib
base=Path('outputs/Windows10-Components/Lab/NotificationCompat')
for t,pos in [('old',0x37a),('host',0x358)]:
 b=(base/f'{t}-ndr-type.bin').read_bytes();assert b[pos]==0x1a
 end=pos+8+struct.unpack_from('<h',b,pos+6)[0]-2
 off=0;i=pos+8;fields=[];pi=pos+6+struct.unpack_from('<h',b,pos+6)[0]
 while b[i]!=0x5b:
  tok=b[i]
  if tok==0x5c:i+=1;continue
  if tok==0x40:off+=4;i+=1;continue
  if tok==0x4c:
   target=i+2+struct.unpack_from('<h',b,i+2)[0];size=struct.unpack_from('<H',b,target+2)[0]
   kind=f'embedded:{size}';i+=4
  elif tok==0x36:
   kind='pointer:'+b[pi:pi+4].hex()
   if not b[pi+1]&8:kind+=' target='+hex(pi+2+struct.unpack_from('<h',b,pi+2)[0])
   size=8;i+=1;pi+=4
  else:
   size={0x0b:8,0x08:4,0x0e:4}.get(tok)
   if size is None:raise RuntimeError((t,hex(i),hex(tok)))
   kind={0x0b:'hyper',0x08:'long',0x0e:'enum'}[tok];i+=1
  fields.append({'offset':off,'size':size,'type':kind});off+=size
 assert off==struct.unpack_from('<H',b,pos+2)[0],(t,off)
 (base/f'{t}-ndr-fields.json').write_text(json.dumps(fields,indent=2))
 print(t,'\n'+'\n'.join(f"{f['offset']:03x} {f['size']:2} {f['type']}" for f in fields))
