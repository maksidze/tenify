"""Decode only types reached by NotificationController's refined record.
Uses the actual PE's NDR32 format, without relying on inferred C definitions.
"""
from pathlib import Path
import struct,json
base=Path('outputs/Windows10-Components/Lab/NotificationCompat')
class Schema:
 def __init__(self,b):self.b=b;self.nodes={}
 def h(self,p):return struct.unpack_from('<H',self.b,p)[0]
 def s(self,p):return struct.unpack_from('<h',self.b,p)[0]
 def ref(self,p):return p+self.s(p)
 def get(self,p):
  if p in self.nodes:return self.nodes[p]
  b=self.b;t=b[p];n={'pos':p,'token':t};self.nodes[p]=n
  primitive={1:1,2:1,3:1,4:1,5:2,6:2,7:2,8:4,9:4,10:4,11:8,12:8,13:4,14:4}
  if t in primitive:n.update(kind='scalar',size=primitive[t]);return n
  if t in (0x11,0x12,0x13,0x14):
   if b[p+1]&8:n.update(kind='stringPointer' if b[p+2]==0x25 else 'simplePointer',size=8,referentToken=b[p+2])
   else:n.update(kind='pointer',size=8,target=self.ref(p+2));self.get(n['target'])
  elif t==0xb4:n.update(kind='userMarshal',size=self.h(p+4),quadrupleIndex=self.h(p+2))
  elif t in (0x15,0x1a):
   n.update(kind='struct',size=self.h(p+2),fields=[]);off=0;i=p+(8 if t==0x1a else 4);pi=p+6+self.s(p+6) if t==0x1a else None
   while b[i]!=0x5b:
    tok=b[i]
    if tok==0x5c:i+=1;continue
    if 0x3d<=tok<=0x44:off+=tok-0x3c;i+=1;continue
    if tok==0x36:
     q=pi;pi+=4;i+=1
    elif tok==0x4c:q=self.ref(i+2);i+=4
    else:q=i;i+=1
    child=self.get(q);n['fields'].append({'offset':off,'node':q});off+=child['size']
   if off!=n['size']:raise ValueError(('structure-size',hex(p),off,n['size']))
  elif t==0x1d:
   n.update(kind='array',size=self.h(p+2),fixedBytes=True,element=p+4);e=self.get(p+4);n['count']=n['size']//e['size']
  elif t==0x21:
   i=p+16
   if b[i]==0x4c:q=self.ref(i+2)
   else:q=i
   count=self.h(p+2);n.update(kind='array',element=q,count=count,correlation=b[p+4:p+10].hex());e=self.get(q);n['size']=count*e['size']
  elif t==0x1b:
   i=p+10;q=self.ref(i+2) if b[i]==0x4c else i
   n.update(kind='array',element=q,count=0,correlation=b[p+4:p+10].hex(),stride=self.h(p+2),size=0);self.get(q)
  elif t==0x2b:
   a=self.ref(p+8);count=self.h(a+2)&0xfff;n.update(kind='union',size=self.h(a),switchToken=b[p+1],switchOffset=self.s(p+4),arms={})
   for j in range(count):
    entry=a+4+j*6;case=struct.unpack_from('<I',b,entry)[0];v=self.h(entry+4)
    if v==0:n['arms'][case]=None
    elif v&0x8000:
     token=v&0xff;key=0x10000+token
     self.nodes[key]={'pos':key,'token':token,'kind':'scalar','size':primitive[token]};n['arms'][case]=key
    else:q=self.ref(entry+4);n['arms'][case]=q;self.get(q)
  else:raise ValueError(('unsupported-token',hex(p),hex(t)))
  return n
if __name__=='__main__':
 for tag,root,updated,deleted in [('old',0x37a,0x438,0x466),('host',0x358,0x418,0x446)]:
  s=Schema((base/f'{tag}-ndr-type.bin').read_bytes());s.get(root);s.get(updated);s.get(deleted)
  (base/f'{tag}-ndr-schema.json').write_text(json.dumps({'root':root,'updated':updated,'deleted':deleted,'nodes':s.nodes},indent=2))
  print(tag,len(s.nodes),sorted(set(x['kind'] for x in s.nodes.values())))
