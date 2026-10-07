from pathlib import Path
import struct,json,sys
p=Path(sys.argv[1] if len(sys.argv)>1 else 'work/settings-viewmodel-actual.xbf');b=p.read_bytes();start=12
major,minor=struct.unpack_from('<II',b,start);offs=struct.unpack_from('<6Q',b,start+8)
def vector(off,nfmt):
 off+=start;n=struct.unpack_from('<I',b,off)[0];off+=4;fmt='<'+nfmt;sz=struct.calcsize(fmt);return [struct.unpack_from(fmt,b,off+i*sz) for i in range(n)]
a=start+offs[0];n=struct.unpack_from('<I',b,a)[0];a+=4;strings=[]
for i in range(n):
 length=struct.unpack_from('<I',b,a)[0];a+=4;strings.append(b[a:a+2*length].decode('utf-16le'));a+=2*length+(2 if minor>=1 else 0)
types=[{'flags':fl,'namespace':ns,'name':strings[st]} for fl,ns,st in vector(offs[3],'III')];props=[{'flags':fl,'type':ty,'name':strings[st]} for fl,ty,st in vector(offs[4],'III')]
metaSize,nodeSize=struct.unpack_from('<II',b,4);offset=start+metaSize;nstreams=struct.unpack_from('<I',b,offset)[0];tables=[struct.unpack_from('<II',b,offset+4+i*8) for i in range(nstreams)];nodeStart=offset+4+8*nstreams
out={'file':str(p),'version':[major,minor],'metadataSize':metaSize,'nodeSize':nodeSize,'types':types,'properties':props,'streams':tables,'nodeStart':nodeStart,'rootNodes':[]}
a=nodeStart+tables[0][0]
for count in range(30):
 pos=a;op=b[a];a+=1;item={'offset':pos,'op':op}
 if op in [3,18]:
  token,length=struct.unpack_from('<HI',b,a);a+=6;prefix=b[a:a+length*2].decode('utf-16le');a+=length*2;item.update(token=token,prefix=prefix)
 elif op in [20,23]:
  token=struct.unpack_from('<H',b,a)[0];a+=2;item.update(token=token,trusted=bool(token&0x8000),type=types[token]['name'] if not token&0x8000 else 'stable#'+str(token&0x7fff))
 elif op in [1,2,8,9,33]:pass
 else:
  item['unparsedBytes']=b[a:a+20].hex();out['rootNodes'].append(item);break
 out['rootNodes'].append(item)
p.with_suffix('.decoded.json').write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in out.items() if k not in ['properties','types']},indent=2));print('FirstTypes',types[:10])
