"""Read-only decoder for the simple old Settings ViewModel second node stream.
Opcode and constant layouts follow the saved Microsoft winui-xbf source.
Unsupported nodes fail closed; no runtime object creation is performed.
"""
import hashlib,json,pathlib,struct
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parents[3]
path=ROOT/'work/settings-viewmodel-actual.xbf';b=path.read_bytes();start=12
assert hashlib.sha256(b).hexdigest()=='61212b95dde521924c56925b14718473ea3dd5d88a95d8d74e581c7311eecdd0'
major,minor=struct.unpack_from('<II',b,start);offsets=struct.unpack_from('<6Q',b,start+8);cursor=start+offsets[0]
def read(fmt):
 global cursor
 v=struct.unpack_from('<'+fmt,b,cursor);cursor+=struct.calcsize('<'+fmt);return v[0] if len(v)==1 else v
def string():
 global cursor
 n=read('I');v=b[cursor:cursor+2*n].decode('utf-16le');cursor+=2*n;return v
strings=[]
for _ in range(read('I')):strings.append(string());cursor+=2 if minor>=1 else 0
def table(offset):
 global cursor
 cursor=start+offset;return [read('III') for _ in range(read('I'))]
types=[strings[z] for x,y,z in table(offsets[3])];properties=[strings[z] for x,y,z in table(offsets[4])]
def token(values):
 n=read('H');return 'stable#'+str(n&32767) if n&32768 else values[n]
def constant():
 n=read('B')
 if n in (1,2,10):return {1:False,2:True,10:None}[n]
 if n==5:return token(strings)
 if n==9:return string()
 if n in (3,4,6,7,8,11):return read({3:'f',4:'i',6:'4f',7:'If',8:'I',11:'HI'}[n])
 raise ValueError(('Unsupported constant',n,hex(cursor)))
metadata_size=struct.unpack_from('<I',b,4)[0];cursor=start+metadata_size
streams=[read('II') for _ in range(read('I'))];base=cursor;begin,end=streams[1];cursor=base+begin;end+=base;nodes=[]
while cursor<end:
 pos=cursor;op=read('B');values=[]
 if op in (1,2,8,9,33,39):pass
 elif op in (3,18):values=[read('H'),string()]
 elif op in (4,10,12,13,14,34,35):values=[constant()]
 elif op in (7,32,19):values=[token(properties)]
 elif op in (20,23):values=[token(types)]
 elif op in (21,22,24,25):values=[token(types),constant()]
 elif op in (26,27,30,36):values=[token(properties),constant()]
 elif op==29:values=[token(properties),token(types)]
 elif op in (28,31):values=[token(properties),token(properties)]
 else:raise ValueError(('Unsupported node',op,hex(pos)))
 nodes.append({'fileOffset':hex(pos),'op':op,'values':values})
assert cursor==end
scope=[];objects=[]
for node in nodes:
 op=node['op'];v=node['values']
 if op in (1,18,19):scope.append(None)
 elif op==20:scope.append({'type':v[0],'fileOffset':node['fileOffset'],'properties':{}})
 elif op==26 and scope and scope[-1] is not None:scope[-1]['properties'][v[0]]=v[1]
 elif op==14 and scope and scope[-1] is not None:scope[-1]['resourceBag']=v[0]
 elif op in (2,33):
  obj=scope.pop()
  if obj is not None:objects.append(obj)
about=[x for x in objects if x['type']=='SettingsPageEntry' and x['properties'].get('Id') in ['SettingsPageAbout_ControlPanelSystem','SettingsPageAbout','SettingsPageAbout_New','SettingsPagePCSystemInfo']]
report={'source':str(path),'sha256':hashlib.sha256(b).hexdigest(),'decodedStream':1,'complete':True,'nodeCount':len(nodes),'scopeBalanced':not scope,'aboutEntries':about,'rootCustomRuntimeDataStreamDecoded':False}
(HERE/'xbf-about-evidence.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps({'nodeCount':len(nodes),'scopeBalanced':not scope,'aboutEntries':len(about)}))
