import sys,pathlib,json,struct
sys.path.insert(0,str(pathlib.Path(__file__).parent/'pylib'))
import pefile
host=pathlib.Path('C:/Windows/System32')
old=pathlib.Path('outputs/Windows10-Components/Image/4/Windows/System32').resolve()
names=['twinui.pcshell.dll','twinui.dll','windows.immersiveshell.serviceprovider.dll','twinui.appcore.dll']
p=pefile.PE(str(host/'apisetschema.dll'))
s=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.apiset')
b=s.get_data(); ver,size,flags,count,entryoff,_,_=struct.unpack_from('<7I',b)
assert ver==6,(ver,'unsupported API namespace version')
def wide(o,n):return b[o:o+n].decode('utf-16le')
apis={};hashed={}
for i in range(count):
 flags,no,nl,hl,vo,vc=struct.unpack_from('<6I',b,entryoff+i*24)
 vals=[]
 for j in range(vc):
  vf,ao,al,to,tl=struct.unpack_from('<5I',b,vo+j*20)
  vals.append({'alias':wide(ao,al),'host':wide(to,tl)})
 apis[wide(no,nl).lower()]=vals
 hashed[wide(no,hl).lower()]=vals
cache={}
def pe(path):
 key=str(path).lower()
 if key not in cache:
  try:cache[key]=pefile.PE(str(path))
  except (OSError,pefile.PEFormatError):cache[key]=None
 return cache[key]
def resolve(dll,parent):
 name=dll.lower().removesuffix('.dll')
 if name.startswith(('api-','ext-')):
  vs=apis.get(name) or hashed.get(name.rsplit('-',1)[0])
  if vs is None:return None,'Unresolved API-set contract'
  matched=next((v for v in vs if v['alias'].lower() in (parent.lower(),parent.lower().removesuffix('.dll'))),None)
  chosen=matched or next((v for v in vs if not v['alias']),None) or (vs[0] if vs else None)
  if not chosen or not chosen['host']:return None,'API-set empty host'
  return chosen['host'],'API-set'
 return dll,'Direct DLL'
def check(dll,symbol,parent,preset,visited=None):
 visited=set() if visited is None else visited
 resolved,kind=resolve(dll,parent)
 if not resolved:return {'status':'unresolved','reason':kind}
 fn=resolved if resolved.lower().endswith('.dll') else resolved+'.dll'
 path=old/fn if preset=='overlay' and fn.lower() in names else host/fn
 key=(str(path).lower(),symbol)
 if key in visited:return {'status':'cycle','dll':fn}
 visited.add(key)
 obj=pe(path)
 if obj is None:return {'status':'missing-file','dll':fn,'path':str(path),'resolution':kind}
 ex=getattr(obj,'DIRECTORY_ENTRY_EXPORT',None)
 hit=next((x for x in ex.symbols if (x.name==symbol.encode() if isinstance(symbol,str) else x.ordinal==symbol)),None) if ex else None
 if hit is None:return {'status':'missing-export','dll':fn,'path':str(path),'symbol':symbol,'resolution':kind}
 if hit.forwarder:
  target,ts=hit.forwarder.decode().rsplit('.',1)
  ans=check(target,int(ts[1:]) if ts.startswith('#') else ts,fn,preset,visited)
  if ans['status']!='ok':ans['forwardedFrom']=fn+'.'+str(symbol)
  return ans
 return {'status':'ok'}
rows=[]
for name in names:
 obj=pe(old/name)
 row={'file':name,'regularMissing':[],'delayMissing':[],'hostOnlyRegularMissing':[],'imports':[]}
 for kind,dirs in [('regular',getattr(obj,'DIRECTORY_ENTRY_IMPORT',[])),('delay',getattr(obj,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))]:
  for d in dirs:
   dn=d.dll.decode();resolved,how=resolve(dn,name)
   row['imports'].append({'contract':dn,'host':resolved,'kind':kind,'count':len(d.imports)})
   for x in d.imports:
    sym=x.name.decode() if x.name else x.ordinal
    ans=check(dn,sym,name,'overlay')
    if ans['status']!='ok':row['regularMissing' if kind=='regular' else 'delayMissing'].append({'importDLL':dn,'import':sym,**ans})
    if kind=='regular':
     ans=check(dn,sym,name,'host')
     if ans['status']!='ok':row['hostOnlyRegularMissing'].append({'importDLL':dn,'import':sym,**ans})
 rows.append(row)
out={'apiSetSchema':str(host/'apisetschema.dll'),'apiSetVersion':ver,'apiSetCount':count,'comparison':'Windows10 old mapped four DLLs; remaining resolved hosts Windows11; recursive export forwarder checks. Offline only.','files':rows}
pathlib.Path('work/usvfs-missing-imports.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
for row in rows:
 print(row['file'],'regular',len(row['regularMissing']),'delay',len(row['delayMissing']),'hostOnlyRegular',len(row['hostOnlyRegularMissing']))
 for x in row['regularMissing']:
  if x['status']!='unresolved':print(' ',x)
