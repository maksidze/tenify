from pathlib import Path
import struct,json,sys,uuid
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
result={}
for tag,path in [('old','work/windowwatcher/old/4/Windows/System32/OneCoreUAPCommonProxyStub.dll'),('host','C:/Windows/System32/OneCoreUAPCommonProxyStub.dll')]:
 p=pefile.PE(path);base=p.OPTIONAL_HEADER.ImageBase
 sy=json.loads(Path(f'work/compat-research/{tag}-windowwatcher-ps/all-public-symbols.json').read_text()); names={x['name']:x['rva'] for x in sy}; byrv={x['rva']:x['name'] for x in sy}; interfaces={}; iidnames={}
 for s in sy:
  if s['name'].startswith('IID_'):
   try:iidnames[str(uuid.UUID(bytes_le=p.get_data(s['rva'],16)))]=s['name']
   except:pass
 for name,proxy in names.items():
  if not name.startswith('___x_Windows_CInternal_CApplicationModel_CWindowManagement_CI') or not name.endswith('ProxyVtbl'):continue
  stem=name[:-9];stub=names.get(stem+'StubVtbl')
  if stub is None:continue
  info,iid=struct.unpack('<QQ',p.get_data(proxy,16))
  if not info:continue
  desc,fmt,table=struct.unpack('<QQQ',p.get_data(info-base,24));types=struct.unpack('<Q',p.get_data(desc-base+64,8))[0]-base; count=struct.unpack('<I',p.get_data(stub+16,4))[0]
  def typ(off,depth=0):
   d=p.get_data(types+off,32);fc=d[0]
   if depth>8:return {'opaque':d.hex()}
   if d[:2]==b'\x2f\x5a':
    g=str(uuid.UUID(bytes_le=d[2:18]));return {'interface':g,'name':iidnames.get(g)}
   if fc in (0x11,0x12,0x13,0x14):
    return {'pointer':hex(fc),'flags':d[1],'to':{'base':hex(d[2])} if d[1]&8 else typ(off+2+struct.unpack_from('<h',d,2)[0],depth+1)}
   if fc==0x15:
    members=[];at=4
    while at<32:
     c=d[at]
     if c==0x5b:break
     if c==0x4c:
      members.append(typ(off+at+2+struct.unpack_from('<h',d,at+2)[0],depth+1));at+=4
     else:members.append({'format':hex(c)});at+=1
    return {'structSize':struct.unpack_from('<H',d,2)[0],'alignment':d[1],'members':members} if at<32 else {'opaque':d.hex()}
   return {'opaque':d.hex(),'format':hex(fc),'offset':hex(off)}
  methods=[]
  for slot in range(6,count):
   delta=struct.unpack('<H',p.get_data(table-base+slot*2,2))[0];data=p.get_data(fmt-base+delta,300)
   if data[:2]!=b'\x33\x6c':methods.append({'slot':slot,'unsupportedProcedure':data[:12].hex()});continue
   at=16+data[16];params=[]
   for n in range(data[15]):
    flags,stackoff,t=struct.unpack_from('<HHH',data,at+n*6)
    params.append({'attributes':hex(flags),'stackOffset':stackoff,'type':{'base':hex(t&255)} if flags&0x40 else typ(t)})
   methods.append({'slot':slot,'stackBytes':struct.unpack_from('<H',data,8)[0],'parameters':params,'procedureRVA':hex(fmt-base+delta)})
  syntaxcount,syntaxinfo=struct.unpack('<QQ',p.get_data(info-base+32,16));ndr64table=None
  for j in range(min(syntaxcount,4)):
   syntax=p.get_data(syntaxinfo-base+j*80,80)
   if str(uuid.UUID(bytes_le=syntax[:16]))=='71710533-beba-4937-8319-b5dbef9ccc36':ndr64table=struct.unpack_from('<Q',syntax,40)[0]-base
  if ndr64table is not None:
   for m in methods:m['NDR64ProcedureRVA']=hex(struct.unpack('<Q',p.get_data(ndr64table+m['slot']*8,8))[0]-base)
  interfaces[stem.split('_CWindowManagement_C')[-1]]={'IID':str(uuid.UUID(bytes_le=p.get_data(iid-base,16))),'count':count,'proxyInfoRVA':hex(info-base),'NDR64OffsetTableRVA':hex(ndr64table) if ndr64table is not None else None,'methods':methods}
 result[tag]=interfaces
Path('work/windowwatcher/all-ndr.json').write_text(json.dumps(result,indent=2))
print('Decoded',len(result['old']),len(result['host']))
drift=json.loads(Path('work/windowwatcher/interface-drift-counts.json').read_text());rows=[]
def clean(x):
 if isinstance(x,dict):return {k:clean(v) for k,v in x.items() if k not in ('name','offset')}
 if isinstance(x,list):return [clean(v) for v in x]
 return x
def opaque(x):
 if isinstance(x,dict):return 'opaque' in x or any(opaque(v) for v in x.values())
 if isinstance(x,list):return any(opaque(v) for v in x)
 return False
for d in drift:
 name=d['interface'];old=result['old'].get(name);host=result['host'].get(name);row={'interface':name,'oldIID':d['old']['IID'],'hostIID':d['host']['IID'] if d['host'] else None,'methods':[]}
 if old and host:
  for m in old['methods']:
   params=m.get('parameters');candidates=[h['slot'] for h in host['methods'] if params is not None and clean(params)==clean(h.get('parameters'))]
   certainty='opaque type; no semantic mapping' if opaque(params) else 'unique parameter signature; method identity requires caller proof' if len(candidates)==1 else 'ambiguous repeated signature' if candidates else 'no equal parameter signature'
   row['methods'].append({'oldSlot':m['slot'],'hostCandidates':candidates,'certainty':certainty,'parameters':params})
 rows.append(row)
Path('work/windowwatcher/interface-semantic-candidates.json').write_text(json.dumps(rows,indent=2))
print('Changed interfaces',len(rows),'semantic candidates saved; no patches generated')


