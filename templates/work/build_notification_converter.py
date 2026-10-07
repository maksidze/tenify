from pathlib import Path
import json,subprocess
base=Path('outputs/Windows10-Components/Lab/NotificationCompat').resolve()
schemas=[json.loads((base/f'{x}-ndr-schema.json').read_text()) for x in ['old','host']]
nodes=[{int(k):v for k,v in s['nodes'].items()} for s in schemas]
pairs=[];index={};fields=[];arms=[]
recordmap={**{x:x for x in [0,8,16,24,28]},32:40,40:48,44:52,48:64,56:72,60:76,
           **{x:x+16 for x in [64,72,80,88,96,100]},104:124,108:128,
           **{x:x+24 for x in [112,136,144,152,160,168,176,184,192,196,200,208,216,220]},
           224:252,**{x:x+24 for x in [232,240,248,256,264,272,288,304,312,320,324]},328:None,336:360}
def pair(a,b):
 key=(a,b)
 if key in index:return index[key]
 i=len(pairs);index[key]=i;pairs.append(None);o,h=nodes[0][a],nodes[1][b]
 if o['kind']!=h['kind']:raise ValueError(('kind',o,h))
 k=o['kind'];p={'kind':k,'oldSize':o['size'],'hostSize':h['size'],'oldNode':a,'hostNode':b}
 if k in ('scalar','userMarshal','stringPointer'):
  assert o['size']==h['size'] and o['token']==h['token'],(o,h)
  if k=='stringPointer':assert o['referentToken']==h['referentToken']
 elif k=='pointer':p['child']=pair(o['target'],h['target'])
 elif k=='struct':
  hf={f['offset']:f for f in h['fields']};fs=[]
  assert len(o['fields'])<=len(h['fields'])
  for j,f in enumerate(o['fields']):
   target=recordmap[f['offset']] if a==schemas[0]['root'] else h['fields'][j]['offset']
   try:child=pair(f['node'],hf[target]['node']) if target is not None else None
   except Exception as e:raise ValueError(('struct-field',hex(a),hex(b),hex(f['offset']),target)) from e
   fs.append({'oldOffset':f['offset'],'hostOffset':target,'child':child})
  p['fields']=fs
  if a==0x2e4 and b==0x2c2:p['rowTagTranslation']=True
 elif k=='array':
  assert o['count']==h['count'];p['count']=o['count'];p['child']=pair(o['element'],h['element'])
  if not p['count']:
   c=bytes.fromhex(h['correlation']);assert c[0]==0x19 and c[1]==0 and c[4:] in (b'\x01\x00',b'\x00\x00'),h
   p['countOffset']=int.from_bytes(c[2:4],'little',signed=True)
 elif k=='union':
  assert o['switchToken']==h['switchToken']==8 and o['switchOffset']==h['switchOffset']
  p['switchOffset']=h['switchOffset'];p['arms']={}
  # Host removed ImageList row kind 7, shifting Picker/Verb/KeyValue.
  # Confirmed by CopyQuactionRowData branches and their named Copy helpers.
  # New host feature-gated kind 10 has no verified old semantic equivalent.
  for hostcase in range(10):
   oldcase=hostcase if hostcase<7 else hostcase+1
   a2=o['arms'][str(oldcase)];h2=h['arms'][str(hostcase)];assert (a2 is None)==(h2 is None)
   p['arms'][hostcase]=pair(a2,h2) if a2 is not None else None
 else:raise ValueError(k)
 pairs[i]=p;return i
root=pair(schemas[0]['root'],schemas[1]['root'])
updated=pair(schemas[0]['updated'],schemas[1]['updated']);deleted=pair(schemas[0]['deleted'],schemas[1]['deleted'])
kinds={'scalar':0,'userMarshal':0,'stringPointer':0,'struct':1,'pointer':2,'array':3,'union':4}
rows=[]
for p in pairs:
 start=len(fields);count=0;astart=len(arms);acount=0
 for f in p.get('fields',[]):fields.append((f['oldOffset'],f['hostOffset'] or 0,f['child'] if f['child'] is not None else -1));count+=1
 for case,ch in p.get('arms',{}).items():arms.append((int(case),ch if ch is not None else -1));acount+=1
 rows.append((5 if p.get('rowTagTranslation') else kinds[p['kind']],p['oldSize'],p['hostSize'],p.get('child',-1),start,count,p.get('count',0),p.get('countOffset',0),p.get('switchOffset',0),astart,acount))
header='''/* Generated from GUID-matched Microsoft NDR descriptors. */
typedef struct {unsigned kind,oldSize,hostSize;int child;unsigned fields,fieldCount,count;int countOffset,switchOffset;unsigned arms,armCount;} Node;
typedef struct {unsigned oldOffset,hostOffset;int child;} Field;
typedef struct {unsigned value;int child;} Arm;
'''
def table(typ,name,data):return 'static const '+typ+' '+name+'[]={\n'+',\n'.join('{'+','.join(str(z) for z in row)+'}' for row in data)+'\n};\n'
header+=table('Node','nodes',rows)+table('Field','fields',fields)+table('Arm','arms',arms)
header+=f'enum {{ REFINED_ROOT={root}, UPDATED_ROOT={updated}, DELETED_ROOT={deleted} }};\n'
dest=Path('outputs/Windows10-Components/Lab/FlyoutCompat').resolve();(dest/'RefinedConverterSchema.h').write_text(header)
(dest/'record-converter-schema.json').write_text(json.dumps({'root':root,'updatedRoot':updated,'deletedRoot':deleted,'pairs':pairs,'omittedOldFields':[{'offset':'0x148','type':'wstring','reason':'Field removed from host NDR, converted to NULL'}]},indent=2))
print('Exact NDR converter:',len(pairs),'node pairs,',len(fields),'field maps; root',root)
