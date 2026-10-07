from pathlib import Path
import sys,json,hashlib,collections
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'));import pefile
base=root/'outputs/Windows10-Components';out=base/'Lab/FlyoutCompat/OrdinalAudit';out.mkdir(exist_ok=True)
run=base/'state-vfs/f917b22fe7ea4468866915f04bb96405'
old=pefile.PE(str(base/'Image/4/Windows/System32/user32.dll'));host=pefile.PE('C:/Windows/System32/user32.dll');wu=pefile.PE('C:/Windows/System32/win32u.dll')
oldsyms=json.loads((root/'work/compat-research/old-user32/all-public-symbols.json').read_text());hostsyms=json.loads((root/'work/compat-research/host-user32/all-public-symbols.json').read_text())
for folder in ['old-user32','host-user32']:
 r=json.loads((root/f'work/compat-research/{folder}/symbols.json').read_text());p=Path(r['file']);p=p if p.is_absolute() else root/p
 assert r['pdbMatch'] and hashlib.sha256(p.read_bytes()).hexdigest()==r['sha256']
osbyr=collections.defaultdict(list);hsbyn=collections.defaultdict(list);hebyr=collections.defaultdict(list)
for s in oldsyms:osbyr[s['rva']].append(s['name'])
for s in hostsyms:hsbyn[s['name']].append(s['rva'])
for s in host.DIRECTORY_ENTRY_EXPORT.symbols:hebyr[s.address].append({'ordinal':s.ordinal,'name':s.name.decode() if s.name else None,'forwarder':s.forwarder.decode() if s.forwarder else None})
oe={s.ordinal:s for s in old.DIRECTORY_ENTRY_EXPORT.symbols};he={s.ordinal:s for s in host.DIRECTORY_ENTRY_EXPORT.symbols};wun={s.name.decode():s.address for s in wu.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
paths=list(dict.fromkeys(json.loads(line)['path'].removeprefix('\\\\?\\') for line in (run/'debug.jsonl').read_text(encoding='utf-8').splitlines() if json.loads(line).get('type')=='module'))
modules=[];uses=collections.defaultdict(list)
for ptext in paths:
 p=Path(ptext)
 if not p.is_file():continue
 try:
  pe=pefile.PE(str(p),fast_load=False);v=pe.VS_FIXEDFILEINFO[0];build=v.FileVersionLS>>16
 except Exception:continue
 if build not in [19041,19042,19043,19044,19045]:continue
 rows=[]
 for kind in ['DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT']:
  for d in getattr(pe,kind,[]):
   if d.dll.lower() not in [b'user32.dll',b'u32w10.dll',b'uzer32.dll']:continue
   for i in d.imports:
    if i.name:continue
    use={'module':ptext,'importDLL':d.dll.decode(),'kind':kind,'iatRva':hex(i.address-pe.OPTIONAL_HEADER.ImageBase),'ordinal':i.ordinal};rows.append(use);uses[i.ordinal].append(use)
 modules.append({'path':ptext,'build':build,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'user32OrdinalImports':rows})
maps=[]
for ordinal,used in sorted(uses.items()):
 e=oe.get(ordinal);native=he.get(ordinal);row={'oldOrdinal':ordinal,'uses':used}
 if e:
  names=[e.name.decode()] if e.name else osbyr[e.address];names=[n for n in names if not n.startswith('?') and not n.startswith('__imp')]
  row.update(oldRva=hex(e.address),oldNames=names,oldForwarder=e.forwarder.decode() if e.forwarder else None)
  matches=[]
  for n in names:
   for export in host.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name and export.name.decode()==n:
     matches.append({'matchedSymbol':n,'proof':'Exact PE export name equals old semantic PDB/export name','rva':hex(export.address),'ordinal':export.ordinal,'name':n,'forwarder':export.forwarder.decode() if export.forwarder else None})
   for rva in hsbyn.get(n,[]):
    for export in hebyr.get(rva,[]):matches.append({'matchedSymbol':n,'rva':hex(rva),**export})
  row['exactHostExportCandidates']=matches
  row['nativeWin32uByName']=[{'name':n,'rva':hex(wun[n]),'removedFailFastStub':wun[n]==0x1010} for n in names if n in wun]
 if native:
  row['hostSameOrdinal']={'rva':hex(native.address),'name':native.name.decode() if native.name else None,'symbols':next((s['name'] for s in hostsyms if s['rva']==native.address),None)}
 row['status']='exact-symbol-remap' if row.get('exactHostExportCandidates') else 'unsupported-or-needs-contract'
 maps.append(row)
report={'run':str(run),'scope':'Every actually loaded PE with old1904x version; only USER32/U32W10/UZER32 ordinal imports, static import and delay import. PDB GUID/age+binary SHA checked.','modules':modules,'ordinalMappings':maps,'noLiveChanges':True}
(out/'loaded-old-user32-ordinals.json').write_text(json.dumps(report,indent=2));print('Oldmodules',len(modules),'distinctordinals',len(maps),'uses',sum(len(r['uses']) for r in maps))
for r in maps:print(r['oldOrdinal'],','.join(r.get('oldNames',[])),'=>',[(x['ordinal'],x['name']) for x in r.get('exactHostExportCandidates',[])],r['status'])
