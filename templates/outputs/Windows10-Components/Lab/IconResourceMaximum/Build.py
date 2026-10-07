"""Private data-only resource copies. Never writes system or active IconResourceCompat files."""
from pathlib import Path
import json,sys,hashlib,struct
lab=Path(__file__).resolve().parent;root=lab.parents[3];sys.path.insert(0,str(root/'work/pylib'))
import pefile
def resources(path):
 p=pefile.PE(str(path),fast_load=True);r={};base=p.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress
 def walk(offset,prefix):
  header=p.get_data(base+offset,16);n=sum(struct.unpack_from('<HH',header,12))
  for i in range(n):
   name,target=struct.unpack('<II',p.get_data(base+offset+16+i*8,8))
   if name&0x80000000:
    pos=name&0x7fffffff;length=struct.unpack('<H',p.get_data(base+pos,2))[0];name=p.get_data(base+pos+2,length*2).decode('utf-16le')
   if target&0x80000000:walk(target&0x7fffffff,prefix+(name,))
   else:
    address,size,_,_=struct.unpack('<IIII',p.get_data(base+target,16));r[prefix+(name,)]=p.get_data(address,size)
 walk(0,())
 return r
def serialize(template,dest,combined):
 tree={}
 for (typ,ident,lang),data in combined.items():tree.setdefault(typ,{}).setdefault(ident,{})[lang]=data
 pe=pefile.PE(str(template));section=pe.sections[-1];assert section.Name.rstrip(b'\0')==b'.rsrc'
 blob=bytearray();names=[];leaves=[]
 def reserve(n):at=len(blob);blob.extend(b'\0'*n);return at
 def directory(node):
  keys=sorted(node,key=lambda v:(0,str(v)) if isinstance(v,str) else (1,v));at=reserve(16+8*len(keys));struct.pack_into('<HH',blob,at+12,sum(isinstance(x,str) for x in keys),sum(isinstance(x,int) for x in keys))
  for i,key in enumerate(keys):
   entry=at+16+8*i
   if isinstance(key,str):names.append((entry,key))
   else:struct.pack_into('<I',blob,entry,key)
   value=node[key]
   if isinstance(value,dict):target=directory(value);struct.pack_into('<I',blob,entry+4,target|0x80000000)
   else:target=reserve(16);struct.pack_into('<I',blob,entry+4,target);leaves.append((target,value))
  return at
 directory(tree)
 for entry,name in names:
  raw=name.encode('utf-16le');at=reserve(2+len(raw));struct.pack_into('<H',blob,at,len(raw)//2);blob[at+2:at+2+len(raw)]=raw;struct.pack_into('<I',blob,entry,at|0x80000000)
 for at,data in leaves:
  reserve((-len(blob))%4);pos=reserve(len(data));blob[pos:pos+len(data)]=data;struct.pack_into('<IIII',blob,at,section.VirtualAddress+pos,len(data),0,0)
 align=lambda n,a:(n+a-1)//a*a
 section.Misc_VirtualSize=len(blob);section.SizeOfRawData=align(len(blob),pe.OPTIONAL_HEADER.FileAlignment);pe.OPTIONAL_HEADER.SizeOfImage=align(section.VirtualAddress+len(blob),pe.OPTIONAL_HEADER.SectionAlignment);pe.OPTIONAL_HEADER.CheckSum=0
 pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress=section.VirtualAddress;pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size=len(blob);pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress=0;pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size=0
 dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(pe.write()[:section.PointerToRawData]+blob+b'\0'*(section.SizeOfRawData-len(blob)))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
inventory=json.loads((lab/'inventory.json').read_text());audit=json.loads((lab/'group-audit.json').read_text());failed={(x['Relative'],x['Group']) for x in audit['Failed']};records=[]
for item in inventory:
 if item.get('HostMissing') or not item['CommonGroups']:continue
 host=Path(item['Host']);old=Path(item['Old']);assert sha(host)==item['HostSHA256'] and sha(old)==item['OldSHA256']
 hr=resources(host);oldr=resources(old);used={k[1] for k in hr if k[0]==3 and isinstance(k[1],int)};newid=max(used,default=0)+1;updates={};accepted=[];skipped=[];assigned={}
 for group in item['CommonGroups']:
  if (item['Relative'],group) in failed:skipped.append(dict(Group=group,Reason='Decoder cannot validate this group; host retained'));continue
  keys=[k for k in oldr if k[0]==14 and k[1]==group]
  for key in keys:
   if key not in hr:continue
   data=bytearray(oldr[key]);count=struct.unpack_from('<H',data,4)[0]
   for n in range(count):
    oldid=struct.unpack_from('<H',data,6+14*n+12)[0];payloads=[(k,b) for k,b in oldr.items() if k[0]==3 and k[1]==oldid];assert payloads
    if oldid not in assigned:
     assert newid<=65535
     assigned[oldid]=newid
     for k,b in payloads:updates[3,newid,k[2]]=b
     used.add(newid);newid+=1
    struct.pack_into('<H',data,6+14*n+12,assigned[oldid])
   updates[key]=bytes(data)
  accepted.append(group)
 if not updates:continue
 combined=dict(hr);combined.update(updates);is_mun=item['Relative'].startswith('SystemResources')
 dest=lab/'MergedResources'/item['Relative'] if is_mun else lab/'ResourceOnlyContainers'/(host.name+'.mun')
 serialize(host if is_mun else Path('C:/Windows/SystemResources/imageres.dll.mun'),dest,combined)
 merged=resources(dest);untouched={k:b for k,b in hr.items() if k not in updates};assert all(merged.get(k)==b for k,b in untouched.items()),(str(dest),[(k,len(b),len(merged.get(k,b''))) for k,b in untouched.items() if merged.get(k)!=b][:4]);assert all(merged.get(k)==b for k,b in updates.items()),str(dest)
 records.append(dict(Host=str(host),Old=str(old),Private=str(dest),HostSHA256=sha(host),OldSHA256=sha(old),PrivateSHA256=sha(dest),ResourceGroups=accepted,Skipped=skipped,HostOnlyGroups=item['HostOnlyGroups'],AddedIconPayloadVariants=sum(k[0]==3 for k in updates),PreservedHostVariants=len(untouched),AllUntouchedHostResourcesByteExact=True,Mode='DataOnlyMUNVFS' if is_mun else 'ResourceOnlyLoaderRouteNoExecutableOverlay'))
manifest=dict(Version=1,Scope='Equivalent Windows system icon resources only',Records=records,Mappings=[dict(Source=x['Private'],Destination=x['Host'],Kind='File') for x in records if x['Mode']=='DataOnlyMUNVFS'],ResourceOnlyMappings=[dict(Source=x['Private'],Destination=x['Host']) for x in records if x['Mode']!='DataOnlyMUNVFS'],SystemFilesModified=False,BaseLaunchersModified=False)
(lab/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(dict(Files=len(records),MUNMappings=len(manifest['Mappings']),ResourceOnlyContainers=len(manifest['ResourceOnlyMappings']),Groups=sum(len(x['ResourceGroups']) for x in records),Bytes=sum(Path(x['Private']).stat().st_size for x in records))))
