from pathlib import Path
p=Path('outputs/Windows10-Components/Lab/IconResourceCompat/Build-MergedIcons.py')
s=p.read_text(encoding='utf-8-sig')
a=s.index(' handle=k.BeginUpdateResourceW');b=s.index(' merged=resources(dest)',a)
s=s[:a]+''' combined=dict(hr);combined.update(updates)
 # Serialize the complete data-only resource tree; UpdateResource refuses MUN additions.
 tree={}
 for (typ,ident,lang),data in combined.items():tree.setdefault(typ,{}).setdefault(ident,{})[lang]=data
 pe=pefile.PE(str(host));section=pe.sections[-1]
 if section.Name.rstrip(b'\\x00')!=b'.rsrc':raise RuntimeError('Expected final resource-only section')
 blob=bytearray();names=[];leaves=[]
 def reserve(n):
  at=len(blob);blob.extend(b'\\x00'*n);return at
 def ordered(node):return sorted(node,key=lambda v:(0,str(v)) if isinstance(v,str) else (1,v))
 def directory(node):
  keys=ordered(node);at=reserve(16+8*len(keys));struct.pack_into('<HH',blob,at+12,sum(isinstance(x,str) for x in keys),sum(isinstance(x,int) for x in keys))
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
 section.Misc_VirtualSize=len(blob);section.SizeOfRawData=align(len(blob),pe.OPTIONAL_HEADER.FileAlignment)
 pe.OPTIONAL_HEADER.SizeOfImage=align(section.VirtualAddress+len(blob),pe.OPTIONAL_HEADER.SectionAlignment);pe.OPTIONAL_HEADER.CheckSum=0
 pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress=section.VirtualAddress;pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size=len(blob)
 pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress=0;pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size=0
 raw=pe.write()[:section.PointerToRawData]+blob+b'\\x00'*(section.SizeOfRawData-len(blob));dest.write_bytes(raw)
''' +s[b:]
p.write_text(s,encoding='utf8')
q=p.parent/'Probe-OwnIcons.py';t=q.read_text(encoding='utf-8-sig').replace("['native','old-resource-overlay']","['native','old-resource-overlay','merged-resource-overlay']").replace("src=image/'SystemResources'/name;target=win/'SystemResources'/name","src=(lab/'MergedResources'/name) if preset=='merged-resource-overlay' else image/'SystemResources'/name;target=win/'SystemResources'/name")
t=t.replace("print(json.dumps({'run':str(run)","summary['baselineBlankIds']=[r['id'] for r in summary['comparisons'] if not r['nativeNonzero']]\n summary['newBlankRegressions']=[r['id'] for r in summary['comparisons'] if r['nativeNonzero'] and not r['oldNonzero']]\n summary['mergedPixelMatchesOld']=[a['id'] for a,b in zip(results['old-resource-overlay']['icons'],results['merged-resource-overlay']['icons']) if a['pixelSHA256']==b['pixelSHA256']]\n (lab/'own-resource-icon-probe.json').write_text(json.dumps(summary,indent=2),encoding='utf8')\n print(json.dumps({'run':str(run)")
q.write_text(t,encoding='utf8')
