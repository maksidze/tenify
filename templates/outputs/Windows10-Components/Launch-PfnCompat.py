"""Install tested USER32 compatibility only in a bootstrap's owned, entry-paused child.

No process creation, arbitrary PID, system file writes, or global registry changes.
The caller owns the child and must terminate it on any bootstrap failure.
"""
from pathlib import Path
import struct, hashlib, json

def exports(path):
    data=Path(path).read_bytes();nt=struct.unpack_from('<I',data,0x3c)[0];opt=nt+24
    if data[:2]!=b'MZ' or data[nt:nt+4]!=b'PE\0\0' or struct.unpack_from('<H',data,opt)[0]!=0x20b:
        raise ValueError('Expected x64 PE')
    count=struct.unpack_from('<H',data,nt+6)[0];size=struct.unpack_from('<H',data,nt+20)[0];sections=[]
    for index in range(count):
        at=opt+size+index*40;vs,rva,rawsize,raw=struct.unpack_from('<IIII',data,at+8);sections.append((rva,max(vs,rawsize),raw))
    def offset(rva):
        for start,length,raw in sections:
            if start<=rva<start+length:return raw+rva-start
        raise ValueError('Unmapped PE RVA')
    def string(rva):
        at=offset(rva);return data[at:data.index(b'\0',at)].decode('ascii')
    directory,length=struct.unpack_from('<II',data,opt+112);at=offset(directory)
    ordinal_base,nfunctions,nnames,functions,names,ordinals=struct.unpack_from('<IIIIII',data,at+16)
    byordinal={}
    for index in range(nfunctions):
        rva=struct.unpack_from('<I',data,offset(functions)+index*4)[0]
        if rva:byordinal[ordinal_base+index]={'rva':rva,'forwarder':string(rva) if directory<=rva<directory+length else None}
    byname={}
    for index in range(nnames):
        rva=struct.unpack_from('<I',data,offset(names)+index*4)[0];ordinal=ordinal_base+struct.unpack_from('<H',data,offset(ordinals)+index*2)[0]
        byname[string(rva)]=byordinal[ordinal]
    return byname,byordinal

def install_pfn_hook(bootstrap,directory):
    if not bootstrap.primary_suspended:raise RuntimeError('Owned child must be paused at its PE entrypoint')
    directory=Path(directory).resolve();manifest=json.loads((directory/'pfn-runtime-hashes.json').read_text(encoding='utf8'))
    for name,expected in manifest.items():
        if hashlib.sha256((directory/name).read_bytes()).hexdigest()!=expected:raise RuntimeError('PFN lab DLL hash mismatch: '+name)
    helper=directory/'UZER32.dll';byname,byordinal=exports(helper);changes=[];preserved=[]
    for slot in bootstrap.layout['imports']:
        if slot['dll'].lower()!='user32.dll':continue
        symbol=byname.get(slot['name']) if slot['name'] else byordinal.get(slot['ordinal'])
        if not symbol:raise RuntimeError('Old USER32 export absent: '+str(slot))
        if symbol['forwarder']:
            if symbol['forwarder']!='NTDLL.NtdllDefWindowProc_A':raise RuntimeError('Unresolved old USER32 forwarder')
            preserved.append(slot['name']);continue
        changes.append((slot['iatRva'],symbol['rva']))
    if not changes:raise RuntimeError('Owned EXE has no eligible USER32 import slots')
    remote=bootstrap.load_library(helper)
    for rva,target in changes:bootstrap.patch_iat(rva,remote+target)
    return {'helper':str(helper),'remoteBase':hex(remote),'slotsChanged':len(changes),'sameNativeForwardersPreserved':preserved,'signedExeOnDiskUnchanged':True}
