"""Masked byte patterns, unique executable-section matches and semantic checks."""
from pathlib import Path
import struct
def parse(pattern):
    tokens=pattern.split();values=[];mask=[]
    if not tokens:raise ValueError('Empty signature')
    for token in tokens:
        if token in ['?','??']:values.append(0);mask.append(False)
        elif len(token)==2:
            try:values.append(int(token,16));mask.append(True)
            except ValueError:raise ValueError('Invalid signature token: '+token)
        else:raise ValueError('Invalid signature token: '+token)
    if sum(mask)<8:raise ValueError('Signature has fewer than eight fixed bytes')
    return bytes(values),mask
def matches(data,pattern):
    values,mask=parse(pattern);anchor=max((i for i in range(len(mask)) if mask[i]),key=lambda i:sum(mask[i:i+8]));end=anchor
    while end<len(mask) and mask[end]:end+=1
    needle=values[anchor:end];result=[];pos=0
    while True:
        at=data.find(needle,pos)
        if at<0:break
        start=at-anchor;pos=at+1
        if start>=0 and start+len(values)<=len(data) and all(not fixed or data[start+i]==values[i] for i,fixed in enumerate(mask)):result.append(start)
    return result
def unique_rva(path,pattern,delta=0):
    import pefile
    pe=pefile.PE(str(path),fast_load=True);found=[]
    try:
        for section in pe.sections:
            if section.Characteristics&0x20000000:
                found.extend(section.VirtualAddress+offset+delta for offset in matches(section.get_data(),pattern))
        if len(found)!=1:raise RuntimeError('Expected one executable signature match, found '+str(len(found))+': '+str(path))
        return found[0]
    finally:pe.close()
def resolve(profile,root):
    import pefile
    path=Path(root)/profile['Module'];sites={s['Name']:unique_rva(path,s['Pattern'],s.get('Delta',0)) for s in profile['Sites']}
    pe=pefile.PE(str(path),fast_load=True)
    try:
        for rule in profile.get('Checks',[]):
            at=sites[rule['Site']];data=pe.get_data(at,7)
            if rule['Kind']=='call-rel32':
                if data[0]!=0xe8 or at+5+struct.unpack_from('<i',data,1)[0]!=sites[rule['Target']]:raise RuntimeError('Relative call target differs from resolved factory signature')
            elif rule['Kind']=='lea-rip-wide-string':
                if data[:3]!=b'\x48\x8d\x0d':raise RuntimeError('Expected LEA RCX [RIP+disp32]')
                target=at+7+struct.unpack_from('<i',data,3)[0];expected=(rule['Value']+'\0').encode('utf-16-le')
                if pe.get_data(target,len(expected))!=expected:raise RuntimeError('Resolved Settings LEA does not reference the required DLL name')
            else:raise RuntimeError('Unknown semantic signature rule')
    finally:pe.close()
    return sites
