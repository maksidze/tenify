import json,sys,struct
sys.path.insert(0,'work/pylib');import pefile,capstone
out={}
for label,path,rva in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll',0x541190),('host','C:/Windows/System32/twinui.pcshell.dll',0x6ee2f0)]:
 syms=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'));ns={}
 for s in syms:ns.setdefault(s['rva'],[]).append(s['name'])
 p=pefile.PE(path);d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);print(label);slots=[]
 for k in range(15):
  f=struct.unpack('<Q',p.get_data(rva+k*8,8))[0]-p.OPTIONAL_HEADER.ImageBase
  names=[n for n in ns.get(f,[]) if 'CVirtualDesktop@@' in n or 'VirtualDesktop2' in n]
  if k>2 and not names:break
  print(k,hex(f),names);slots.append({'slot':k,'rva':hex(f),'names':names})
 out[label]={'table':hex(rva),'slots':slots}
json.dump(out,open('work/vd-desktop-object-vtables.json','w'),indent=2)
