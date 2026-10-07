import sys,json,struct
sys.path.insert(0,'work/pylib');import pefile
for label,path,a in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll',0x541190),('host','C:/Windows/System32/twinui.pcshell.dll',0x6ee2f0)]:
 p=pefile.PE(path);s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'));print(label)
 for n in (6,7,8,9):
  ptr=struct.unpack('<Q',p.get_data(a+n*8,8))[0]-p.OPTIONAL_HEADER.ImageBase
  print(n,hex(ptr),[r['name'] for r in s if r['rva']==ptr][:3])
