import sys,json
sys.path.insert(0,'work/pylib');import pefile,capstone
for label,path in [('oldPCS','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll'),('oldExplorer','outputs/Windows10-Components/Runtime/Explorer10/explorer.exe'),('nativeExplorer','C:/Windows/explorer.exe')]:
 p=pefile.PE(path);print(label)
 for e in p.DIRECTORY_ENTRY_IMPORT+getattr(p,'DIRECTORY_ENTRY_DELAY_IMPORT',[]):
  for i in e.imports:
   if i.name and any(x in i.name for x in (b'SHTaskPool',b'SHSetThreadRef',b'SHGetThreadRef',b'SHCreateThread')):print(hex(i.address-p.OPTIONAL_HEADER.ImageBase),e.dll.decode(),i.name.decode())
