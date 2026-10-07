import sys
sys.path.insert(0,'work/pylib');import pefile
for path,rva in [('outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll',0x545198),('C:/Windows/System32/twinui.pcshell.dll',0x736d88)]:
 p=pefile.PE(path);print([(e.dll,i.name) for e in p.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.address-p.OPTIONAL_HEADER.ImageBase==rva])
