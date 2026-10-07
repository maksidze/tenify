from pathlib import Path
import sys,hashlib
sys.path.insert(0,'work/pylib');import pefile
base=Path('outputs/Windows10-Components/Image/4/Windows/SystemApps/Microsoft.Windows.Search_cw5n1h2txyewy')
for name in ['SearchApp.exe','SearchApi.dll','Search.Core.dll']:
 p=pefile.PE(str(base/name));print(name,'sha',hashlib.sha256((base/name).read_bytes()).hexdigest(),'entry',hex(p.OPTIONAL_HEADER.AddressOfEntryPoint))
 for d in p.DIRECTORY_ENTRY_IMPORT:
  for i in d.imports:
   if i.name and ('ActivationFactory' in i.name.decode() or 'Initialize' in i.name.decode() and 'Ro' in i.name.decode()):print(d.dll.decode(),i.name.decode(),hex(i.address-p.OPTIONAL_HEADER.ImageBase))
 print('DllGetActivationFactory',[(x.name.decode(),hex(x.address)) for x in p.DIRECTORY_ENTRY_EXPORT.symbols if x.name and b'ActivationFactory' in x.name])
