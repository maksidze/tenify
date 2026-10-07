from pathlib import Path
import sys,json,hashlib
L=Path(__file__).resolve().parent;sys.path.insert(0,str(L.parents[3]/'work/pylib'));import pefile
paths=[Path('C:/Windows/System32/SystemSettings.DataModel.dll'),Path('C:/Windows/System32/Windows.UI.Xaml.dll'),Path('C:/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'),L.parents[1]/'Image/4/Windows/ImmersiveControlPanel/SystemSettings.dll',L.parents[1]/'Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll']
out=[]
for p in paths:
 pe=pefile.PE(str(p));items=[]
 for kind,desc in [('Regular',getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])),('Delay',getattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))]:
  for d in desc:
   for i in d.imports:
    name=i.name.decode() if i.name else '#'+str(i.ordinal)
    if any(n in name for n in ['Activation','Activate','LoadLibrary','GetProcAddress']):items.append(dict(Kind=kind,DLL=d.dll.decode(),Name=name,RVA=hex(i.address-pe.OPTIONAL_HEADER.ImageBase)))
 out.append(dict(Path=str(p),SHA256=hashlib.sha256(p.read_bytes()).hexdigest(),Imports=items))
(L/'factory-import-audit.json').write_text(json.dumps(out,indent=2));print(json.dumps(out[0],indent=2))
