from pathlib import Path
import sys,json,hashlib
R=Path(__file__).resolve().parents[4];sys.path.insert(0,str(R/'work/pylib'))
import pefile
paths=[Path('C:/Windows/WinSxS/amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.5074_none_3e0d6f78e32fd63f/comctl32.dll'),Path('C:/Windows/System32/user32.dll'),Path('C:/Windows/System32/shell32.dll'),Path('C:/Windows/System32/uxtheme.dll')]
for path in paths:
 p=pefile.PE(str(path));print('\n',path,'SHA',hashlib.sha256(path.read_bytes()).hexdigest())
 for entry in list(getattr(p,'DIRECTORY_ENTRY_IMPORT',[]))+list(getattr(p,'DIRECTORY_ENTRY_DELAY_IMPORT',[])):
  for x in entry.imports:
   name=x.name.decode()if x.name else '#'+str(x.ordinal)
   if 'ThemeData'in name or 'WindowTheme'in name:print(hex(x.address-p.OPTIONAL_HEADER.ImageBase),entry.dll.decode(),name)
