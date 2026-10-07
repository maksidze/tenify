from pathlib import Path
import sys,json
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'work/pylib'))
import pefile
pe=pefile.PE('C:/Windows/System32/uxtheme.dll')
names={x['rva']:x['name'] for x in json.loads((ROOT/'work/compat-research/host-uxtheme/all-public-symbols.json').read_text())}
for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    name=e.name.decode() if e.name else names.get(e.address,'?')
    if not e.name or any(x in name for x in ('ThemeFile','LoadTheme','ThemeDataFrom','PrivateTheme','ApplyTheme')):
        print(f'{e.ordinal} {e.address:x} {name} {e.forwarder.decode() if e.forwarder else ""}')
