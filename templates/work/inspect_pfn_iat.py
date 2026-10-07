from pathlib import Path
import sys
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
p=pefile.PE('outputs/Windows10-Components/Runtime/Explorer10/explorer.exe');d=pefile.PE('outputs/Windows10-Components/Lab/PfnCompat/UZER32.dll');byname={x.name:x for x in d.DIRECTORY_ENTRY_EXPORT.symbols if x.name};byord={x.ordinal:x for x in d.DIRECTORY_ENTRY_EXPORT.symbols};i=next(x for x in p.DIRECTORY_ENTRY_IMPORT if x.dll.lower()==b'user32.dll');print('USER32 slots',len(i.imports));print('missing',[(x.name,x.ordinal) for x in i.imports if not (byname.get(x.name) if x.name else byord.get(x.ordinal))]);print('forwarders',[(x.name,(byname.get(x.name) if x.name else byord.get(x.ordinal)).forwarder) for x in i.imports if (byname.get(x.name) if x.name else byord.get(x.ordinal)).forwarder])
