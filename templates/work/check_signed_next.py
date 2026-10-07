from pathlib import Path
import sys,json,struct
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
r=json.loads(Path('outputs/Windows10-Components/Lab/PfnCompat/signed-injected-probe.json').read_text(encoding='utf8'));p=pefile.PE('outputs/Windows10-Components/Lab/PfnCompat/W1N32U.dll');print('Classes',r['windowClasses']);print([(x.name.decode(),hex(x.address),x.ordinal) for x in p.DIRECTORY_ENTRY_EXPORT.symbols if x.name and x.ordinal==0x306]);m=r['ownedChildIATHook']['modulesAtHook'];base=int(next(v for k,v in m.items() if k.endswith('uzer32.dll')),16);e=next(x for x in r['debugEvents'] if x.get('type')=='exceptionContext');ret=struct.unpack_from('<Q',bytes.fromhex(e['stackBytes']))[0];print('CallerUSER32 return',hex(ret-base))
