from pathlib import Path
import sys,json
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
r=json.loads(Path('outputs/Windows10-Components/Lab/PfnCompat/csr-size-trace.json').read_text());m=next(x for x in r['modules'] if x['path'].endswith('W1N32U.dll'));addr=next(int(x['address'],16) for x in r['events'] if x.get('code')=='0xc000001d');rv=addr-int(m['base'],16);p=pefile.PE('outputs/Windows10-Components/Lab/PfnCompat/W1N32U.dll')
print('TrapRVA',hex(rv));print([(x.name.decode(),hex(x.address)) for x in p.DIRECTORY_ENTRY_EXPORT.symbols if x.name and x.address==rv-5])
