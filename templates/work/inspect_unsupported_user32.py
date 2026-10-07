from pathlib import Path
import sys,json,struct,bisect
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/user32.dll');base=p.OPTIONAL_HEADER.ImageBase
cmp=json.loads(Path('work/win32u-syscall-comparison.json').read_text());unsupported={x['name']:x for x in cmp['operations'] if x['status'] in ('missing-host','unknown-stub')}
iat={x.address-base:x.name.decode() for d in p.DIRECTORY_ENTRY_IMPORT if d.dll.lower()==b'win32u.dll' for x in d.imports if x.name and x.name.decode() in unsupported}
syms=json.loads(Path('work/user32-all-public-symbols.json').read_text());syms.sort();ad=[x[0] for x in syms]
sec=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text');data=sec.get_data();c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
refs=[]
for i in range(len(data)-7):
 size=0
 if data[i:i+2] in (b'\xff\x15',b'\xff\x25'):size=6
 elif data[i] in range(0x48,0x50) and data[i+1] in (0x8b,0x8d) and data[i+2]&0xc7==5:size=7
 if not size:continue
 target=sec.VirtualAddress+i+size+struct.unpack_from('<i',data,i+size-4)[0]
 if target not in iat:continue
 rv=sec.VirtualAddress+i
 if size==6 and i>0 and data[i-1] in range(0x40,0x50):rv-=1
 ix=bisect.bisect_right(ad,rv)-1;fn=syms[ix] if ix>=0 else [rv,'unknown']
 after=[f'{x.address:x}: {x.mnemonic} {x.op_str}' for x in c.disasm(p.get_data(rv,40),rv)]
 refs.append({'operation':iat[target],'instructionRVA':hex(rv),'publicSymbol':fn[1],'symbolRVA':hex(fn[0]),'instructions':after})
rows=[]
for target,n in iat.items():
 x=unsupported[n];rows.append({'name':n,'iatRVA':hex(target),'status':x['status'],'hostRVA':x['host']['rva'] if x['host'] else None,'referenceCount':sum(r['operation']==n for r in refs)})
Path('work/user32-unsupported-operations.json').write_text(json.dumps({'imports':rows,'references':refs},indent=2),encoding='utf8')
print('Imported unsupported',len(rows),'refs',len(refs))
for row in rows:
 if row['status']=='missing-host':
  print(row['name'],[(x['instructionRVA'],x['publicSymbol']) for x in refs if x['operation']==row['name']])
