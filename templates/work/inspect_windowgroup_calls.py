import sys,pathlib,json,struct,bisect
sys.path.insert(0,str(pathlib.Path('work/pylib').resolve()))
import pefile,capstone
def pdbStreams(data):
 b,_,_,db,_,bm=struct.unpack_from('<6I',data,32);cnt=(db+b-1)//b
 blocks=struct.unpack_from('<'+str(cnt)+'I',data,bm*b)
 d=b''.join(data[x*b:(x+1)*b] for x in blocks)[:db]
 n=struct.unpack_from('<I',d)[0];sizes=struct.unpack_from('<'+str(n)+'I',d,4);pos=4+4*n;ss=[]
 for z in sizes:
  c=0 if z==0xffffffff else (z+b-1)//b
  bs=struct.unpack_from('<'+str(c)+'I',d,pos) if c else [];pos+=c*4
  ss.append(b''.join(data[x*b:(x+1)*b] for x in bs)[:z])
 return ss
base=pathlib.Path('outputs/Windows10-Components')
p=pefile.PE(str(base/'Image/4/Windows/System32/twinui.pcshell.dll'))
ss=pdbStreams(next((base/'Symbols/twinui.pcshell.pdb').rglob('twinui.pcshell.pdb')).read_bytes());idx=struct.unpack_from('<H',ss[3],20)[0];r=ss[idx];pos=0;syms=[]
while pos+4<=len(r):
 length,kind=struct.unpack_from('<HH',r,pos);end=pos+length+2
 if end>len(r) or length<2:break
 if kind==0x110e and length>=12:
  flags,off,seg=struct.unpack_from('<IIH',r,pos+4);name=r[pos+14:end].split(b'\0')[0].decode(errors='replace')
  if 0<seg<=len(p.sections):syms.append((p.sections[seg-1].VirtualAddress+off,name))
 pos=end
syms.sort();addrs=[x[0] for x in syms]
im={x.address-p.OPTIONAL_HEADER.ImageBase:x.ordinal for d in p.DIRECTORY_ENTRY_IMPORT if d.dll.lower()==b'user32.dll' for x in d.imports if x.ordinal in range(2628,2633)}
sec=next(x for x in p.sections if x.Name.rstrip(b'\0')==b'.text');data=sec.get_data();c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.detail=True
matches=[]
for i in range(len(data)-7):
 # RIP-relative call/jump or common rex MOV/LEA instructions.
 size=0
 if data[i:i+2] in (b'\xff\x15',b'\xff\x25'):size=6
 elif data[i] in range(0x48,0x50) and data[i+1] in (0x8b,0x8d) and data[i+2]&0xc7==5:size=7
 if not size:continue
 target=sec.VirtualAddress+i+size+struct.unpack_from('<i',data,i+size-4)[0]
 if target not in im:continue
 rv=sec.VirtualAddress+i
 if size==6 and i>0 and data[i-1] in range(0x40,0x50):rv-=1
 ind=bisect.bisect_right(addrs,rv)-1
 fn=syms[ind] if ind>=0 else (rv,'unknown')
 # Get exact function start from exception metadata, avoiding misaligned look-behind.
 runtime=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress),None)
 start=runtime.BeginAddress if runtime else rv
 instructions=list(c.disasm(p.get_data(start,rv-start+size+24),start))
 before=[f'{x.address:x}: {x.mnemonic} {x.op_str}' for x in instructions if x.address<=rv][-12:]
 matches.append({'ordinal':im[target],'iatRVA':hex(target),'referenceRVA':hex(rv),'nearestPublicSymbol':fn[1],'symbolRVA':hex(fn[0]),'runtimeFunctionStart':hex(start),'context':before})
out={'imports':{hex(k):v for k,v in im.items()},'references':matches,'relatedPublicSymbols':[{'rva':hex(a),'name':n} for a,n in syms if 'windowgroup' in n.lower()]}
pathlib.Path('work/windowgroup-pcshell-calls.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
print('References',len(matches))
for x in matches:print(x['ordinal'],x['referenceRVA'],x['nearestPublicSymbol'])
