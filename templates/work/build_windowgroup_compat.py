"""Lab-only USER32 import adapter; unsupported WindowGroup calls fail with error 50."""
from pathlib import Path
import sys,struct,hashlib,json,ctypes as C
sys.path.insert(0,str(Path('work/pylib').resolve()));import pefile
base=Path('outputs/Windows10-Components');src=base/'Image/4/Windows/System32/twinui.pcshell.dll';pe=pefile.PE(str(src));lab=base/'Lab/WindowGroupCompat';lab.mkdir(parents=True,exist_ok=True)
missing={2628,2629,2630,2631,2632};names=set();ordinals=set()
for kind in ['DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT']:
 for dll in getattr(pe,kind,[]):
  if dll.dll.lower()==b'user32.dll':
   for i in dll.imports:
    if i.name:names.add(i.name.decode())
    else:ordinals.add(i.ordinal)
exported={};ordinal=1
for n in sorted(names):
 while ordinal in ordinals:ordinal+=1
 exported[ordinal]={'name':n,'forwarder':'USER32.'+n};ordinal+=1
for o in ordinals:exported[o]={'forwarder':'USER32.#'+str(o)} if o not in missing else {'stub':True}
align=lambda x,a:(x+a-1)//a*a
data=bytearray();rbase=0x2000
def reserve(n):
 pos=len(data);data.extend(b'\0'*n);return pos
def put(b):pos=len(data);data.extend(b);return pos
def string(s):return put(s.encode('ascii')+b'\0')
export=reserve(40);functionCount=max(exported);functions=reserve(functionCount*4);nameTable=reserve(len(names)*4);ordinalTable=reserve(len(names)*2);dllName=string('U32W10.dll')
named=[]
for o,d in exported.items():
 if d.get('stub'):address=0x1000
 else:address=rbase+string(d['forwarder'])
 struct.pack_into('<I',data,functions+(o-1)*4,address)
 if 'name' in d:named.append((d['name'],o))
for i,(n,o) in enumerate(sorted(named)):
 struct.pack_into('<I',data,nameTable+i*4,rbase+string(n));struct.pack_into('<H',data,ordinalTable+i*2,o-1)
exportSize=len(data)
struct.pack_into('<IIHHIIIIIII',data,export,0,0,0,0,rbase+dllName,1,functionCount,len(names),rbase+functions,rbase+nameTable,rbase+ordinalTable)
# The one code stub calls KERNEL32.SetLastError(ERROR_NOT_SUPPORTED) and returns FALSE.
while len(data)%8:data.append(0)
imports=reserve(40);oft=reserve(16);iat=reserve(16);kernelName=string('KERNEL32.dll');hint=put(b'\0\0SetLastError\0')
struct.pack_into('<QQ',data,oft,rbase+hint,0);struct.pack_into('<QQ',data,iat,rbase+hint,0)
struct.pack_into('<IIIII',data,imports,rbase+oft,0,0,rbase+kernelName,rbase+iat)
code=b'\x48\x83\xec\x28\xb9\x32\0\0\0\xff\x15'+struct.pack('<i',rbase+iat-(0x1000+15))+b'\x31\xc0\x48\x83\xc4\x28\xc3'
textRaw=0x200;rdataRaw=0x400;relocRaw=rdataRaw+align(len(data),0x200);relocRva=align(rbase+len(data),0x1000);relocs=struct.pack('<II',0x1000,8)
headers=bytearray(0x200);headers[:2]=b'MZ';struct.pack_into('<I',headers,0x3c,0x80);headers[0x80:0x84]=b'PE\0\0';struct.pack_into('<HHIIIHH',headers,0x84,0x8664,3,0,0,0,240,0x2022)
optional=0x98
struct.pack_into('<HBBIIIII',headers,optional,0x20b,14,0,align(len(code),0x200),align(len(data),0x200)+0x200,0,0,0x1000)
struct.pack_into('<QII',headers,optional+24,0x180000000,0x1000,0x200)
struct.pack_into('<HHHHHHI',headers,optional+40,6,0,0,0,6,0,0)
struct.pack_into('<IIIHH',headers,optional+56,relocRva+0x1000,0x200,0,2,0x160)
struct.pack_into('<QQQQII',headers,optional+72,0x100000,0x1000,0x100000,0x1000,0,16)
struct.pack_into('<II',headers,optional+112,rbase+export,exportSize)
struct.pack_into('<II',headers,optional+120,rbase+imports,40)
struct.pack_into('<II',headers,optional+112+5*8,relocRva,len(relocs))
struct.pack_into('<II',headers,optional+112+12*8,rbase+iat,16)
sectionOffset=optional+240
for i,(n,vs,rva,size,raw,flags) in enumerate([(b'.text',len(code),0x1000,0x200,textRaw,0x60000020),(b'.rdata',len(data),rbase,align(len(data),0x200),rdataRaw,0x40000040),(b'.reloc',len(relocs),relocRva,0x200,relocRaw,0x42000040)]):
 struct.pack_into('<8sIIIIIIHHI',headers,sectionOffset+i*40,n,vs,rva,size,raw,0,0,0,0,flags)
binary=headers+code+b'\0'*(0x200-len(code))+data+b'\0'*(align(len(data),0x200)-len(data))+relocs+b'\0'*(0x200-len(relocs))
shim=lab/'U32W10.dll';shim.write_bytes(binary);shimPe=pefile.PE(str(shim));shimPe.OPTIONAL_HEADER.CheckSum=shimPe.generate_checksum();shim.write_bytes(shimPe.write())
# Only this extracted lab copy is patched, never Windows/System32.
patched=bytearray(src.read_bytes());changes=[]
for dll in pe.DIRECTORY_ENTRY_IMPORT:
 if dll.dll.lower()==b'user32.dll':
  offset=pe.get_offset_from_rva(dll.struct.Name);patched[offset:offset+11]=b'U32W10.dll\0';changes.append({'field':'import DLL name','offset':offset,'old':'USER32.dll','new':'U32W10.dll'})
assert len(patched)==src.stat().st_size
integrity=pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics');struct.pack_into('<H',patched,integrity,pe.OPTIONAL_HEADER.DllCharacteristics&~0x80)
security=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];struct.pack_into('<II',patched,security.get_file_offset(),0,0)
patchedPe=pefile.PE(data=patched);struct.pack_into('<I',patched,patchedPe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),patchedPe.generate_checksum())
dst=lab/'twinui.pcshell.dll';dst.write_bytes(patched)
native=C.WinDLL(str(shim.resolve()),use_last_error=True)
getProc=C.WinDLL('kernel32',use_last_error=True).GetProcAddress;getProc.restype=C.c_void_p;getProc.argtypes=[C.c_void_p,C.c_void_p]
test=[]
for o in sorted(missing):
 f=C.WINFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,use_last_error=True)(getProc(native._handle,o));C.set_last_error(0);rv=f(None,None,None,None);err=C.get_last_error();test.append({'ordinal':o,'return':rv,'lastError':err})
 if rv!=0 or err!=50:raise RuntimeError('Stub contract failed')
report={'purpose':'LAB ONLY: WindowGroup feature unavailable on Windows11; return FALSE + ERROR_NOT_SUPPORTED, never fabricate success or kernel syscall numbers','sourceDLL':str(src.resolve()),'sourceSHA256':hashlib.sha256(src.read_bytes()).hexdigest(),'patchedSHA256':hashlib.sha256(patched).hexdigest(),'signature':'Patch invalidates signature on this separate lab DLL; signed Explorer and all system files untouched','changedImports':changes,'stubContractTest':test,'forwardedNames':len(names),'forwardedOrdinals':sorted(ordinals-missing),'codeSectionsUnchanged':all(a.get_data()==b.get_data() for a,b in zip(pe.sections,patchedPe.sections) if a.Characteristics&0x20)}
(lab/'patch-info.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
