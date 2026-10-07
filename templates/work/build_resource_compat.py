from pathlib import Path
import sys,struct,json,hashlib,shutil
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
from keystone import Ks,KS_ARCH_X86,KS_MODE_64
base=Path('outputs/Windows10-Components').resolve();lab=base/'Lab/ResourceCompat';dst=lab/'FactoryWrapper';dst.mkdir(parents=True,exist_ok=True)
imagebase=0x180000000;rbase=0x2000;data=bytearray()
def reserve(n):p=len(data);data.extend(b'\0'*n);return p
def put(b):p=len(data);data.extend(b);return p
def astr(s):return put(s.encode('ascii')+b'\0')
def wstr(s):return put(s.encode('utf-16-le')+b'\0\0')
exports=reserve(40);funcs=reserve(16);names=reserve(16);ords=reserve(8);dllname=astr('RSCW10.dll')
forwarders={n:astr('COMBASE.'+n) for n in ['RoInitialize','RoUninitialize','RoActivateInstance']}
imports=reserve(60);iat_positions={}
for idx,(dll,fns) in enumerate([('COMBASE.dll',['RoGetActivationFactory']),('KERNEL32.dll',['VirtualProtect','OutputDebugStringW'])]):
    reserve((-len(data))%8)
    oft=reserve((len(fns)+1)*8);iat=reserve((len(fns)+1)*8);name=astr(dll)
    for i,f in enumerate(fns):
        hint=put(b'\0\0'+f.encode()+b'\0');struct.pack_into('<Q',data,oft+i*8,rbase+hint);struct.pack_into('<Q',data,iat+i*8,rbase+hint);iat_positions[f]=imagebase+rbase+iat+i*8
    struct.pack_into('<IIIII',data,imports+idx*20,rbase+oft,0,0,rbase+name,rbase+iat)
orig=reserve(8);prot=reserve(8)
guidFactory=put(bytes.fromhex('58ac8e4a52b69d458de1239471e8b22b'))
guidExt=put(bytes.fromhex('59e8258c4210a04d9232bf2aa8ff3726'))
pri=wstr(str(base/'Image/4/Windows/SystemResources/Windows.UI.ShellCommon/Windows.UI.ShellCommon.pri'))
oklog=wstr('[ResourceCompat] GetForSystemProfile manager LoadPriFileForSystemUse old ShellCommon S_OK\n')
badlog=wstr('[ResourceCompat] GetForSystemProfile manager LoadPriFileForSystemUse FAILED\n')
va=lambda p:imagebase+rbase+p
wrapper=imagebase+0x1000;getfor=imagebase+0x1400
asm=f'''
push rbx; push rsi; push rdi; sub rsp, 0x40
mov rsi, rdx; mov rdi, r8
mov rax, {iat_positions['RoGetActivationFactory']}; call qword ptr [rax]
mov ebx, eax; test eax,eax; js done
mov rax,{va(guidFactory)}; mov rcx,[rax]; cmp [rsi],rcx; jne done
mov rcx,[rax+8];cmp [rsi+8],rcx; jne done
mov rax,[rdi];mov rax,[rax];lea rcx,[rax+48]
mov edx,8; mov r8d,0x40; mov r9,{va(prot)}
mov rax,{iat_positions['VirtualProtect']};call qword ptr [rax]
test eax,eax; jz done
mov rax,[rdi];mov rax,[rax];mov rdx,[rax+48];mov rcx,{getfor}
cmp rdx,rcx; je restoreprotect
mov r8,{va(orig)};mov [r8],rdx;mov [rax+48],rcx
restoreprotect:
lea rcx,[rax+48];mov edx,8;mov rax,{va(prot)};mov r8d,[rax];lea r9,[rsp+32]
mov rax,{iat_positions['VirtualProtect']};call qword ptr [rax]
done: mov eax,ebx; add rsp,0x40;pop rdi;pop rsi;pop rbx;ret
'''
asm2=f'''
push rbx;push rsi;push rdi;sub rsp,0x30
mov rsi,rdx;mov rax,{va(orig)};call qword ptr [rax];mov ebx,eax;test eax,eax;js done
mov qword ptr [rsp+32],0
mov rcx,[rsi];mov rdx,{va(guidExt)};lea r8,[rsp+32];mov rax,[rcx];call qword ptr [rax]
test eax,eax;js fail
mov rcx,[rsp+32];mov rdx,{va(pri)};mov rax,[rcx];call qword ptr [rax+48];mov edi,eax
mov rcx,[rsp+32];mov rax,[rcx];call qword ptr [rax+16]
test edi,edi;js fail
mov rcx,{va(oklog)};jmp log
fail:mov rcx,{va(badlog)}
log:mov rax,{iat_positions['OutputDebugStringW']};call qword ptr [rax]
done:mov eax,ebx;add rsp,0x30;pop rdi;pop rsi;pop rbx;ret
'''
ks=Ks(KS_ARCH_X86,KS_MODE_64);code1=bytes(ks.asm(asm,wrapper)[0]);code2=bytes(ks.asm(asm2,getfor)[0]);code=code1+b'\x90'*(0x400-len(code1))+code2
reloc_entries=[];md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
for start,buf in [(wrapper,code1),(getfor,code2)]:
    for ins in md.disasm(buf,start):
        if ins.mnemonic=='movabs' and ins.imm_size==8:
            immediate=struct.unpack_from('<Q',ins.bytes,ins.imm_offset)[0]
            if imagebase<=immediate<imagebase+0x10000:reloc_entries.append((ins.address-imagebase+ins.imm_offset)&0xfff)
es=['RoActivateInstance','RoGetActivationFactory','RoInitialize','RoUninitialize']
for i,n in enumerate(es):
    struct.pack_into('<I',data,funcs+i*4,0x1000 if n=='RoGetActivationFactory' else rbase+forwarders[n]);struct.pack_into('<I',data,names+i*4,rbase+astr(n));struct.pack_into('<H',data,ords+i*2,i)
struct.pack_into('<IIHHIIIIIII',data,exports,0,0,0,0,rbase+dllname,1,4,4,rbase+funcs,rbase+names,rbase+ords)
align=lambda x,a:(x+a-1)//a*a
relocs=struct.pack('<II',0x1000,align(8+len(reloc_entries)*2,4))+b''.join(struct.pack('<H',0xa000+x) for x in reloc_entries)
relocs+=b'\0'*(align(len(relocs),4)-len(relocs))
textsize=align(len(code),0x200);rdsize=align(len(data),0x200);relocrva=align(rbase+len(data),0x1000)
h=bytearray(0x200);h[:2]=b'MZ';struct.pack_into('<I',h,0x3c,0x80);h[0x80:0x84]=b'PE\0\0';struct.pack_into('<HHIIIHH',h,0x84,0x8664,3,0,0,0,240,0x2022);o=0x98
struct.pack_into('<HBBIIIII',h,o,0x20b,14,0,textsize,rdsize+0x200,0,0,0x1000);struct.pack_into('<QII',h,o+24,imagebase,0x1000,0x200);struct.pack_into('<HHHHHHI',h,o+40,6,0,0,0,6,0,0);struct.pack_into('<IIIHH',h,o+56,relocrva+0x1000,0x200,0,2,0x160);struct.pack_into('<QQQQII',h,o+72,0x100000,0x1000,0x100000,0x1000,0,16)
struct.pack_into('<II',h,o+112,rbase+exports,len(data));struct.pack_into('<II',h,o+120,rbase+imports,60);struct.pack_into('<II',h,o+112+5*8,relocrva,len(relocs))
iatlow=min(iat_positions.values())-imagebase; iathi=max(iat_positions.values())-imagebase+16
struct.pack_into('<II',h,o+112+12*8,iatlow,iathi-iatlow)
for i,(n,vs,rva,size,raw,flags) in enumerate([(b'.text',len(code),0x1000,textsize,0x200,0x60000020),(b'.rdata',len(data),rbase,rdsize,0x200+textsize,0xc0000040),(b'.reloc',len(relocs),relocrva,0x200,0x200+textsize+rdsize,0x42000040)]):
    struct.pack_into('<8sIIIIIIHHI',h,o+240+i*40,n,vs,rva,size,raw,0,0,0,0,flags)
binary=h+code+b'\0'*(textsize-len(code))+data+b'\0'*(rdsize-len(data))+relocs+b'\0'*(0x200-len(relocs));shim=dst/'RSCW10.dll';shim.write_bytes(binary)
src=base/'Runtime/Explorer10/explorer.exe';pe=pefile.PE(str(src));patched=bytearray(src.read_bytes());oldimport=None
for dll in pe.DIRECTORY_ENTRY_IMPORT:
    if any(i.name==b'RoGetActivationFactory' for i in dll.imports):
        oldimport=dll.dll.decode();off=pe.get_offset_from_rva(dll.struct.Name);patched[off:off+len(dll.dll)+1]=b'RSCW10.dll\0'+b'\0'*(len(dll.dll)+1-11)
struct.pack_into('<H',patched,pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics'),pe.OPTIONAL_HEADER.DllCharacteristics&~0x80);struct.pack_into('<II',patched,pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(),0,0)
out=dst/'explorer.exe';out.write_bytes(patched);shutil.copytree(src.parent/'ru-RU',dst/'ru-RU',dirs_exist_ok=True)
report={'originalImport':oldimport,'newImport':'RSCW10.dll','oldExplorerCodeSectionsUnchanged':True,'signature':'LAB COPY ONLY invalidated; FORCE_INTEGRITY cleared on lab copy, not source/system','shimRelocationCount':len(reloc_entries),'shimSize':len(binary),'originalSHA256':hashlib.sha256(src.read_bytes()).hexdigest(),'patchedSHA256':hashlib.sha256(patched).hexdigest(),'purpose':'ResourceManager GetForSystemProfile: load old ShellCommon PRI into the SAME returned manager before Explorer requests StartUI'}
(dst/'patch-info.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
