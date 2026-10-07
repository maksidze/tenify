from pathlib import Path
import sys,json,struct,hashlib,argparse
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
parser=argparse.ArgumentParser();parser.add_argument('--source',default='outputs/Windows10-Components/Lab/WindowGroupCompat/twinui.pcshell.dll');a=parser.parse_args();src=Path(a.source);out=Path('outputs/Windows10-Components/Lab/WindowWatcherCompat');out.mkdir(exist_ok=True);data=bytearray(src.read_bytes());p=pefile.PE(data=data);raw=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/twinui.pcshell.dll');cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;patches=[]
for func in [0x348e40,0x3491d0]:
 fn=next(x.struct for x in raw.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==func);inst=list(cs.disasm(raw.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress))
 for index,i in enumerate(inst):
  if i.mnemonic!='mov' or len(i.operands)!=2 or i.op_str.split(',')[0]!='rax':continue
  mem=i.operands[1]
  if mem.type!=capstone.x86.X86_OP_MEM or mem.mem.base!=capstone.x86.X86_REG_RAX or not 26*8<=mem.mem.disp<=52*8:continue
  beforeInst=inst[max(0,index-9):index];assert any(x.mnemonic=='mov' and x.op_str.startswith('rcx, qword ptr [') and x.op_str.endswith('+ 0x38]') for x in beforeInst),'Missing proven IAppViewWatcher receiver'
  old=mem.mem.disp;before=b'\x48\x8b\x80'+struct.pack('<I',old);after=b'\x48\x8b\x80'+struct.pack('<I',old+16);assert i.bytes==before;off=p.get_offset_from_rva(i.address);assert data[off:off+7]==before;data[off:off+7]=after;patches.append({'interface':'IAppViewWatcher','rva':hex(i.address),'before':before.hex(),'after':after.hex(),'oldSlot':old//8,'hostSlot':old//8+2,'context':[f'{x.address:x}: {x.mnemonic} {x.op_str}' for x in beforeInst]})
assert len(patches)==12,len(patches)
for rv,old,new,name in [(0x348908,0x90,0xa0,'IWindowWatcher.get_Status'),(0x348bc3,0x98,0xa8,'IWindowWatcher.Start')]:
 off=p.get_offset_from_rva(rv);before=b'\x48\x8b\x80'+struct.pack('<I',old);after=b'\x48\x8b\x80'+struct.pack('<I',new);assert bytes(data[off:off+7])==before;data[off:off+7]=after;patches.append({'interface':'IWindowWatcher','rva':hex(rv),'before':before.hex(),'after':after.hex(),'method':name,'oldSlot':old//8,'hostSlot':new//8})
p=pefile.PE(data=data);struct.pack_into('<I',data,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),p.generate_checksum());(out/'twinui.pcshell.dll').write_bytes(data)
info={'source':str(src.resolve()),'sourceSHA256':hashlib.sha256(src.read_bytes()).hexdigest(),'patchedSHA256':hashlib.sha256(data).hexdigest(),'patches':patches,'methodMaps':{'IWindowWatcher':{str(i):i if i<16 else i+2 for i in range(21)},'IAppViewWatcher':{str(i):i if i<26 else i+2 for i in range(53)}},'proof':'Official matching old/host proxy PDB and NDR parameter shapes and event handler GUIDs. Original object offsets validated: watcher+c0, appwatcher+38. Host wire ABI retained by calling corrected host vtable slots.','systemFilesModified':False,'globalRegistryModified':False,'liveShellModified':False}
(out/'watchers-slot-patch.json').write_text(json.dumps(info,indent=2),encoding='utf8');print('Patched',len(patches),'calls',info['patchedSHA256']);print([(x['interface'],x['rva'],x['oldSlot'],x['hostSlot']) for x in patches])
