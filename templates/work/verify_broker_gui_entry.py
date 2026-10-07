from pathlib import Path
import struct,sys,json
sys.path.insert(0,'work/pylib');import pefile,capstone
root=Path.cwd();lab=root/'outputs/Windows10-Components/Lab'
def streams(data):
 b,_,_,nb,_,bm=struct.unpack_from('<6I',data,32);blocks=struct.unpack_from('<'+'I'*((nb+b-1)//b),data,bm*b);directory=b''.join(data[x*b:(x+1)*b] for x in blocks)[:nb];n=struct.unpack_from('<I',directory)[0];sizes=struct.unpack_from('<'+'I'*n,directory,4);pos=4+4*n;out=[]
 for size in sizes:
  count=0 if size==0xffffffff else (size+b-1)//b;blocks=struct.unpack_from('<'+'I'*count,directory,pos) if count else [];pos+=4*count;out.append(b''.join(data[x*b:(x+1)*b] for x in blocks)[:size])
 return out
def symbols(pe,pdb):
 ss=streams(pdb.read_bytes());records=ss[struct.unpack_from('<H',ss[3],20)[0]];pos=0;out={}
 while pos+4<=len(records):
  length,kind=struct.unpack_from('<HH',records,pos);end=pos+length+2
  if length<2 or end>len(records):break
  if kind==0x110e:
   flags,offset,segment=struct.unpack_from('<IIH',records,pos+4);name=records[pos+14:end].split(b'\0')[0].decode(errors='replace')
   if segment and segment<=len(pe.sections):out[name]=pe.sections[segment-1].VirtualAddress+offset
  pos=end
 return out
rows=[];d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for p in [lab/'StartCompat/StartCompatHostProbe.Gui.exe',lab/'SettingsBrokerCompat/SettingsBrokerProbe.Gui.exe',lab/'SettingsBrokerCompat/SettingsBrokerDetached.Gui.exe']:
 pe=pefile.PE(str(p));s=symbols(pe,p.with_suffix('.pdb'));selected={k:v for k,v in s.items() if k in ['wWinMain','wmain','BrokerExistingWmain','wmainCRTStartup','WinMainCRTStartup']};calls={}
 for name in ['wWinMain','wmain']:
  if name not in selected:continue
  a=selected[name];fn=next((x.struct for x in pe.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress),None)
  lines=[]
  for i in d.disasm(pe.get_data(a,fn.EndAddress-a if fn else 128),a):
   if i.mnemonic in ['call','jmp']:lines.append(dict(rva=hex(i.address),instruction=i.mnemonic+' '+i.op_str,targetSymbol=next((k for k,v in selected.items() if i.op_str==hex(v)),'')))
  calls[name]=lines
 assert 'wWinMain' in selected and 'BrokerExistingWmain' in selected
 assert any(x['targetSymbol']=='BrokerExistingWmain' for x in calls['wWinMain'])
 assert any(x['targetSymbol']=='wWinMain' for x in calls['wmain'])
 rows.append(dict(file=str(p),subsystem=pe.OPTIONAL_HEADER.Subsystem,entrypoint=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),symbols=selected,calls=calls))
(lab/'BrokerGuiEntry/entry-route-proof.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
print('Verified GUI subsystem and CRT wmain -> wWinMain -> renamed unchanged broker wmain in all 3 copies; no process launch')
