from pathlib import Path
import sys,json,hashlib
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
lab=root/'outputs/Windows10-Components/Lab/HostMultitaskingCompat';dll=lab/'twinui.pcshell.dll';pe=pefile.PE(str(dll));cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
points=[]
for rva,label in [(0x48ebd0,'HotKeyHandler.Initialize'),(0x48ec64,'HotKeyHandler.RegisterHotKeys'),(0x133b48,'HotKeyHandler.OnAltTab'),(0x187688,'MultitaskingView.CreateHost')]:
 points.append({'rva':rva,'label':label,'expectedByte':pe.get_data(rva,1).hex()})
 if rva in (0x48ebd0,0x48ec64):
  fn=next(x.struct for x in pe.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==rva)
  for i in cs.disasm(pe.get_data(rva,fn.EndAddress-rva),rva):
   if i.mnemonic=='ret':points.append({'rva':i.address,'label':label+'.Return','expectedByte':i.bytes[:1].hex()})
assert pe.get_data(0x133e81,2)==bytes.fromhex('7502')
config=[{'path':str(dll),'sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'points':points,
 'diagnosticPatches':[{'rva':0x133e81,'before':'7502','after':'9090',
 'reason':'During this explicit diagnostic child only, retain ordinary no-debugger Alt+Tab behavior; otherwise IsDebuggerPresent suppresses registration. Restored on detach.'}]}]
(lab/'trace-breakpoints.json').write_text(json.dumps(config,indent=2),encoding='utf8');print(json.dumps(config,indent=2))
