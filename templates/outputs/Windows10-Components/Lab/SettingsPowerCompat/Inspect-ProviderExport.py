from pathlib import Path
import sys,struct
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile,capstone
p=pefile.PE(str(root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'));addr=next(e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols if e.name==b'GetSetting');cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
fn=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=addr<x.struct.EndAddress);ss=[]
for i in cs.disasm(p.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress):ss.append(f'{i.address:x} {i.mnemonic} {i.op_str}')
(Path(__file__).parent/'old-provider-export-disasm.txt').write_text('\n'.join(ss));print('\n'.join(ss[:55]))
