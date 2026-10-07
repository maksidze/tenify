from pathlib import Path
import hashlib,json,sys
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile,capstone
vm=B/'Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'
assert hashlib.sha256(vm.read_bytes()).hexdigest()=='a56da88f90b9464dbfe29d792cbacf837363be8b3af3225b759ef4b9c61249c1'
p=pefile.PE(str(vm));cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
lines=[]
for a,n in [(0x398dd,72),(0x3b7ac,180)]:
 lines+=['\n'+hex(a)]+[f'{i.address:x} {i.mnemonic} {i.op_str}' for i in cs.disasm(p.get_data(a,n),a)]
(H/'adapter-callsite.txt').write_text('\n'.join(lines))
guard=p.get_data(0x398e4,33)
assert guard[20:25]==bytes.fromhex('e8af1e0000')
header='/* Exact old VM call context. Patch only the five-byte call at+20. */\nstatic const BYTE callContext[]={' + ','.join('0x%02x'%x for x in guard)+'};\n'
(H/'DescriptionCallsite.h').write_text(header)
print('\n'.join(lines))
