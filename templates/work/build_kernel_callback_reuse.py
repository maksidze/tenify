from pathlib import Path
import sys,struct,json,hashlib
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
r=Path('outputs/Windows10-Components/Lab/PfnCompat');f=r/'UZER32.dll';d=bytearray(f.read_bytes());p=pefile.PE(data=d);off=p.get_offset_from_rva(0x1885b)
assert d[off:off+7]==bytes.fromhex('488d1d0e680700');old=hashlib.sha256(d).hexdigest();d[off:off+7]=bytes.fromhex('488b58580f1f00')
p=pefile.PE(data=d);struct.pack_into('<I',d,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),p.generate_checksum());f.write_bytes(d)
(r/'kernel-callback-reuse-info.json').write_text(json.dumps({'sourceSHA256':old,'patchedSHA256':hashlib.sha256(d).hexdigest(),'rva':'0x1885b','before':'488d1d0e680700','after':'488b58580f1f00','semantics':'RAX is current PEB from preceding gs:[60]. Obtain existing PEB KernelCallbackTable into RBX instead of old static table; original subsequent write preserves same native table.','remainingRisk':'Alternative mitigation-policy path later can clone and alter table; unchanged and unsupported pending trace.','systemFilesModified':False},indent=2))
