from pathlib import Path
import sys,struct,json,hashlib
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
r=Path('outputs/Windows10-Components/Lab/PfnCompat');f=r/'UZER32.dll';d=bytearray(f.read_bytes());p=pefile.PE(data=d);off=p.get_offset_from_rva(0x1855d)
assert d[off:off+6]==bytes.fromhex('41 bd 40 02 00 00')
source=hashlib.sha256(d).hexdigest();d[off+2:off+6]=struct.pack('<I',0x248)
p=pefile.PE(data=d);struct.pack_into('<I',d,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),p.generate_checksum());f.write_bytes(d)
info={'sourceSHA256':source,'patchedSHA256':hashlib.sha256(d).hexdigest(),'patchRVA':'0x1855d','before':'41bd40020000','after':'41bd48020000','reason':'Match real host USER32 CSR connection size 0x248; stack allocation has room through rsp+0x2b8 before next local at rsp+0x2c0. Old shared-info copy consumes unchanged first 0x238 bytes after 8-byte header; host copies 0x240 bytes.','falseSuccess':False,'systemFilesModified':False}
(r/'csr-size-compat-info.json').write_text(json.dumps(info,indent=2))
