from pathlib import Path
import sys,struct,json,hashlib
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
r=Path('outputs/Windows10-Components/Lab/PfnCompat');f=r/'explorer.exe';d=bytearray(f.read_bytes());p=pefile.PE(data=d);off=p.get_offset_from_rva(0x154128);assert d[off:off+2]==b'\x75\x14';src=hashlib.sha256(d).hexdigest();d[off]=0x74
p=pefile.PE(data=d);struct.pack_into('<I',d,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),p.generate_checksum());f.write_bytes(d)
(r/'feeds-nullguard-compat-info.json').write_text(json.dumps({'sourceSHA256':src,'patchedSHA256':hashlib.sha256(d).hexdigest(),'rva':'0x154128','before':'7514','after':'7414','symbol':'Feeds::CompositionHost::~CompositionHost','reason':'Skip interface method dereference when [this+60] is null; preserve method call for actual interface. Exact original ISO bytes confirmed.','systemFilesModified':False},indent=2))
