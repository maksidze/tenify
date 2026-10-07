from pathlib import Path
import sys,struct
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
lab=Path('outputs/Windows10-Components/Lab/XamlManifestCompat');data=bytearray((lab/'ManifestProbe.exe').read_bytes());p=pefile.PE(data=data);align=lambda n,a:(n+a-1)//a*a
hdr=p.sections[-1].get_file_offset()+40;assert hdr+40<=p.sections[0].PointerToRawData and not any(data[hdr:hdr+40])
rv=align(p.sections[-1].VirtualAddress+max(p.sections[-1].Misc_VirtualSize,p.sections[-1].SizeOfRawData),p.OPTIONAL_HEADER.SectionAlignment)
xml=Path('work/xaml-context.manifest').read_bytes();directory=struct.pack('<IIHHHH',0,0,0,0,0,1)
resource=directory+struct.pack('<II',24,0x80000018)+directory+struct.pack('<II',1,0x80000030)+directory+struct.pack('<II',1033,72)+struct.pack('<IIII',rv+88,len(xml),0,0)+xml
raw=align(len(data),p.OPTIONAL_HEADER.FileAlignment);size=align(len(resource),p.OPTIONAL_HEADER.FileAlignment);data.extend(bytes(raw+size-len(data)));data[raw:raw+len(resource)]=resource
data[hdr:hdr+40]=struct.pack('<8sIIIIIIHHI',b'.xamctx\0',len(resource),rv,size,raw,0,0,0,0,0x40000040)
struct.pack_into('<H',data,p.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),len(p.sections)+1)
struct.pack_into('<I',data,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(rv+len(resource),p.OPTIONAL_HEADER.SectionAlignment))
struct.pack_into('<II',data,p.OPTIONAL_HEADER.DATA_DIRECTORY[2].get_file_offset(),rv,len(resource))
(lab/'ManifestEmbedded.exe').write_bytes(data)
q=pefile.PE(data=data);assert q.DIRECTORY_ENTRY_RESOURCE.entries[0].id==24
print('Embedded actual RT_MANIFEST resource1',len(xml),'bytes')
