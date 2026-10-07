from pathlib import Path
import sys,json,hashlib
lab=Path(__file__).resolve().parent;root=lab.parents[3];sys.path.insert(0,str(root/'work/pylib'))
import pefile
old=root/'outputs/Windows10-Components/Image/4/Windows'
def icons(path):
 p=pefile.PE(str(path),fast_load=True);p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]);out={}
 for t in getattr(p,'DIRECTORY_ENTRY_RESOURCE',type('X',(),{'entries':[]})()).entries:
  if t.id not in (3,14):continue
  for e in t.directory.entries:
   for lang in e.directory.entries:
    d=lang.data.struct;out[t.id,str(e.name) if e.name else e.id,lang.id]=p.get_data(d.OffsetToData,d.Size)
 p.close();return out
records=[]
for directory,patterns in [('SystemResources',['*.mun']),('System32',['*.dll','*.cpl']),('',['explorer.exe'])]:
 for pattern in patterns:
  for p in (old/directory).glob(pattern):
   try:
    oldr=icons(p)
    if not any(k[0]==14 for k in oldr):continue
    relative=p.relative_to(old);host=Path('C:/Windows')/relative
    if not host.exists():records.append(dict(Relative=str(relative),HostMissing=True,OldGroups=len({k[1] for k in oldr if k[0]==14})));continue
    hr=icons(host);oldg={k[1] for k in oldr if k[0]==14};hg={k[1] for k in hr if k[0]==14}
    records.append(dict(Relative=str(relative),Old=str(p),Host=str(host),OldSHA256=hashlib.sha256(p.read_bytes()).hexdigest(),HostSHA256=hashlib.sha256(host.read_bytes()).hexdigest(),OldGroups=sorted(oldg,key=str),HostGroups=sorted(hg,key=str),CommonGroups=sorted(oldg&hg,key=str),HostOnlyGroups=sorted(hg-oldg,key=str),OldOnlyGroups=sorted(oldg-hg,key=str)))
   except pefile.PEFormatError:continue
(lab/'inventory.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
print(json.dumps(dict(IconFiles=len(records),Paired=sum(not r.get('HostMissing') for r in records),CommonGroups=sum(len(r.get('CommonGroups',[])) for r in records))))
