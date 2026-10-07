"""Build isolated aliases only. No syscall execution and no writes to Windows."""
from pathlib import Path
import sys,struct,json,hashlib,shutil
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
base=Path('outputs/Windows10-Components');image=base/'Image/4/Windows';lab=base/'Lab/AliasCoreDLLs';lab.mkdir(parents=True,exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
entries=[]
def patch(source,target,replacements):
 original=source.read_bytes();p=pefile.PE(data=original);data=bytearray(original);changes=[]
 for kind in ['DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT']:
  for dll in getattr(p,kind,[]):
   name=dll.dll.decode('ascii');new=replacements.get(name.lower())
   if not new:continue
   assert len(new)==len(name)
   offset=p.get_offset_from_rva(dll.struct.Name)
   assert data[offset:offset+len(name)+1]==dll.dll+b'\0'
   data[offset:offset+len(name)+1]=new.encode()+b'\0'
   changes.append({'directory':kind,'offset':offset,'old':name,'new':new,'imports':len(dll.imports)})
 if replacements and not changes:raise RuntimeError('Import to patch absent: '+str(source))
 if changes:
  struct.pack_into('<H',data,p.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics'),p.OPTIONAL_HEADER.DllCharacteristics&~0x80)
  struct.pack_into('<II',data,p.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(),0,0)
  revised=pefile.PE(data=data)
  struct.pack_into('<I',data,revised.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),revised.generate_checksum())
 assert len(data)==len(original)
 target.write_bytes(data);q=pefile.PE(data=data)
 codeUnchanged=all(s.get_data()==t.get_data() for s,t in zip(p.sections,q.sections) if s.Characteristics&0x20)
 assert codeUnchanged
 entries.append({'source':str(source.resolve()),'target':str(target.resolve()),'sourceSHA256':sha(original),'targetSHA256':sha(data),'changes':changes,'codeSectionsUnchanged':codeUnchanged,'originalSignaturePreserved':not bool(changes),'entrypointRVA':hex(q.OPTIONAL_HEADER.AddressOfEntryPoint)})
 return q
win32u=patch(image/'System32/win32u.dll',lab/'W1N32U.dll',{})
user32=patch(image/'System32/user32.dll',lab/'UZER32.dll',{'win32u.dll':'W1N32U.dll'})
pcshell=patch(image/'System32/twinui.pcshell.dll',lab/'twinui.pcshell.dll',{'user32.dll':'UZER32.dll'})
explorer=patch(image/'explorer.exe',lab/'explorer.exe',{'user32.dll':'UZER32.dll'})
for source,targetName in [(image/'ru-RU/explorer.exe.mui','explorer.exe.mui'),(image/'System32/ru-RU/user32.dll.mui','UZER32.dll.mui'),(image/'System32/ru-RU/twinui.pcshell.dll.mui','twinui.pcshell.dll.mui')]:
 if source.is_file():
  (lab/'ru-RU').mkdir(exist_ok=True);shutil.copyfile(source,lab/'ru-RU'/targetName)
exportsByName={e.name for e in win32u.DIRECTORY_ENTRY_EXPORT.symbols if e.name};exportsByOrdinal={e.ordinal for e in win32u.DIRECTORY_ENTRY_EXPORT.symbols}
required=next(d for d in user32.DIRECTORY_ENTRY_IMPORT if d.dll.lower()==b'w1n32u.dll').imports
missing=[(i.name.decode() if i.name else '#'+str(i.ordinal)) for i in required if (i.name not in exportsByName if i.name else i.ordinal not in exportsByOrdinal)]
report={'status':'Aliases built; static import validation only, no Explorer launch','files':entries,'UZER32_to_W1N32U_imports':len(required),'missingWin32uExports':missing,'systemFilesModified':False,'syscallBodiesUnchanged':True,'warning':'W1N32U retains Windows 10 syscall numbers; successful mapping is not runtime compatibility. Patched USER32/pcshell/Explorer lab signatures are invalid.'}
(lab/'patch-info.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({'files':len(entries),'win32uImports':len(required),'missingWin32uExports':missing,'systemFilesModified':False},indent=2))
