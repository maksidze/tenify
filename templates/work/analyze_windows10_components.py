from pathlib import Path
import sys,json,hashlib,struct,uuid,urllib.request,concurrent.futures,csv
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
base=Path('outputs/Windows10-Components');image=base/'Image/4'
targets=['Windows/explorer.exe','Windows/System32/twinui.pcshell.dll','Windows/System32/twinui.dll','Windows/System32/windows.immersiveshell.serviceprovider.dll','Windows/System32/Windows.UI.Xaml.dll','Windows/ImmersiveControlPanel/SystemSettings.exe','Windows/ImmersiveControlPanel/SystemSettings.dll','Windows/SystemApps/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/StartMenuExperienceHost.exe','Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy/ShellExperienceHost.exe']
rows=[];symbols=[]
for rel in targets:
 p=image/rel
 if not p.is_file():continue
 data=p.read_bytes();pe=pefile.PE(data=data)
 version=None
 if getattr(pe,'VS_FIXEDFILEINFO',None):
  v=pe.VS_FIXEDFILEINFO[0];version='.'.join(map(str,[v.FileVersionMS>>16,v.FileVersionMS&65535,v.FileVersionLS>>16,v.FileVersionLS&65535]))
 imports=[]
 for attr in ['DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT']:
  for dll in getattr(pe,attr,[]):imports.append({'dll':dll.dll.decode(errors='replace'),'kind':attr,'functions':[i.name.decode(errors='replace') if i.name else '#'+str(i.ordinal) for i in dll.imports]})
 debug=[]
 for d in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
  raw=data[d.struct.PointerToRawData:d.struct.PointerToRawData+d.struct.SizeOfData]
  if raw[:4]==b'RSDS':
   name=raw[24:].split(b'\0')[0].decode(errors='replace').replace('\\','/').rsplit('/',1)[-1]
   guid=uuid.UUID(bytes_le=raw[4:20]).hex.upper();age=struct.unpack_from('<I',raw,20)[0];key=guid+format(age,'X')
   debug.append({'pdb':name,'guid':guid,'age':age,'key':key})
   if p.name.lower() in ('explorer.exe','twinui.pcshell.dll','windows.immersiveshell.serviceprovider.dll'):
    symbols.append({'image':rel,'pdb':name,'key':key,'url':f'https://msdl.microsoft.com/download/symbols/{name}/{key}/{name}'})
 rows.append({'path':rel,'version':version,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'dllCharacteristics':hex(pe.OPTIONAL_HEADER.DllCharacteristics),'codeview':debug,'imports':imports})
(base/'Metadata/core-binary-analysis.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
def download(s):
 dest=base/'Symbols'/s['pdb']/s['key']/s['pdb'];dest.parent.mkdir(parents=True,exist_ok=True)
 try:
  with urllib.request.urlopen(urllib.request.Request(s['url'],headers={'User-Agent':'Microsoft-Symbol-Server/10.0'}),timeout=45) as r:
   with dest.with_suffix('.download').open('wb') as f:
    while True:
     b=r.read(1024*1024)
     if not b:break
     f.write(b)
  temp=dest.with_suffix('.download')
  with temp.open('rb') as f:magic=f.read(32)
  if not magic.startswith(b'Microsoft C/C++ MSF'):raise RuntimeError('Not an MSF PDB')
  temp.replace(dest)
  s.update(status='downloaded',size=dest.stat().st_size,path=str(dest.resolve()),sha256=hashlib.sha256(dest.read_bytes()).hexdigest())
 except Exception as e:s.update(status='failed',error=str(e))
 return s
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(download,symbols))
(base/'Metadata/symbol-downloads.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
print(json.dumps({'binaries':[{'file':x['path'],'version':x['version']} for x in rows],'symbols':results},indent=2))
# Runtime folder deliberately contains just the signed EXE and matching MUI.
runtime=base/'Runtime/Explorer10';runtime.mkdir(parents=True,exist_ok=True)
import shutil
shutil.copy2(image/'Windows/explorer.exe',runtime/'explorer.exe')
for lang in ('ru-RU','en-US'):
 src=image/'Windows'/lang/'explorer.exe.mui'
 if src.is_file():(runtime/lang).mkdir(exist_ok=True);shutil.copy2(src,runtime/lang/'explorer.exe.mui')
