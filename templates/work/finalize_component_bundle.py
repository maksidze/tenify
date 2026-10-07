from pathlib import Path
import json,hashlib,struct,uuid,csv,collections,re
sysbase=Path('outputs/Windows10-Components');meta=sysbase/'Metadata';image=Path('\\\\?\\'+str((sysbase/'Image').resolve()))
selection=json.loads((meta/'selection.json').read_text(encoding='utf-8'))
core=json.loads((meta/'core-binary-analysis.json').read_text(encoding='utf-8'));versions={x['path'].replace('/','\\'):x.get('version') for x in core}
with (meta/'files.csv').open('w',encoding='utf-8-sig',newline='') as f:
 w=csv.DictWriter(f,fieldnames=['path','category','bytes','version','sha256','wimSHA1']);w.writeheader()
 for x in selection:
  p=image/x['archivePath'];w.writerow({'path':x['path'],'category':x['category'],'bytes':p.stat().st_size,'version':versions.get(x['path'],''),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'wimSHA1':x['wimSHA1']})
downloads=json.loads((meta/'symbol-downloads.json').read_text(encoding='utf-8'))
for s in downloads:
 if s['status']!='downloaded':continue
 data=Path(s['path']).read_bytes();blockSize,_,_,directoryBytes,_,blockMap=struct.unpack_from('<6I',data,32)
 count=(directoryBytes+blockSize-1)//blockSize
 blocks=struct.unpack_from('<'+str(count)+'I',data,blockMap*blockSize)
 directory=b''.join(data[b*blockSize:(b+1)*blockSize] for b in blocks)[:directoryBytes]
 streamCount=struct.unpack_from('<I',directory)[0];sizes=struct.unpack_from('<'+str(streamCount)+'I',directory,4);offset=4+4*streamCount;streams=[]
 for size in sizes:
  n=0 if size==0xffffffff else (size+blockSize-1)//blockSize
  bs=struct.unpack_from('<'+str(n)+'I',directory,offset) if n else [];offset+=n*4
  streams.append(b''.join(data[b*blockSize:(b+1)*blockSize] for b in bs)[:size])
 info=streams[1];age=struct.unpack_from('<I',info,8)[0];guid=uuid.UUID(bytes_le=info[12:28]).hex.upper()
 dbiAge=struct.unpack_from('<I',streams[3],8)[0] if len(streams[3])>=12 else None
 key=guid+format(dbiAge if dbiAge is not None else age,'X')
 s.update(pdbInfoGUID=guid,pdbInfoAge=age,pdbDBIAge=dbiAge,codeviewMatch=key==s['key'],validation='RSDS GUID and DBI age; public PDB Info-stream age can differ after stripping')
 if not s['codeviewMatch']:print('PDB mismatch',s['pdb'],'PE key',s['key'],'PDB key',key)
(meta/'symbol-downloads.json').write_text(json.dumps(downloads,indent=2),encoding='utf-8')
tools=[]
for name,url in [('7zr.exe','https://github.com/ip7z/7zip/releases/download/26.03/7zr.exe'),('7z2603-x64.exe','https://github.com/ip7z/7zip/releases/download/26.03/7z2603-x64.exe')]:
 p=sysbase/'Tools'/name;tools.append({'file':name,'url':url,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'method':'Downloaded official 7-Zip release; installer unpacked locally, not installed'})
(meta/'tool-downloads.json').write_text(json.dumps(tools,indent=2),encoding='utf-8')
# Build separate launcher; no changes to previously used Explorer copies or launchers.
s=Path('outputs/Start-Explorer10.ps1').read_text(encoding='utf-8-sig')
s=s.replace('param([switch]$Guard, [string]$RunDirectory)','param([switch]$Guard, [string]$RunDirectory, [switch]$PreflightOnly)')
s=s.replace("$oldExe='C:\\Users\\MAKSIDZE\\Documents\\Explorer_10\\explorer.exe'", "$oldExe=Join-Path $PSScriptRoot 'Runtime\\Explorer10\\explorer.exe'")
xaml=Path('outputs/Start-Explorer10-Xaml.ps1').read_text(encoding='utf-8-sig')
code=xaml.split("Add-Type @'",1)[1].split("'@",1)[0]
s=re.sub(r"Add-Type @'.*?'@",lambda m:"Add-Type @'"+code+"'@",s,count=1,flags=re.S)
s=s.replace("foreach($language in 'ru-RU','en-US')", "foreach($language in 'ru-RU')")
needle="if((Get-Item -LiteralPath $oldExe).VersionInfo.FileVersion -notlike '10.0.19041.*'){throw 'Unexpected Explorer version'}"
s=s.replace(needle,needle+"\nif((Get-AuthenticodeSignature -LiteralPath $oldExe).Status -ne 'Valid'){throw 'Explorer signature is not valid; current shell unchanged'}\n[Explorer10Probe]::Preflight($oldExe)\nif($PreflightOnly){Write-Host 'PASS: signed ISO Explorer process can be created. Live shell unchanged.';exit 0}")
s=s.replace("$xamlExe=Join-Path $PSScriptRoot 'Explorer10-Xaml\\explorer.exe'", "$xamlExe=Join-Path (Split-Path $PSScriptRoot) 'Explorer10-Xaml\\explorer.exe'")
s=s.replace("if($existing.Path -ine $nativeExe -and $existing.Path -ine $xamlExe)","if($existing.Path -ine $nativeExe -and $existing.Path -ine $xamlExe -and $existing.Path -ine 'C:\\Users\\MAKSIDZE\\Documents\\Explorer_10\\explorer.exe')")
s=s.replace("Join-Path $PSScriptRoot 'Shell10-Test\\state\\restart-in-progress.json'", "Join-Path (Split-Path $PSScriptRoot) 'Shell10-Test\\state\\restart-in-progress.json'")
s+='\nexit 1\n'
(sysbase/'Start-Explorer10-ISO.ps1').write_text(s,encoding='utf-8-sig')
(sysbase/'Start-Explorer10-ISO.bat').write_text('''@echo off
setlocal
echo Start the signed Windows 10 Explorer extracted from D:.
echo Current Explorer windows will close. UAC is needed for a temporary restart guard.
"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Explorer10-ISO.ps1"
if errorlevel 1 pause
''',encoding='ascii')
for name in ['explorer-isolated-probe','applocal-immersive-probe']:
 r=json.loads((meta/(name+'.json')).read_text(encoding='utf-8'))
 paths=[x['path'] for x in r['modules'] if any(t in x['path'].lower() for t in ['twinui','immersiveshell','xaml'])]
 print(name,r.get('desktopAndTaskbarCreated'),paths)
print('PDB matches:',[s['codeviewMatch'] for s in downloads if s['status']=='downloaded'])
