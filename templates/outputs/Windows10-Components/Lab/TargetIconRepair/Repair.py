"""Two explicitly scoped repairs. No Explorer restart, VFS, input or cache deletion."""
from pathlib import Path
import argparse,ctypes as C,ctypes.wintypes as W,hashlib,json,os,struct,subprocess,time,uuid
LAB=Path(__file__).resolve().parent;BASE=LAB.parents[1]
PIN=Path(os.environ['APPDATA'])/'Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/File Explorer.lnk'
FOLDER=None # Per-user diagnostic folder is not part of the distributable project.
RESOURCE=BASE/'Lab/IconResourceMaximum/ResourceOnlyContainers/explorer.exe.mun'
PIN_EXE=BASE/'Lab/NoVfsShellCompat/PinIcon.exe';PROBE=BASE/'Lab/FolderIconCompat/FolderCacheProbe.exe';DLL=BASE/'Lab/IconRoutesNoVfsCompat/IconRoutes.NoVfs.dll'
ACTIVE=LAB/'active.json';BAD=C.c_void_p(-1).value
def sha(x):return hashlib.sha256(x if isinstance(x,bytes)else Path(x).read_bytes()).hexdigest()
def save(p,data):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);temp=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
 with temp.open('w',encoding='utf-8')as f:json.dump(data,f,indent=2,ensure_ascii=False);f.flush();os.fsync(f.fileno())
 os.replace(temp,p)
def saved_bytes(p,data):
 with Path(p).open('xb')as f:f.write(data);f.flush();os.fsync(f.fileno())
def under(p,root):return Path(p).resolve().is_relative_to(Path(root).resolve())
def validate():
 pins=json.loads((LAB/'pins.json').read_text())
 for path,expected in pins['Files'].items():
  if sha(path)!=expected:raise RuntimeError('Pinned input changed: '+path)
 m=json.loads((BASE/'Lab/IconRoutesNoVfsCompat/manifest.json').read_text())
 if not m['OwnProofPassed']or m['USVFS']:raise RuntimeError('No-VFS proof missing')
 for relative,expected in m['Files'].items():
  if sha(BASE/'Lab/IconRoutesNoVfsCompat'/relative)!=expected:raise RuntimeError('Adapter file changed: '+relative)
 for path,expected in m['Dependencies'].items():
  if sha(path)!=expected:raise RuntimeError('Adapter dependency changed: '+path)
 return pins
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True)
def api(d,n,r,a):f=getattr(d,n);f.restype=r;f.argtypes=a;return f
close=api(k,'CloseHandle',W.BOOL,[W.HANDLE]);wait=api(k,'WaitForSingleObject',W.DWORD,[W.HANDLE,W.DWORD]);term=api(k,'TerminateProcess',W.BOOL,[W.HANDLE,W.UINT]);exitCode=api(k,'GetExitCodeProcess',W.BOOL,[W.HANDLE,C.POINTER(W.DWORD)])
mutexCreate=api(k,'CreateMutexW',W.HANDLE,[C.c_void_p,W.BOOL,W.LPCWSTR]);mutexRelease=api(k,'ReleaseMutex',W.BOOL,[W.HANDLE])
class SI(C.Structure):_fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('reserved2',W.WORD),('reservedPtr',C.c_void_p),('stdin',W.HANDLE),('stdout',W.HANDLE),('stderr',W.HANDLE)]
class PI(C.Structure):_fields_=[('process',W.HANDLE),('thread',W.HANDLE),('pid',W.DWORD),('tid',W.DWORD)]
create=api(k,'CreateProcessW',W.BOOL,[W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,W.DWORD,C.c_void_p,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)])
createDesktop=api(u,'CreateDesktopW',W.HANDLE,[W.LPCWSTR,W.LPCWSTR,C.c_void_p,W.DWORD,W.DWORD,C.c_void_p]);closeDesktop=api(u,'CloseDesktop',W.BOOL,[W.HANDLE])
createJob=api(k,'CreateJobObjectW',W.HANDLE,[C.c_void_p,W.LPCWSTR]);setJob=api(k,'SetInformationJobObject',W.BOOL,[W.HANDLE,C.c_int,C.c_void_p,W.DWORD]);assign=api(k,'AssignProcessToJobObject',W.BOOL,[W.HANDLE,W.HANDLE]);resume=api(k,'ResumeThread',W.DWORD,[W.HANDLE])
def child(exe,args,seconds):
 name='TargetIcons_'+uuid.uuid4().hex;desk=createDesktop(name,None,None,0,0x1ff,None);job=None;pi=PI();result=None
 if not desk:raise C.WinError(C.get_last_error())
 try:
  job=createJob(None,None)
  if not job:raise C.WinError(C.get_last_error())
  limits=C.create_string_buffer(144);struct.pack_into('<I',limits,16,0x2000)
  if not setJob(job,9,limits,len(limits)):raise C.WinError(C.get_last_error())
  si=SI();si.cb=C.sizeof(si);si.desktop='WinSta0\\'+name;si.flags=1;si.show=0
  cmd=C.create_unicode_buffer(subprocess.list2cmdline([str(exe)]+[str(a)for a in args]))
  if not create(str(exe),cmd,None,None,False,0x08000004,None,str(LAB),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
  if not assign(job,pi.process):raise C.WinError(C.get_last_error())
  if resume(pi.thread)==0xffffffff:raise C.WinError(C.get_last_error())
  timed=wait(pi.process,int(seconds*1000))!=0
  if timed:term(pi.process,0xdec9);wait(pi.process,5000)
  code=W.DWORD()
  if not exitCode(pi.process,C.byref(code)):raise C.WinError(C.get_last_error())
  result=dict(PID=pi.pid,ExitCode=code.value,TimedOut=timed,CreateNoWindow=True,PrivateDesktop=True,KillOnCloseJob=True)
 finally:
  if pi.process and wait(pi.process,0)!=0:term(pi.process,0xdec9);wait(pi.process,5000)
  if pi.thread:close(pi.thread)
  if pi.process:close(pi.process)
  if job:close(job)
  closed=bool(closeDesktop(desk))
 if result is not None:result['DesktopClosed']=closed
 return result
createFile=api(k,'CreateFileW',W.HANDLE,[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE]);sizeFile=api(k,'GetFileSizeEx',W.BOOL,[W.HANDLE,C.POINTER(C.c_longlong)]);readFile=api(k,'ReadFile',W.BOOL,[W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p]);writeFile=api(k,'WriteFile',W.BOOL,[W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p]);seek=api(k,'SetFilePointerEx',W.BOOL,[W.HANDLE,C.c_longlong,C.c_void_p,W.DWORD]);eof=api(k,'SetEndOfFile',W.BOOL,[W.HANDLE]);flush=api(k,'FlushFileBuffers',W.BOOL,[W.HANDLE]);getFinal=api(k,'GetFinalPathNameByHandleW',W.DWORD,[W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD]);getInfo=api(k,'GetFileInformationByHandle',W.BOOL,[W.HANDLE,C.c_void_p])
def read_handle(h):
 n=C.c_longlong()
 if not sizeFile(h,C.byref(n))or n.value<76 or n.value>4*1024*1024:raise RuntimeError('Unexpected shortcut length')
 if not seek(h,0,None,0):raise C.WinError(C.get_last_error())
 b=C.create_string_buffer(n.value);got=W.DWORD()
 if not readFile(h,b,n.value,C.byref(got),None)or got.value!=n.value:raise C.WinError(C.get_last_error())
 return b.raw
def write_handle(h,data):
 if not seek(h,0,None,0):raise C.WinError(C.get_last_error())
 written=W.DWORD();b=C.create_string_buffer(data)
 if not writeFile(h,b,len(data),C.byref(written),None)or written.value!=len(data):raise RuntimeError('Incomplete shortcut write')
 if not eof(h)or not flush(h):raise C.WinError(C.get_last_error())
 if read_handle(h)!=data:raise RuntimeError('Shortcut write readback differs')
def replace_owned(path,expected,data):
 # Deny concurrent writes and renames. Writes use this verified file handle,
 # never a second pathname lookup after the ownership check.
 h=createFile(str(path),0xc0000000,1,None,3,0x00200000,None)
 if h==BAD:raise C.WinError(C.get_last_error())
 try:
  info=C.create_string_buffer(52)
  if not getInfo(h,info):raise C.WinError(C.get_last_error())
  attributes=struct.unpack_from('<I',info)[0]
  if attributes&(0x400|0x10):raise RuntimeError('Shortcut is a directory/reparse point')
  resolved=C.create_unicode_buffer(32768);n=getFinal(h,resolved,len(resolved),0)
  if not n or n>=len(resolved)or resolved.value.removeprefix('\\\\?\\').casefold()!=str(path.resolve()).casefold():raise RuntimeError('Shortcut physical path differs')
  current=read_handle(h)
  if sha(current)!=expected:return dict(Status='PreservedForeignChange',CurrentSHA256=sha(current))
  try:write_handle(h,data)
  except Exception:
   # Still holding the same exclusive handle: rollback cannot overwrite a
   # concurrent third-party writer. A crash leaves durable before/after copies.
   write_handle(h,current)
   raise
  return dict(Status='Written',SHA256=sha(data),ExclusiveSameHandle=True)
 finally:close(h)
def pidl(data):
 if len(data)<78 or data[:4]!=b'\x4c\x00\x00\x00' or data[4:20]!=bytes.fromhex('0114020000000000c000000000000046'):raise RuntimeError('Not a ShellLink file')
 flags=struct.unpack_from('<I',data,20)[0]
 if not flags&1:raise RuntimeError('Expected exact Explorer PIDL is absent')
 length=struct.unpack_from('<H',data,76)[0]
 if 78+length>len(data):raise RuntimeError('Truncated PIDL')
 return data[78:78+length]
def check_path(path,selftest=False):
 if selftest:
  if not under(path,LAB/'fixtures'):raise RuntimeError('Fixture target escaped own directory')
 elif path.resolve()!=PIN.resolve():raise RuntimeError('Only the exact File Explorer taskbar link is allowed')
 if path.exists()and getattr(path.lstat(),'st_file_attributes',0)&0x400:raise RuntimeError('Reparse-point shortcuts are not accepted')
def stage_pin(path,directory,selftest=False):
 check_path(path,selftest);original=path.read_bytes();before=sha(original);saved_bytes(directory/'before.lnk',original);staged=directory/'after.lnk';saved_bytes(staged,original)
 journal=dict(Version=1,Nonce=directory.name,SelfTest=selftest,PinPath=str(path),BeforeSHA256=before,Backup='before.lnk',Prepared='after.lnk',Resource=str(RESOURCE),ResourceSHA256=sha(RESOURCE),Phase='BackedUp',TargetPIDLSHA256=sha(pidl(original)))
 save(directory/'journal.json',journal)
 process=child(PIN_EXE,[staged,RESOURCE,directory/'pin-stage.txt'],20);journal['PrepareProcess']=process
 if process['ExitCode']or process['TimedOut']or not process['DesktopClosed']:raise RuntimeError('PinIcon staging failed')
 replacement=staged.read_bytes()
 if pidl(replacement)!=pidl(original):raise RuntimeError('Prepared shortcut PIDL changed')
 journal['AfterSHA256']=sha(replacement);journal['PIDLByteExact']=True;journal['Phase']='Prepared';save(directory/'journal.json',journal)
 return journal
def apply_pin(journal,directory):
 path=Path(journal['PinPath']);check_path(path,journal['SelfTest']);journal['Phase']='WritePending';save(directory/'journal.json',journal)
 result=replace_owned(path,journal['BeforeSHA256'],(directory/'after.lnk').read_bytes());journal['PinResult']=result;journal['Phase']='Applied'if result['Status']=='Written'else'ForeignPreserved';save(directory/'journal.json',journal);return result
def restore(directory):
 directory=Path(directory).resolve()
 if not under(directory,LAB/'runs')and not under(directory,LAB/'fixtures'):raise RuntimeError('Journal outside own directory')
 j=json.loads((directory/'journal.json').read_text());path=Path(j['PinPath']);check_path(path,j['SelfTest']);original=(directory/'before.lnk').read_bytes()
 if sha(original)!=j['BeforeSHA256']:raise RuntimeError('Backup hash differs')
 if not path.exists():
  result=dict(Status='PreservedForeignChange',Missing=True);j['RestoreResult']=result;j['Phase']='ForeignPreserved';save(directory/'journal.json',j);return dict(Pin=result,Journal=str(directory/'journal.json'))
 current=sha(path)
 if current==j['BeforeSHA256']:result=dict(Status='AlreadyOriginal')
 elif 'AfterSHA256'not in j:result=dict(Status='PreservedForeignChange',CurrentSHA256=current)
 else:result=replace_owned(path,j['AfterSHA256'],original)
 j['RestoreResult']=result;j['Phase']='Restored'if result['Status']in('Written','AlreadyOriginal')else'ForeignPreserved';save(directory/'journal.json',j)
 return dict(Pin=result,Journal=str(directory/'journal.json'),Thumbnail='No cache rollback: cached preview will be regenerated normally; no cache database restored or deleted')
def fingerprint(folder):
 entries=[dict(Name=p.name,Size=p.stat().st_size,MtimeNs=p.stat().st_mtime_ns)for p in sorted(folder.iterdir(),key=lambda p:p.name.casefold())]
 return sha(json.dumps(dict(Path=str(folder),MtimeNs=folder.stat().st_mtime_ns,Entries=entries),sort_keys=True).encode())
def thumbnail(directory,journal):
 if not FOLDER.is_dir()or FOLDER.is_symlink()or getattr(FOLDER.lstat(),'st_file_attributes',0)&0x400:raise RuntimeError('Exact desktop Wub folder unavailable/reparse point')
 before=fingerprint(FOLDER)
 if journal.get('Thumbnail',{}).get('Fingerprint')==before and journal['Thumbnail'].get('Passed'):return dict(Status='AlreadyRefreshed',Fingerprint=before)
 out=directory/('thumbnail-'+uuid.uuid4().hex);out.mkdir();empty=out/'OwnEmpty';empty.mkdir();custom=out/'OwnCustom';custom.mkdir()
 process=child(PROBE,[out,empty,FOLDER,BASE,DLL,custom,'no-vfs-key'],55)
 report=json.loads((out/'icons.json').read_text())if(out/'icons.json').exists()else{}
 by={r['name']:r for r in report.get('icons',[])}
 required=['own-force-thumbnail','after-force-factory-8']
 passed=process['ExitCode']==0 and not process['TimedOut']and process['DesktopClosed']and report.get('restore')==0 and report.get('cacheRestore')==0 and all(by.get(n,{}).get('hr')=='00000000' for n in required)
 hashes={n:sha(out/(n+'.bgra'))for n in ['nonempty-factory-8']+required if(out/(n+'.bgra')).exists()}
 passed=passed and hashes.get('own-force-thumbnail')==hashes.get('after-force-factory-8')and fingerprint(FOLDER)==before
 result=dict(Status='Refreshed'if passed else'Failed',Passed=bool(passed),Fingerprint=before,Process=process,Folder=str(FOLDER),Output=str(out),PixelsSHA256=hashes,AlreadyCorrect=hashes.get('nonempty-factory-8')==hashes.get('own-force-thumbnail'))
 journal['Thumbnail']=result;save(directory/'journal.json',journal)
 if not passed:raise RuntimeError('Targeted Wub thumbnail proof failed; see '+str(out))
 return result
def setup(skip_thumbnail=True):
 validate();j=None;directory=None
 if not PIN.exists():return dict(Status="NotPinnedPreserved",SystemFilesModified=False,GlobalCacheDeleted=False)
 if ACTIVE.exists():
  ref=json.loads(ACTIVE.read_text());directory=Path(ref['Directory']).resolve()
  if not under(directory,LAB/'runs'):raise RuntimeError('Active directory outside own runs')
  j=json.loads((directory/'journal.json').read_text());check_path(Path(j['PinPath']))
  if not PIN.exists():return dict(Status='PreservedForeignChange',PinMissing=True,Journal=str(directory/'journal.json'))
  current=sha(PIN)
  if j.get('AfterSHA256')==current:j['Phase']='Applied';save(directory/'journal.json',j)
  elif j['BeforeSHA256']==current:j=None
  else:return dict(Status='PreservedForeignChange',PinSHA256=current,Journal=str(directory/'journal.json'))
 if j is None:
  directory=LAB/'runs'/uuid.uuid4().hex;directory.mkdir(parents=True);j=stage_pin(PIN,directory)
  save(ACTIVE,dict(Directory=str(directory),Nonce=directory.name));result=apply_pin(j,directory)
  if result['Status']!='Written':return dict(Status='PreservedForeignChange',Pin=result,Journal=str(directory/'journal.json'))
 else:result=dict(Status='AlreadyApplied',SHA256=j['AfterSHA256'])
 thumb=dict(Status='Skipped')if skip_thumbnail or FOLDER is None else thumbnail(directory,j)
 return dict(Status='Applied',Pin=result,Thumbnail=thumb,Journal=str(directory/'journal.json'),ExplorerRestarted=False,SystemFilesModified=False,GlobalCacheDeleted=False)
def selftest():
 validate();directory=LAB/'fixtures'/uuid.uuid4().hex;directory.mkdir(parents=True);target=directory/'OwnExplorer.lnk';saved_bytes(target,PIN.read_bytes());j=stage_pin(target,directory,True);a=apply_pin(j,directory);r=restore(directory);r2=restore(directory)
 reapplied=replace_owned(target,j['BeforeSHA256'],(directory/'after.lnk').read_bytes());foreign=target.read_bytes()+b'OWN_FOREIGN_MARKER';target.write_bytes(foreign);refused=restore(directory)
 proof=dict(Directory=str(directory),Apply=a,Restore=r,SecondRestore=r2,Reapply=reapplied,ForeignRestore=refused,ForeignBytesPreserved=target.read_bytes()==foreign,PIDLByteExact=j['PIDLByteExact'])
 proof['Passed']=a['Status']=='Written'and r['Pin']['Status']=='Written'and r2['Pin']['Status']=='AlreadyOriginal'and refused['Pin']['Status']=='PreservedForeignChange'and proof['ForeignBytesPreserved']and proof['PIDLByteExact'];save(LAB/'own-proof.json',proof)
 if not proof['Passed']:raise RuntimeError('Own pin lifecycle fixture failed')
 return proof
def main():
 parser=argparse.ArgumentParser();parser.add_argument('action',choices=['setup','restore','status','selftest']);parser.add_argument('--journal');parser.add_argument('--skip-thumbnail',action='store_true');args=parser.parse_args()
 lock=mutexCreate(None,False,'Local\\Explorer10.TargetIconRepair')
 if not lock:raise C.WinError(C.get_last_error())
 acquired=False
 try:
  result=wait(lock,0);acquired=result in(0,0x80)
  if not acquired:raise RuntimeError('Another targeted icon operation owns the mutex')
  if args.action=='setup':result=setup(args.skip_thumbnail)
  elif args.action=='selftest':result=selftest()
  elif args.action=='restore':
   if not args.journal and not ACTIVE.exists():result=dict(Status='NoActiveRepair')
   else:
    directory=Path(args.journal).parent if args.journal else Path(json.loads(ACTIVE.read_text())['Directory'])
    result=restore(directory)
  else:result=dict(Active=json.loads(ACTIVE.read_text())if ACTIVE.exists()else None,PinSHA256=sha(PIN)if PIN.exists()else None,Folder=str(FOLDER))
  save(LAB/'last-result.json',result);print(json.dumps(result,ensure_ascii=False));return 0
 finally:
  if acquired:mutexRelease(lock)
  close(lock)
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as error:
  save(LAB/'last-error.json',dict(Error=str(error),Time=time.time()));print(json.dumps(dict(Error=str(error)),ensure_ascii=False));raise SystemExit(1)
