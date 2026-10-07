from pathlib import Path
import json,hashlib,struct,importlib.util,ctypes as C
from ctypes import wintypes as W
BASE=Path(__file__).resolve().parents[2];LAB=BASE/'Lab/IconRoutesNoVfsCompat'
def install_icons(b):
 if not b.primary_suspended or not b.entry_restored or b.attached or b.exe.resolve()!=(BASE/'Runtime/Explorer10/explorer.exe').resolve():raise RuntimeError('New owned entry-held Explorer required')
 sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();m=json.loads((LAB/'manifest.json').read_text())
 if not m['OwnProofPassed']or m['USVFS']or m['RouteCount']!=240:raise RuntimeError('No-VFS icon manifest not ready')
 for n,d in m['Files'].items():
  if sha(LAB/n)!=d:raise RuntimeError('Icon artifact changed '+n)
 for n,d in m['Dependencies'].items():
  if sha(n)!=d:raise RuntimeError('Icon dependency changed '+n)
 helper=Path(m['Helper']);base=b.load_library(helper)
 spec=importlib.util.spec_from_file_location('direct_icon_exports',BASE/'Lab/ControlThemeBootstrap/Launch-ControlTheme10.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);exports=module.exports(helper)
 spec=importlib.util.spec_from_file_location('direct_icon_identity',BASE/'Launch-TouchpadCompat.py');identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity);physical=identity.mapped_file_identity(b,base,helper)
 def call(name):
  h=b.remote_thread(b.pi.process,None,0,base+exports[name],None,0,None)
  if not h:raise C.WinError(C.get_last_error())
  try:
   if b.wait(h,15000)!=0:raise RuntimeError('Icon initialization pending; discard exact owned child')
   fn=b.k.GetExitCodeThread;fn.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];fn.restype=W.BOOL;code=W.DWORD()
   if not fn(h,C.byref(code)):raise C.WinError(C.get_last_error())
   return code.value
  finally:b.close(h)
 result=call(m['InitializeExport']);patches=call('GetIconRoutePatchCount');hits=call('GetIconRouteHits');keyHits=call('GetFolderCacheKeyHits');failures=call('GetNoVfsIconFailures')
 report=dict(result=result,patches=patches,hits=hits,folderKeyHits=keyHits,failures=failures,NoVFS=True,helperSHA256=sha(helper),manifestSHA256=sha(LAB/'manifest.json'),helperBase=hex(base),physical=physical)
 if result or patches<1 or failures:raise RuntimeError('No-VFS icon readiness refused '+json.dumps(report))
 # Read the genuine Windows.Storage cache-key vtable publication.
 storage=next(v for n,v in b.modules().items()if n.endswith('\\windows.storage.dll'));target=struct.unpack('<Q',b.read(storage+0x652550,8))[0];size=module.pefile.PE(str(helper)).OPTIONAL_HEADER.SizeOfImage
 if not base<=target<base+size:raise RuntimeError('Actual folder cache-key slot does not target private helper')
 report['folderSlot']=hex(storage+0x652550);report['folderTarget']=hex(target);report['cacheKeyReadback']=True
 return report
