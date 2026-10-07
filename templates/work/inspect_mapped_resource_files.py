"""Read-only physical mapped-resource inventory for an exact Explorer instance."""
import ctypes as C,json,sys
from ctypes import wintypes as W
from pathlib import Path
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'outputs/Windows10-Components/Lab/SettingsUntilStopCompat'))
import SessionController as S
pid=int(sys.argv[1]);birth=int(sys.argv[2]);expected=root/'outputs/Windows10-Components/Runtime/Explorer10/explorer.exe'
h=S.open_process(0x1010,False,pid)
if not h:raise SystemExit('Cannot query exact process')
try:
 i=S.identity(h)
 if not i or i['Birth']!=birth or i['Path'].casefold()!=str(expected).casefold():raise SystemExit('Exact Explorer identity differs')
 class MBI(C.Structure):_fields_=[('Base',C.c_void_p),('Allocation',C.c_void_p),('AllocationProtect',W.DWORD),('PartitionId',W.WORD),('Size',C.c_size_t),('State',W.DWORD),('Protect',W.DWORD),('Type',W.DWORD)]
 query=S.api('VirtualQueryEx',C.c_size_t,[C.c_void_p,C.c_void_p,C.POINTER(MBI),C.c_size_t])
 name=S.api('K32GetMappedFileNameW',W.DWORD,[C.c_void_p,C.c_void_p,W.LPWSTR,W.DWORD])
 pos=0;seen=set();files=set();regions=0
 while pos<0x7fffffffffff:
  m=MBI()
  if not query(h,pos,C.byref(m),C.sizeof(m)):break
  regions+=1
  if m.State==0x1000 and m.Type in (0x1000000,0x40000) and m.Allocation not in seen:
   seen.add(m.Allocation);buf=C.create_unicode_buffer(32768)
   if name(h,m.Base,buf,len(buf)) and '.mun' in buf.value.lower():files.add(buf.value)
  end=(m.Base or 0)+m.Size
  if end<=pos:raise RuntimeError('Invalid region progression')
  pos=end
 result=dict(Pid=pid,Birth=birth,ReadOnly=True,Regions=regions,MappedResourceFiles=sorted(files),Icons10PhysicallyMapped=any('IconResourceCompat' in p or 'IconResourceMaximum' in p for p in files),VisibleUIVerified=False)
 print(json.dumps(result,indent=2))
finally:S.close(h)
