"""Read-only access test: own ephemeral VFS, existing SEH token impersonation.
No shared logging owner, process creation, registration or ACL mutation.
"""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import json,uuid,sys,subprocess
P=C.c_void_p;D=W.DWORD
def bind(d,n,r,a):
 f=getattr(d,n);f.restype=r;f.argtypes=a;return f
base=Path(__file__).resolve().parent.parent/'outputs/Windows10-Components'
k=C.WinDLL('kernel32',use_last_error=True);a=C.WinDLL('advapi32',use_last_error=True)
op=bind(k,'OpenProcess',P,[D,W.BOOL,D]);close=bind(k,'CloseHandle',W.BOOL,[P])
token=bind(a,'OpenProcessToken',W.BOOL,[P,D,C.POINTER(P)])
dup=bind(a,'DuplicateTokenEx',W.BOOL,[P,D,P,C.c_int,C.c_int,C.POINTER(P)])
imp=bind(a,'SetThreadToken',W.BOOL,[P,P]);revert=bind(a,'RevertToSelf',W.BOOL,[])
info=bind(a,'GetTokenInformation',W.BOOL,[P,C.c_int,P,D,C.POINTER(D)])
openmap=bind(k,'OpenFileMappingW',P,[D,W.BOOL,W.LPCWSTR])
getsd=bind(a,'GetSecurityInfo',D,[P,C.c_int,D,P,P,P,P,C.POINTER(P)])
sdstr=bind(a,'ConvertSecurityDescriptorToStringSecurityDescriptorW',W.BOOL,[P,D,D,C.POINTER(W.LPWSTR),C.POINTER(D)])
strsd=bind(a,'ConvertStringSecurityDescriptorToSecurityDescriptorW',W.BOOL,[W.LPCWSTR,D,C.POINTER(P),C.POINTER(D)])
setsd=bind(a,'SetKernelObjectSecurity',W.BOOL,[P,D,P])
sidstr=bind(a,'ConvertSidToStringSidW',W.BOOL,[P,C.POINTER(W.LPWSTR)])
localfree=bind(k,'LocalFree',P,[P])
cookie=__import__('os').add_dll_directory(str(base/'Tools/USVFS/bin'))
v=C.WinDLL(str(base/'Tools/USVFS/bin/usvfs_x64.dll'),use_last_error=True)
new=bind(v,'usvfsCreateParameters',P,[]);free=bind(v,'usvfsFreeParameters',None,[P])
setname=bind(v,'usvfsSetInstanceName',None,[P,C.c_char_p]);create=bind(v,'usvfsCreateVFS',W.BOOL,[P]);disconnect=bind(v,'usvfsDisconnectVFS',None,[])
pid=int(sys.argv[1]);report={'pid':pid,'noLiveProcessChanges':True,'noPersistentAclChanges':True,'temporaryOwnSectionAclTest':'--grant-own' in sys.argv}
handles=[];params=None;connected=False;impersonating=False
try:
 h=op(0x1000,False,pid)
 if not h:raise C.WinError(C.get_last_error())
 handles.append(h);t=P()
 if not token(h,0xA,C.byref(t)):raise C.WinError(C.get_last_error())
 handles.append(t);value=D();needed=D()
 if not info(t,29,C.byref(value),4,C.byref(needed)):raise C.WinError(C.get_last_error())
 report['isAppContainer']=value.value
 if not value.value:raise ValueError('Not an AppContainer token')
 sidbuf=C.create_string_buffer(64)
 if not info(t,31,sidbuf,len(sidbuf),C.byref(needed)):raise C.WinError(C.get_last_error())
 sid=P.from_buffer(sidbuf);sidtext=W.LPWSTR()
 if not sidstr(sid,C.byref(sidtext)):raise C.WinError(C.get_last_error())
 packageSid=sidtext.value;localfree(sidtext);report['packageSid']=packageSid
 dt=P()
 if not dup(t,0xC,None,2,2,C.byref(dt)):raise C.WinError(C.get_last_error())
 handles.append(dt)
 name='CodexFlyoutIPC_'+uuid.uuid4().hex;params=new();setname(params,name.encode())
 if not create(params):raise C.WinError(C.get_last_error())
 connected=True;report['instance']=name;rows=[]
 for n in [name,name+'_1','inv_'+name,'inv_'+name+'_1']:
  row={'name':n};mh=openmap(6|0xe0000,False,n);row['normalOpen']=bool(mh);row['normalError']=0 if mh else C.get_last_error()
  if mh:
   sd=P();text=W.LPWSTR();l=D();err=getsd(mh,6,4,None,None,None,None,C.byref(sd));row['securityError']=err
   if not err:
    if sdstr(sd,1,4,C.byref(text),C.byref(l)):row['dacl']=text.value;localfree(text)
    localfree(sd)
   close(mh)
  if not imp(None,dt):raise C.WinError(C.get_last_error())
  impersonating=True
  try:
   for access in [4,6]:
    mh=openmap(access,False,n);row['appContainerRead' if access==4 else 'appContainerReadWrite']={'ok':bool(mh),'error':0 if mh else C.get_last_error()}
    if mh:close(mh)
  finally:
   if not revert():raise C.WinError(C.get_last_error())
   impersonating=False
  rows.append(row)
  if '--grant-own' in sys.argv and row['normalOpen']:
   # All names belong to this unique VFS and vanish at disconnect. Retain their
   # original descriptor and restore it before close, even on failed access.
   mh=openmap(6|0xe0000,False,n);original=P();modified=P();size=D()
   err=getsd(mh,6,0x14,None,None,None,None,C.byref(original))
   if err:close(mh);raise C.WinError(err)
   try:
    sddl=row['dacl']+'(A;;GA;;;'+packageSid+')S:(ML;;NW;;;LW)'
    if not strsd(sddl,1,C.byref(modified),C.byref(size)):raise C.WinError(C.get_last_error())
    if not setsd(mh,0x14,modified):raise C.WinError(C.get_last_error())
    if not imp(None,dt):raise C.WinError(C.get_last_error())
    impersonating=True
    try:
     q=openmap(6,False,n);row['ownPackageGrantReadWrite']={'ok':bool(q),'error':0 if q else C.get_last_error()}
     if q:close(q)
    finally:revert();impersonating=False
   finally:
    row['securityRestored']=bool(setsd(mh,0x14,original))
    empty=P();length=D()
    if strsd(row['dacl']+'S:',1,C.byref(empty),C.byref(length)):
     try:row['defaultLabelCleared']=bool(setsd(mh,0x10,empty))
     finally:localfree(empty)
    check=P();err=getsd(mh,6,0x14,None,None,None,None,C.byref(check));text=W.LPWSTR();l=D()
    try:
     if not err and sdstr(check,1,0x14,C.byref(text),C.byref(l)):
      row['restoredSddl']=text.value;row['restoredReadbackMatched']=text.value.removesuffix('S:')==row['dacl'];localfree(text)
    finally:
     if check:localfree(check)
    if modified:localfree(modified)
    localfree(original);close(mh)
 report['objects']=rows
except Exception as e:report['error']=repr(e)
finally:
 if impersonating:revert()
 if connected:disconnect()
 if params:free(params)
 for h in reversed(handles):close(h)
 cookie.close()
 out=base/'Lab/FlyoutCompat/ipc-token-access.json';out.write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
