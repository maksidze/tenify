"""Isolated USVFS + resource routes + real own child creation regression."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,os,subprocess,uuid
r=Path.cwd();b=r/'outputs/Windows10-Components';l=b/'Lab/IconResourceMaximum';nonce=uuid.uuid4().hex;run=l/'state'/nonce;pair=run/'PrivateUSVFS';pair.mkdir(parents=True)
for name,off,pin in [('usvfs_x64.dll',0xdef40,'7ee7758433ab76713900e661056be8074b9c567971fde38fd0e514c76895e274'),('usvfs_proxy_x64.exe',0x54d68,'491d4d7e3fce9876e904f8cccb648f43def428a2a527d41f0221d9c0ce1d408e')]:
 data=(b/'Tools/USVFS/bin'/name).read_bytes();assert hashlib.sha256(data).hexdigest()==pin and data[off:off+11]==b'__shm_sink_';replacement=('__r'+nonce[:8]).encode();assert len(replacement)==11;(pair/name).write_bytes(data[:off]+replacement+data[off+11:])
os.add_dll_directory(str(pair));v=C.WinDLL(str(pair/'usvfs_x64.dll'),use_last_error=True);k=C.WinDLL('kernel32',use_last_error=True);P=C.c_void_p;D=W.DWORD
def api(lib,name,ret,args):f=getattr(lib,name);f.restype=ret;f.argtypes=args;return f
class SI(C.Structure):_fields_=[('cb',D),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',D),('y',D),('xs',D),('ys',D),('xc',D),('yc',D),('fill',D),('flags',D),('show',W.WORD),('res2',W.WORD),('pres2',P),('hin',P),('hout',P),('herr',P)]
class PI(C.Structure):_fields_=[('process',P),('thread',P),('pid',D),('tid',D)]
param=api(v,'usvfsCreateParameters',P,[])();pi=PI();connected=False
try:
 api(v,'usvfsSetInstanceName',None,[P,C.c_char_p])(param,('IconRegression_'+nonce).encode());api(v,'usvfsSetDebugMode',None,[P,W.BOOL])(param,False);api(v,'usvfsSetLogLevel',None,[P,C.c_uint8])(param,1)
 if not api(v,'usvfsCreateVFS',W.BOOL,[P])(param):raise C.WinError(C.get_last_error())
 connected=True;exe=l/'IconRouteProbe.exe';log=run/'results.jsonl';si=SI();si.cb=C.sizeof(si);si.flags=1;si.show=0
 cmd=C.create_unicode_buffer(subprocess.list2cmdline([str(exe),str(l/'IconRoutes.ChildSafe.dll'),str(log)]))
 if not api(v,'usvfsCreateProcessHooked',W.BOOL,[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,P,P])(str(exe),cmd,None,None,False,0x08000000,None,str(l),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
 if api(k,'WaitForSingleObject',D,[P,D])(pi.process,35000)!=0:raise TimeoutError('Own regression child timed out')
 code=D();assert api(k,'GetExitCodeProcess',W.BOOL,[P,P])(pi.process,C.byref(code));rows=[json.loads(x) for x in log.read_text().splitlines()];proof={'ExitCode':code.value,'Rows':rows,'USVFSHookedParent':True,'Passed':code.value==0 and all(x.get('pass',True) for x in rows),'Run':str(run),'NoSystemWrites':True}
 (l/'childsafe-usvfs-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps({x:y for x,y in proof.items() if x!='Rows'}));assert proof['Passed']
finally:
 if pi.process:
  if api(k,'WaitForSingleObject',D,[P,D])(pi.process,0)!=0:api(k,'TerminateProcess',W.BOOL,[P,D])(pi.process,0xdeca)
  api(k,'CloseHandle',W.BOOL,[P])(pi.thread);api(k,'CloseHandle',W.BOOL,[P])(pi.process)
 if connected:api(v,'usvfsDisconnectVFS',None,[])()
 api(v,'usvfsFreeParameters',None,[P])(param)
