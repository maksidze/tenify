"""Exact activation adoption. No package registration or activation on import."""
import ctypes as C, json, struct, time
from ctypes import wintypes as W
from pathlib import Path
K=C.WinDLL('kernel32',use_last_error=True);P=C.c_void_p
def api(n,r,a):
 f=getattr(K,n);f.restype=r;f.argtypes=a;return f
open_process=api('OpenProcess',P,[W.DWORD,W.BOOL,W.DWORD])
open_thread=api('OpenThread',P,[W.DWORD,W.BOOL,W.DWORD])
close=api('CloseHandle',W.BOOL,[P]);wait=api('WaitForSingleObject',W.DWORD,[P,W.DWORD])
times=api('GetProcessTimes',W.BOOL,[P,P,P,P,P]);query=api('QueryFullProcessImageNameW',W.BOOL,[P,W.DWORD,W.LPWSTR,P])
package=api('GetPackageFullName',W.LONG,[P,P,W.LPWSTR]);thread_pid=api('GetProcessIdOfThread',W.DWORD,[P])
terminate=api('TerminateProcess',W.BOOL,[P,W.UINT]);resume=api('ResumeThread',W.DWORD,[P])
tick=api('GetTickCount64',C.c_ulonglong,[])
mutex=api('CreateMutexW',P,[P,W.BOOL,W.LPCWSTR]);release=api('ReleaseMutex',W.BOOL,[P])
def identity(h):
 born,end,k,u=(C.c_ulonglong() for _ in range(4));path=C.create_unicode_buffer(32768);n=W.DWORD(len(path));pkg=C.create_unicode_buffer(4096);pn=W.UINT(len(pkg))
 if not times(h,C.byref(born),C.byref(end),C.byref(k),C.byref(u)) or not query(h,0,path,C.byref(n)):raise C.WinError(C.get_last_error())
 result=package(h,C.byref(pn),pkg)
 if result not in (0,15700):raise RuntimeError('Package identity query failed '+str(result))
 return dict(Birth=born.value,Path=path.value,Package=pkg.value if result==0 else '')
def atomic(path,value):
 p=Path(path);tmp=p.with_name(p.name+'.pending');tmp.write_text(json.dumps(value,indent=2),encoding='utf-8');tmp.replace(p)
def lease_active(state):
 try:
  from LeaseIO import read_lease
  raw=read_lease(state['LeaseFile'])
  if len(raw)!=16:return False
  deadline,born=struct.unpack('<QQ',raw);now=tick();owner=state['Controller']
  if born!=owner['Birth'] or not now<deadline<=now+20000:return False
  h=open_process(0x101000,False,owner['Pid'])
  if not h:return False
  try:
   i=identity(h)
   return wait(h,0)==258 and i['Birth']==born and i['Path'].casefold()==owner['Path'].casefold()
  finally:close(h)
 except (OSError,KeyError,ValueError):return False
class OwnedActivation:
 def __init__(self,state,pid,tid):
  self.state=state;self.pid=pid;self.tid=tid;self.process=None;self.thread=None;self.claimed=False;self.finished=False
  try:
   self.process=open_process(0x1fffff,False,pid)
   if not self.process:raise C.WinError(C.get_last_error())
   self.actual=identity(self.process)
   if wait(self.process,0)!=258:raise RuntimeError('Target already exited')
   if self.actual['Path'].casefold()!=state['NativePath'].casefold() or self.actual['Package']!=state['PackageFullName']:raise RuntimeError('Target path/package differs')
   if self.actual['Birth']<state['StartBirth']:raise RuntimeError('Target predates session')
   self.thread=open_thread(0x1fffff,False,tid)
   if not self.thread or thread_pid(self.thread)!=pid:raise RuntimeError('Primary thread belongs to another process')
  except BaseException:self.close();raise
 def claim(self):
  # No hook has run yet. Orphan callback may resume native; cancellation of a
  # healthy owned session instead stops only this freshly validated activation.
  gate=mutex(None,False,'Local\\SettingsSessionRestore_'+self.state['Nonce']);acquired=wait(gate,20000) in (0,0x80)
  try:
   if not acquired:raise RuntimeError('Adoption/restore gate timeout')
   directory=Path(self.state['Directory'])
   if Path(self.state['CancelFile']).exists() or (directory/'restored.json').exists() or not lease_active(self.state):return False
   self.record=directory/('a_'+str(self.pid)+'_'+str(self.actual['Birth'])+'.record')
   # Guard reads public *.record without taking the adoption gate. Publish
   # only a complete flushed record; an empty in-progress file is never public.
   pending=self.record.with_suffix('.pending-'+str(self.tid))
   try:
    with pending.open('xb') as f:f.write(struct.pack('<IIQ',0x53534c31,self.pid,self.actual['Birth']));f.flush();import os;os.fsync(f.fileno())
    pending.rename(self.record) # Windows rename refuses an existing immutable record.
   finally:pending.unlink(missing_ok=True)
   self.claimed=True;return True
  finally:
   if acquired:release(gate)
   close(gate)
 def stop(self):
  if wait(self.process,0)==0:self.finished=True;return 'AlreadyExited'
  if identity(self.process)!=self.actual:raise RuntimeError('Captured handle identity changed')
  if not terminate(self.process,0xdeca):raise C.WinError(C.get_last_error())
  if wait(self.process,5000)!=0:raise RuntimeError('Exact owned termination timed out')
  self.finished=True;return 'StoppedExact'
 def resume_native(self):
  if self.claimed:raise RuntimeError('Claimed/possibly mutated process cannot fall back')
  if resume(self.thread)==0xffffffff:raise C.WinError(C.get_last_error())
  self.finished=True
 def close(self):
  if self.thread:close(self.thread);self.thread=None
  if self.process:close(self.process);self.process=None
