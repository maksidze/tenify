from pathlib import Path
import ctypes as C,json,struct,os
root=Path('outputs/Windows10-Components/Lab/FlyoutCompat').resolve()
d=C.WinDLL(str(root/'RefinedConverter.dll'));d.RFConvert.restype=C.c_long;d.RFConvert.argtypes=[C.c_uint,C.c_void_p,C.c_uint,C.POINTER(C.c_void_p),C.POINTER(C.c_void_p)]
d.RFFree.argtypes=[C.c_void_p];d.RFInstall.argtypes=[C.c_void_p];d.RFInstall.restype=C.c_long;d.RFRestore.restype=C.c_long
keep=[];results=[]
def buffer(n):b=C.create_string_buffer(n);keep.append(b);return b
def pointer(b,offset,value):C.c_void_p.from_buffer(b,offset).value=C.addressof(value) if hasattr(value,'raw') else value
def long(b,offset,value):C.c_uint32.from_buffer(b,offset).value=value
def run(kind,record,count,check):
 out=C.c_void_p();owner=C.c_void_p();hr=d.RFConvert(kind,C.addressof(record),count,C.byref(out),C.byref(owner))
 assert hr==0,(hex(hr&0xffffffff),kind)
 try:check(out.value)
 finally:d.RFFree(owner)
def read(p,n):return C.string_at(p,n)
def word(p,o):return struct.unpack('<I',read(p+o,4))[0]
def ptr(p,o):return struct.unpack('<Q',read(p+o,8))[0]
records=buffer(0x170*2);strings=[C.create_unicode_buffer(x) for x in ['first','second']];keep+=strings
groups=[buffer(0x38),buffer(0x38)]
for i in range(2):
 pointer(records,i*0x170+0x28,C.addressof(strings[i]));pointer(records,i*0x170+0xa0,groups[i]);long(groups[i],0x28,7+i)
 long(records,i*0x170+0x70,0x101+i);long(records,i*0x170+0x74,0x221+i);long(records,i*0x170+0x7c,0x331+i);long(records,i*0x170+0x80,0x441+i)
 long(records,i*0x170+0x88,3);C.c_uint64.from_buffer(records,i*0x170+0x160).value=3
def checkRecords(p):
 for i in range(2):
  q=p+i*0x158;assert ptr(q,0x20)==C.addressof(strings[i]);assert word(ptr(q,0x88),0x28)==7+i
  assert ptr(q,0x88)!=C.addressof(groups[i]);assert word(q,0x60)==0x101+i;assert word(q,0x68)==0x331+i;assert word(q,0x6c)==0x441+i
  assert ptr(q,0x148)==0
run(0,records,2,checkRecords);results.append('Two records: stride, group clone, strings, flags/enums, removed WSTRING safely NULL')
updated=buffer(0x180);C.memmove(updated,records,0x170);pointer(updated,0x170,C.addressof(strings[1]));long(updated,0x178,0x15)
def checkUpdated(p):assert ptr(p,0x158)==C.addressof(strings[1]) and word(p,0x160)==0x15
run(1,updated,1,checkUpdated);results.append('Updated record: embedded refined record and trailing fields')
deleted=buffer(0x28);pointer(deleted,0,C.addressof(strings[0]));pointer(deleted,8,C.addressof(strings[1]));long(deleted,0x20,11)
run(2,deleted,1,lambda p: None if read(p,0x28)==deleted.raw else (_ for _ in ()).throw(AssertionError('deleted')));results.append('Deleted record stable 0x28 layout')
arrays=buffer(0x170);data=buffer(256);data.raw=bytes(range(256));pointer(arrays,0x150,data);long(arrays,0x158,256)
props=buffer(0x20);pointer(props,0,C.addressof(strings[0]));pointer(props,8,C.addressof(strings[1]));pointer(props,16,C.addressof(strings[1]));pointer(arrays,0x100,props);long(arrays,0xfc,2)
def checkArrays(p):
 assert word(p,0x140)==256 and ptr(p,0x138)!=C.addressof(data) and read(ptr(p,0x138),256)==bytes(range(256))
 assert word(p,0xe0)==2 and ptr(p,0xe8)!=C.addressof(props) and read(ptr(p,0xe8),32)==props.raw
run(0,arrays,1,checkArrays);results.append('Correlated byte and property arrays: owned clones and host count offsets')
for tag,size,oldtag in [(1,0x450,1),(2,0xa0,2),(3,0x28,3),(4,0x28,4),(5,0x28,5),(6,0x20,6),(7,0x30,8),(8,0x28,9),(9,0x10,10)]:
 record=buffer(0x170);payload=buffer(0x90);body=buffer(size);pointer(record,0xa8,payload);long(payload,0,tag);pointer(payload,0x10,body)
 def checkPayload(p):
  oldpayload=ptr(p,0x90);assert oldpayload!=C.addressof(payload);assert word(oldpayload,0)==oldtag;assert ptr(oldpayload,0x10)!=C.addressof(body)
 run(0,record,1,checkPayload)
results.append('All supported tagged nested QuickAction payload kinds 1..9 converted, including enlarged fixed embedded structures')
record=buffer(0x170);payload=buffer(0x90);pointer(record,0xa8,payload);long(payload,0,10)
out=C.c_void_p(123);owner=C.c_void_p(123);hr=d.RFConvert(0,C.addressof(record),1,C.byref(out),C.byref(owner));assert hr&0xffffffff==0x80070032 and not out.value and not owner.value
results.append('New feature-gated host payload kind10 fails visibly with ERROR_NOT_SUPPORTED and freed arena')
out=C.c_void_p(123);owner=C.c_void_p(123);hr=d.RFConvert(0,C.addressof(record),4097,C.byref(out),C.byref(owner));assert hr&0xffffffff==0x80070057 and not out.value and not owner.value
results.append('Invalid count rejected without output allocations')
k=C.WinDLL('kernel32',use_last_error=True);k.GetModuleHandleW.restype=C.c_void_p;k.GetModuleHandleW.argtypes=[C.c_wchar_p]
hr=d.RFInstall(k.GetModuleHandleW('kernel32.dll'));assert hr&0xffffffff==0x8007051a
results.append('Wrong module rejected by exact CodeView GUID guard')
# Own process only: loading a private DLL creates no ActionCenter app/server.
k.LoadLibraryW.restype=C.c_void_p;k.LoadLibraryW.argtypes=[C.c_wchar_p]
k.LoadLibraryW(str(Path(os.environ['SystemRoot'])/'System32/wincorlib.dll'))
combase=C.WinDLL('combase');combase.RoInitialize.argtypes=[C.c_uint];combase.RoInitialize(0)
k.LoadLibraryExW.restype=C.c_void_p;k.LoadLibraryExW.argtypes=[C.c_wchar_p,C.c_void_p,C.c_uint]
action=k.LoadLibraryExW(str(root/'Runtime/Windows.UI.ActionCenter.dll'),None,8);assert action,C.get_last_error()
before=[ptr(action+r,0) for r in [0x3e4978,0x3e4980,0x3e4988,0x3ef0c8]]
hr=d.RFInstall(action);assert hr==0,hex(hr&0xffffffff)
after=[ptr(action+r,0) for r in [0x3e4978,0x3e4980,0x3e4988,0x3ef0c8]];assert all(a!=b for a,b in zip(before,after))
assert d.RFRestore()==0;assert before==[ptr(action+r,0) for r in [0x3e4978,0x3e4980,0x3e4988,0x3ef0c8]]
results.append('Own private oldAction DLL: exact four callback vtable slots installed and restored; no UI/server instantiated')
(root/'converter-synthetic-result.json').write_text(json.dumps({'pass':True,'tests':results,'systemFilesChanged':False,'liveShellAffected':False},indent=2))
print(json.dumps(results,indent=2))
