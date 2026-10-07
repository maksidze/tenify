"""Run native callback field/stride loop against synthetic Win11 records.
It has no window, shell, COM or notification side effects.
"""
import ctypes as C,sys,json
from pathlib import Path
sys.path.insert(0,str(Path('work/pylib').resolve()))
from keystone import Ks,KS_ARCH_X86,KS_MODE_64
ks=Ks(KS_ARCH_X86,KS_MODE_64)
asm='''
push r14
xor eax,eax
test r9d,r9d
jz done
lea r14,[r8+0xa0]
loop:
test byte ptr [r14-0x30],1
jnz skip
mov rdx,[r14]
add eax,dword ptr [rdx+0x28]
skip:
add r14,0x170
dec r9d
jnz loop
done:
pop r14
ret
'''
code=bytes(ks.asm(asm)[0]);k=C.WinDLL('kernel32',use_last_error=True)
k.VirtualAlloc.restype=C.c_void_p;k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.c_uint32]
k.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32]
address=k.VirtualAlloc(None,len(code),0x3000,0x40)
assert address
try:
 C.memmove(address,code,len(code));fn=C.WINFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32)(address)
 groups=[C.create_string_buffer(0x38) for _ in range(3)]
 for group,kind in zip(groups,[7,11,17]):C.c_uint32.from_buffer(group,0x28).value=kind
 records=C.create_string_buffer(3*0x170)
 for i,group in enumerate(groups):
  # +0x88 is an integer in host layout, reproducing the old crash's 3.
  C.c_uint32.from_buffer(records,i*0x170+0x88).value=3
  C.c_void_p.from_buffer(records,i*0x170+0xa0).value=C.addressof(group)
 C.c_ubyte.from_buffer(records,0x170+0x70).value=1
 tests=[('zero count',0,0),('single record',1,7),('flagged second ignored',2,7),('stride reaches third',3,24)]
 result=[]
 for name,count,expected in tests:
  actual=fn(None,0,C.addressof(records),count)
  assert actual==expected,(name,actual,expected)
  result.append({'test':name,'count':count,'actual':actual,'expected':expected,'pass':True})
 Path('outputs/Windows10-Components/Lab/NotificationCompat/synthetic-result.json').write_text(json.dumps({'nativeLoop':code.hex(),'recordsLayout':'Win11 0x170, flags+0x70, group+0xa0','tests':result},indent=2))
 print(json.dumps(result))
finally:k.VirtualFree(address,0,0x8000)
