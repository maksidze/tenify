from pathlib import Path
p=Path('outputs/Windows10-Components/Probe-Explorer10.py');s=p.read_text()
s=s.replace("hfile,hprocess,hthread,base=struct.unpack_from('<QQQQ',data);handles.update([hprocess,hthread])", "hfile,hprocess,hthread,base=struct.unpack_from('<QQQQ',data);handles.update([hprocess,hthread]);modules.append({'path':result['exe'],'base':hex(base)})")
needle="events.append({'type':'exception','code':hex(code),'address':hex(address),'firstChance':bool(first)})"
replace=needle+'''
    if code in [0xc0000005,0xc000001d,0xc000041d]:
     thread=threadOpen(0x58,False,e.tid)
     if thread:
      try:
       buf=C.create_string_buffer(1248);ptr=(C.addressof(buf)+15)&~15;C.c_uint32.from_address(ptr+48).value=0x100003
       if contextGet(thread,ptr):
        ctx=C.string_at(ptr,1232)
        regs={n:hex(struct.unpack_from('<Q',ctx,o)[0]) for n,o in [('rax',120),('rcx',128),('rdx',136),('rbx',144),('rsp',152),('rbp',160),('rsi',168),('rdi',176),('r8',184),('r9',192),('rip',248)]}
        events.append({'type':'exceptionContext','code':hex(code),'registers':regs,'stackBytes':mem(int(regs['rsp'],16),256).hex(),'exceptionInfo':data[32:64].hex()})
      finally:close(thread)
'''
assert needle in s;s=s.replace(needle,replace);Path('outputs/Windows10-Components/Lab/PfnCompat/Probe-PfnCompat.py').write_text(s)
