from pathlib import Path
p=Path('work/probe_pfn_signed_injected.py');s=p.read_text();needle="source=source.replace(old,prep+inject)"
patch=r'''
source=source.replace("code=struct.unpack_from('<I',d)[0];first=struct.unpack_from('<I',d,152)[0];debugEvents.append({'type':'exception','code':hex(code),'firstChance':bool(first)})", """code=struct.unpack_from('<I',d)[0];first=struct.unpack_from('<I',d,152)[0];address=struct.unpack_from('<Q',d,16)[0];debugEvents.append({'type':'exception','code':hex(code),'firstChance':bool(first),'address':hex(address)})
   if code in [0xc000001d,0xc0000005,0xc000041d]:
    tOpen=api(kernel,'OpenThread',P,[D,W.BOOL,D]);tGet=api(kernel,'GetThreadContext',W.BOOL,[P,P]);thread=tOpen(0x58,False,e.tid)
    if thread:
     try:
      b=C.create_string_buffer(1248);ptr=(C.addressof(b)+15)&~15;C.c_uint32.from_address(ptr+48).value=0x100003
      if tGet(thread,ptr):
       ctx=C.string_at(ptr,1232);regs={n:hex(struct.unpack_from('<Q',ctx,o)[0]) for n,o in [('rax',120),('rcx',128),('rdx',136),('rsp',152),('r8',184),('r9',192),('rip',248)]};stack=C.create_string_buffer(192);nr=C.c_size_t();read(pi.process,int(regs['rsp'],16),stack,192,C.byref(nr));debugEvents.append({'type':'exceptionContext','code':hex(code),'registers':regs,'stackBytes':stack.raw[:nr.value].hex()})
     finally:close(thread)""")
'''
s=s.replace(needle,needle+'\n'+patch);s=s.replace("'sameNativeForwardersPreserved':preserved}","'sameNativeForwardersPreserved':preserved,'modulesAtHook':{k:hex(v) for k,v in mods.items()}}")
p.write_text(s)
