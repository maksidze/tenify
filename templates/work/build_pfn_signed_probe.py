from pathlib import Path
s=Path('work/probe_resource_compat_injected.py').read_text(encoding='utf8')
s=s.replace("lab=base/'Lab/ResourceCompat/Injected'","lab=base/'Lab/PfnCompat/SignedInjected'")
s=s.replace("base/'Lab/ResourceCompat/Injected-probe.json'","base/'Lab/PfnCompat/signed-injected-probe.json'")
s=s.replace("base/'Lab/ResourceCompat/Injected/explorer.exe'","base/'Lab/PfnCompat/SignedInjected/explorer.exe'")
s=s.replace("shim=base/'Lab/ResourceCompat/FactoryWrapper/RSCW10.dll'","shim=base/'Lab/PfnCompat/UZER32.dll'")
start=s.index('  pe=pefile.PE(str(exe));target=');end=s.index("\n'''",start)
s=s[:start]+'''  pe=pefile.PE(str(exe));lib=pefile.PE(str(shim))
  byname={x.name:x for x in lib.DIRECTORY_ENTRY_EXPORT.symbols if x.name};byord={x.ordinal:x for x in lib.DIRECTORY_ENTRY_EXPORT.symbols}
  imports=next(d for d in pe.DIRECTORY_ENTRY_IMPORT if d.dll.lower()==b'user32.dll');changes=[];preserved=[]
  for i in imports.imports:
   x=byname.get(i.name) if i.name else byord.get(i.ordinal)
   if not x:raise RuntimeError('Old USER32 export missing')
   if x.forwarder:
    if x.forwarder!=b'NTDLL.NtdllDefWindowProc_A':raise RuntimeError('Unresolved DLL forwarder')
    preserved.append((i.name or str(i.ordinal).encode()).decode());continue
   changes.append((i.address-pe.OPTIONAL_HEADER.ImageBase,shimBase+x.address,(i.name or str(i.ordinal).encode()).decode()))
  for target,replacement,name in changes:
   site=exeBase+target;oldProt=D()
   if not protect(pi.process,site,8,4,C.byref(oldProt)):raise C.WinError(C.get_last_error())
   try:
    value=C.create_string_buffer(struct.pack('<Q',replacement));n=C.c_size_t()
    if not write(pi.process,site,value,8,C.byref(n)) or n.value!=8:raise C.WinError(C.get_last_error())
   finally:
    ignored=D();protect(pi.process,site,8,oldProt.value,C.byref(ignored))
  result['ownedChildIATHook']={'pid':pi.pid,'helper':str(shim),'signedExeOnDiskUnchanged':True,'slotsChanged':len(changes),'sameNativeForwardersPreserved':preserved}
  resume(pi.thread)
'''+s[end:]
s=s.replace("if e.code==1 and int.from_bytes(bytes(e.data)[:4],'little')==0x80000003:initial=True", "if e.code==1 and int.from_bytes(bytes(e.data)[:4],'little')==0x80000003:\n     initial=True\n     suspend=api(kernel,'SuspendThread',D,[P])\n     if suspend(pi.thread)==0xffffffff:raise C.WinError(C.get_last_error())")
Path('work/probe_pfn_signed_injected.py').write_text(s,encoding='utf8')
