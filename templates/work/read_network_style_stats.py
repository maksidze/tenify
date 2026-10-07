from pathlib import Path
import ctypes as C,json,sys,struct,hashlib,importlib.util,types
R=Path(__file__).resolve().parent.parent;B=R/'outputs/Windows10-Components';L=B/'Lab/ShellAppearanceCompat'
sys.path.insert(0,str(L));sys.path.insert(0,str(R/'work/pylib'))
import SessionController as S,pefile
directory=Path(sys.argv[1]);state=json.loads((directory/'state.json').read_text())
rows=[]
for record,pid,birth in S.records(directory):
    log=record.with_suffix('.log')
    if not log.exists() or not log.read_text().startswith('DETACH_OWNERSHIP_TRANSFER'):continue
    report=json.loads(log.read_text().split('\n',1)[1]);mapping=report['AdapterMappings'][0]
    helper=Path(mapping['PhysicalHelper']['expectedPhysicalFile'])
    activation=json.loads((directory/f'activation_{pid}_{birth}'/'activation.json').read_text())
    helper=Path(activation['Adapters'][0]['Helper']);base=int(mapping['HelperBase'],16)
    if hashlib.sha256(helper.read_bytes()).hexdigest()!=activation['Adapters'][0]['HelperSHA256']:raise RuntimeError('Helper hash differs')
    h=S.open_process(0x101010,False,pid)
    if not h:continue
    try:
        ident=S.identity(h)
        if not ident or ident['Birth']!=birth or ident['Path'].casefold()!=state['NativePath'].casefold() or ident['Package']!=state['PackageFullName'] or S.wait(h,0)!=258:continue
        spec=importlib.util.spec_from_file_location('netstats_identity',B/'Launch-TouchpadCompat.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        m.mapped_file_identity(types.SimpleNamespace(pi=types.SimpleNamespace(process=h)),base,helper)
        read=S.api('ReadProcessMemory',C.c_int,[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p])
        pe=pefile.PE(str(helper));exports={e.name.decode():e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
        values={}
        for name in ['NetworkPageApplyCount','NetworkPageConnectCount','NetworkPageLoadedCount','NetworkPageErrorCount','NetworkPageLastError','NetworkPageRecordCount','NetworkControlsCount','NetworkControlsLayoutCount']:
            if name not in exports:continue
            # These exports are trivial getter FUNCTIONS, not data symbols.
            # Verify their complete expected prologue/load/epilogue before
            # reading the referenced static LONG without executing code.
            code=pe.get_data(exports[name],12)
            if code[:6]==bytes.fromhex('554889e58b05') and code[10:12]==bytes.fromhex('5dc3'):
                rva=exports[name]+10+struct.unpack('<i',code[6:10])[0]
            elif code[:2]==bytes.fromhex('8b05') and code[6]==0xc3:
                rva=exports[name]+6+struct.unpack('<i',code[2:6])[0]
            else:raise RuntimeError('Unrecognized counter getter '+name)
            value=C.c_uint32();got=C.c_size_t()
            if not read(h,base+rva,C.byref(value),4,C.byref(got)) or got.value!=4:raise C.WinError(C.get_last_error())
            values[name]=value.value
        if S.identity(h)!=ident or S.wait(h,0)!=258:raise RuntimeError('Identity exited during read')
        surface=None
        if 'NetworkControlsSurface' in exports:
            spec=importlib.util.spec_from_file_location('net_surface',B/'Lab/NetworkControlSquareCompat/SurfaceReader.py');surface_reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(surface_reader)
            surface=surface_reader.read_surface(h,base)
        rows.append(dict(PID=pid,Birth=birth,Stats=values,Surface=surface,ReadOnly=True))
    finally:S.close(h)
text=json.dumps(rows,indent=2);(directory/'root-readonly-stats.json').write_text(text);print(text)
