from pathlib import Path
import sys
base=Path('outputs/Windows10-Components').resolve();source=(base/'Launch-Explorer10-VFS.py').read_text(encoding='utf-8-sig')
start=source.index('    bootstrap=None\n');end=source.index('    if a.capture_debug:\n',start)
inject=r'''
    import importlib.util,struct
    sys.path.insert(0,str(Path('work/pylib').resolve()))
    import pefile
    spec=importlib.util.spec_from_file_location('component_probe_bootstrap',base/'Launch-ResourceCompat.py');bm=importlib.util.module_from_spec(spec);spec.loader.exec_module(bm)
    boot=bm.OwnChildBootstrap(pi,exe);boot.pause_at_entry()
    pcs=base/'Lab/WindowStaticsCompat/twinui.pcshell.dll';pcsbase=boot.load_library(pcs)
    helper=base/'Lab/ComponentFactoryCompat/COMPW10.dll';helperbase=boot.load_library(helper)
    pe=pefile.PE(str(helper));exports={x.name.decode():x.address for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name}
    tid=D();thread=boot.remote_thread(pi.process,None,0,helperbase+exports['ProbeXamlExplorerClassFactory'],None,0,C.byref(tid))
    if not thread:raise C.WinError(C.get_last_error())
    deadline=time.monotonic()+12
    while boot.wait(thread,0)==258 and time.monotonic()<deadline:
        event=bm.DebugEvent()
        if boot.debug_wait(C.byref(event),100):boot.consume(event)
    if boot.wait(thread,0)!=0:raise RuntimeError('Class factory probe timeout')
    values=struct.unpack('<5i',boot.read(helperbase+exports['ProbeResult'],20))
    descriptor=boot.read(pcsbase+0x649d50,24);guidptr,flags,required,feature=struct.unpack('<QIIQ',descriptor)
    import uuid
    proof={'ownedHiddenChild':pi.pid,'factoryModule':str(pcs),'coInitHR':hex(values[0]&0xffffffff),'getClassObjectHR':hex(values[1]&0xffffffff),'factoryNonNull':bool(values[2]),'createInstanceIUnknownHR':hex(values[3]&0xffffffff),'instanceNonNull':bool(values[4]),'descriptor116':{'CLSID':str(uuid.UUID(bytes_le=boot.read(guidptr,16))),'flags':flags,'required':required,'featureCallbackRVA':hex(feature-pcsbase)},'events':boot.events,'logs':boot.logs}
    (base/'Lab/ComponentFactoryCompat/direct-factory-probe.json').write_text(json.dumps(proof,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps({k:v for k,v in proof.items() if k not in ('events','logs')},indent=2))
    boot.close(thread);boot.finish(detach=True,resume_primary=False)
    raise SystemExit(0)
'''
source=source[:start]+inject+source[end:]
sys.argv=[str(base/'Launch-Explorer10-VFS.py'),'--profile','legacy-watchers','--preflight','--run-directory',str(base/'Lab/ComponentFactoryCompat/own-child-run')]
exec(compile(source,str(base/'Launch-Explorer10-VFS.py'),'exec'),{'__file__':str(base/'Launch-Explorer10-VFS.py')})
