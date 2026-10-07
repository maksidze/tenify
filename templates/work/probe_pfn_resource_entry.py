"""Combined PFN + MRT, signed owned child held at PE entry, never live shell."""
from pathlib import Path
import sys,shutil
base=Path('outputs/Windows10-Components').resolve();controller=base/'Probe-USVFS.py';lab=base/'Lab/PfnCompat/ResourceEntry';lab.mkdir(parents=True,exist_ok=True)
shutil.copy2(base/'Runtime/Explorer10/explorer.exe',lab/'explorer.exe');shutil.copytree(base/'Runtime/Explorer10/ru-RU',lab/'ru-RU',dirs_exist_ok=True)
for name in ['UZER32.dll','W1N32U.dll','pfn-runtime-hashes.json']:shutil.copy2(base/'Lab/PfnCompat'/name,lab/name)
source=controller.read_text(encoding='utf-8-sig').replace("out=base/'Metadata'/('usvfs-'+args.preset+'-probe.json')","out=base/'Lab/PfnCompat/resource-entry-probe.json'").replace("exe=base/'Runtime/Explorer10/explorer.exe'","exe=base/'Lab/PfnCompat/ResourceEntry/explorer.exe'")
old=' if args.capture_debug:\n  if not debugAttach(pi.pid):raise C.WinError(C.get_last_error())\n  attached=True;debugKill(False);resume(pi.thread)'
inject=r'''
 if args.capture_debug:
  import importlib.util,sys
  sys.path.insert(0,str(Path('work/pylib').resolve()))
  import pefile
  spec=importlib.util.spec_from_file_location('resourcebootstrap',base/'Launch-ResourceCompat.py');bootmod=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootmod)
  boot=bootmod.OwnChildBootstrap(pi,exe);boot.pause_at_entry();attached=True;debugHandles.update(boot.debug_handles)
  spec2=importlib.util.spec_from_file_location('pfnbootstrap',base/'Launch-PfnCompat.py');pfnmod=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(pfnmod)
  pfn_result=pfnmod.install_pfn_hook(boot,exe.parent)
  boot.install_resource_hook(base/'Lab/ResourceCompat/FactoryWrapper/RSCW10.dll')
  result['ownedChildHooks']={'pfn':pfn_result,'resourceHook':True,'entryHeldAfterDllInit':True,'signedExeOnDiskUnchanged':True,'modulesAtHook':{k:hex(v) for k,v in boot.modules().items()}}
  boot.finish(detach=False);result['bootstrapEvents']=boot.events;result['bootstrapLogs']=boot.logs
'''
assert old in source;source=source.replace(old,inject)
source=source.replace("except Exception as e:result.update(error=str(e))","except Exception as e:\n import traceback\n result.update(error=str(e),errorType=type(e).__name__,traceback=traceback.format_exc())")
source=source.replace("debugEvents.append({'type':'exception','code':hex(code),'firstChance':bool(first)})","debugEvents.append({'type':'exception','code':hex(code),'firstChance':bool(first),'address':hex(struct.unpack_from('<Q',d,16)[0])})")
sys.argv=[str(controller),'--preset','immersive-compat','--seconds','12','--capture-debug'];exec(compile(source,str(controller),'exec'),{'__file__':str(controller)})
