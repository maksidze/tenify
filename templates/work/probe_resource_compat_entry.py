from pathlib import Path
import sys
detach='--detach' in sys.argv
base=Path('outputs/Windows10-Components').resolve();controller=base/'Probe-USVFS.py'
source=controller.read_text(encoding='utf-8-sig')
source=source.replace("exe=base/'Runtime/Explorer10/explorer.exe'", "exe=base/'Lab/ResourceCompat/Injected/explorer.exe'")
name='EntryDetached' if detach else 'EntryDebug'
source=source.replace("out=base/'Metadata'/('usvfs-'+args.preset+'-probe.json')", "out=base/'Lab/ResourceCompat/"+name+"-probe.json'")
old=' if args.capture_debug:\n  if not debugAttach(pi.pid):raise C.WinError(C.get_last_error())\n  attached=True;debugKill(False);resume(pi.thread)'
new=''' if args.capture_debug:
  import importlib.util
  spec=importlib.util.spec_from_file_location('resource_bootstrap',base/'Launch-ResourceCompat.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
  boot=mod.OwnChildBootstrap(pi,exe)
  boot.pause_at_entry()
  boot.install_resource_hook(base/'Lab/ResourceCompat/FactoryWrapper/RSCW10.dll')
  boot.finish(detach=DETACH)
  result['resourceBootstrap']=boot.events
  if not DETACH:
   attached=True;debugHandles.update(boot.debug_handles)
'''.replace('DETACH',str(detach))
source=source.replace(old,new)
source=source.replace('except Exception as e:result.update(error=str(e))',"except Exception as e:\n import traceback\n result.update(error=str(e),errorType=type(e).__name__,traceback=traceback.format_exc())")
sys.argv=[str(controller),'--preset','immersive-compat','--seconds','10','--capture-debug']
exec(compile(source,str(controller),'exec'),{'__file__':str(controller)})
