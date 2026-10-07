from pathlib import Path
import sys
base=Path('outputs/Windows10-Components').resolve();controller=base/'Probe-USVFS.py'
source=controller.read_text(encoding='utf-8-sig')
source=source.replace("exe=base/'Runtime/Explorer10/explorer.exe'", "exe=base/'Lab/ResourceCompat/Injected/explorer.exe'")
source=source.replace("out=base/'Metadata'/('usvfs-'+args.preset+'-probe.json')", "out=base/'Lab/NotificationCompat/own-child-probe.json'")
old=' if args.capture_debug:\n  if not debugAttach(pi.pid):raise C.WinError(C.get_last_error())\n  attached=True;debugKill(False);resume(pi.thread)'
new=''' if args.capture_debug:
  import importlib.util
  def module(name,path):
   spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
  mod=module('resource_bootstrap',base/'Launch-ResourceCompat.py')
  notification=module('notification_adapter',base/'Launch-NotificationCompat.py')
  boot=mod.OwnChildBootstrap(pi,exe)
  boot.pause_at_entry()
  boot.install_resource_hook(base/'Lab/ResourceCompat/FactoryWrapper/RSCW10.dll')
  result['notificationCompat']=notification.install_notification_hook(boot)
  boot.finish(detach=True)
  result['resourceBootstrap']=boot.events
'''
assert old in source
source=source.replace(old,new)
sys.argv=[str(controller),'--preset','immersive-compat','--seconds','3','--capture-debug']
exec(compile(source,str(controller),'exec'),{'__file__':str(controller)})
