from pathlib import Path
import shutil,subprocess,sys,concurrent.futures,json,os
base=Path('outputs/Windows10-Components').resolve();image=base/'Image/4';root=image/'Windows/System32'
def stage(name,files):
 dest=base/'Runtime'/name;dest.mkdir(parents=True,exist_ok=True)
 for f in files:
  src=root/f
  if src.is_file():shutil.copy2(src,dest/f)
  for lang in ['ru-RU','en-US']:
   for leaf in [f+'.mui',f]:
    src=root/lang/leaf
    if src.is_file():(dest/lang).mkdir(exist_ok=True);shutil.copy2(src,dest/lang/leaf)
 return dest
task=stage('TaskManager10',['taskmgr.exe'])
device=stage('DeviceManager10',['mmc.exe','mmc.exe.config','mmcbase.dll','mmcndmgr.dll','mmcshext.dll','devmgr.dll','devmgmt.msc'])
items=[('taskmanager-isolated-probe',task/'taskmgr.exe',[]),('device-manager-isolated-probe',device/'mmc.exe',[str(device/'devmgmt.msc')]),('startmenu-direct-probe',image/'Windows/SystemApps/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/StartMenuExperienceHost.exe',[]),('shellexperience-direct-probe',image/'Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy/ShellExperienceHost.exe',[]),('settings-direct-probe',image/'Windows/ImmersiveControlPanel/SystemSettings.exe',[])]
def probe(item):
 name,exe,args=item;env=os.environ.copy()
 if '--as-invoker' in sys.argv:
  name=name.replace('-isolated-probe','-as-invoker-probe');env['__COMPAT_LAYER']='RunAsInvoker'
 cmd=[sys.executable,str(base/'Probe-Explorer10.py'),'--exe',str(exe),'--seconds','7','--output',str(base/'Metadata'/(name+'.json'))]
 for a in args:cmd+=['--arg',a]
 r=subprocess.run(cmd,capture_output=True,timeout=25,env=env)
 print(name,'exit',r.returncode,'log',str(base/'Metadata'/(name+'.json')),flush=True)
 return {'name':name,'probeExit':r.returncode,'stdout':r.stdout.decode('utf-8',errors='replace'),'stderr':r.stderr.decode('utf-8',errors='replace')}
if '--as-invoker' in sys.argv:items=items[:2]
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(probe,items))
(base/'Metadata'/('optional-as-invoker-runner.json' if '--as-invoker' in sys.argv else 'optional-probe-runner.json')).write_text(json.dumps(results,indent=2),encoding='utf-8')
