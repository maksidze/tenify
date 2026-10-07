from pathlib import Path
import sys,json,time,subprocess,ctypes as C,struct,importlib.util
from ctypes import wintypes as W
root=Path(__file__).resolve().parents[1];base=root/'outputs/Windows10-Components';lab=base/'Lab/ShellAppearanceCompat';sys.path.insert(0,str(lab));import SessionController as S
_spec=importlib.util.spec_from_file_location('network_readonly_state',base/'Lab/NetworkNtPathCompat/Read-State.py');Telemetry=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(Telemetry)
statePath=Path((root/'work/network-layout-trial-prepared.txt').read_text().strip());state=json.loads(statePath.read_text());directory=Path(state['Directory']);PS='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
S.preflight(state);baseline=[x for x in S.census(state)if x['Path'].casefold()in(state['NativePath'].casefold(),'c:\\windows\\system32\\runtimebroker.exe')];(directory/'root-baseline.json').write_text(json.dumps(baseline,indent=2));controller=None;guard=None;held=[];result={'NoVFS':True,'SystemFilesModified':False,'State':str(statePath)}
try:
 guard=subprocess.Popen([sys.executable,str(root/'work/NetworkLayout-TrialGuard.py'),str(statePath)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 grant=subprocess.run([PS,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(root/'work/NetworkLayout-SourceAccess.ps1'),'-StatePath',str(statePath),'-Mode','Grant'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=30)
 if grant.returncode:raise RuntimeError('Private source access failed '+grant.stderr.decode(errors='replace')[-1000:])
 with(directory/'root-controller.stdout').open('w')as so,(directory/'root-controller.stderr').open('w')as se:
  stopped=[]
  for item in baseline:
   role=dict(state);role['NativePath']=item['Path'];stopped.append(dict(Pid=item['Pid'],Birth=item['Birth'],Path=item['Path'],Outcome=S.exact_stop(item['Pid'],item['Birth'],role)))
  result['BaselineStops']=stopped
  controller=subprocess.Popen([sys.executable,str(lab/'SessionController.py'),'begin',str(statePath)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=so,stderr=se)
  deadline=time.monotonic()+12
  while time.monotonic()<deadline and controller.poll()is None and not(directory/'enabled.json').exists():time.sleep(.1)
  if not(directory/'enabled.json').exists():raise RuntimeError('Registration readiness absent')
  if not S.registration_owned(S.debug_snapshot(state),state['DebuggerCommand']):raise RuntimeError('Registration ownership differs')
  activate=subprocess.run([str(base/'Lab/StartCompat/PackageDebugController.exe'),'activate',state['PackageFamilyName']+'!App',''],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=15);result['ActivateExit']=activate.returncode
  deadline=time.monotonic()+30;records=[]
  while time.monotonic()<deadline:
   records=S.records(directory)
   if records and any('DETACH_OWNERSHIP_TRANSFER' in f.with_suffix('.log').read_text(errors='replace')for f,_,_ in records if f.with_suffix('.log').exists()):break
   if controller.poll()is not None:break
   time.sleep(.1)
  result['Records']=[dict(Path=str(f),Pid=pid,Birth=born)for f,pid,born in records]
  transferred=[(f,pid,born)for f,pid,born in records if f.with_suffix('.log').exists()and 'DETACH_OWNERSHIP_TRANSFER' in f.with_suffix('.log').read_text(errors='replace')]
  if not transferred:raise RuntimeError('Fresh broker bootstrap did not transfer ownership')
  def snapshot_network(label):
   rows=[]
   for _,pid,born in transferred:
    try:rows.append(Telemetry.snapshot(directory,pid,born))
    except Exception as error:rows.append(dict(PID=pid,Birth=born,Status='ReadbackRefused',Error=str(error)))
   (directory/('root-network-factory-'+label+'.json')).write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
   return rows
  result['FactoryBeforeShow']=snapshot_network('before-show')
  result['PackageCensusBeforeShow']=S.census(state)
  for _,pid,born in transferred:
   handle=S.open_process(0x101000,False,pid)
   if not handle:raise RuntimeError('Before-show exact process handle unavailable '+str(pid))
   ident=S.identity(handle)
   if S.wait(handle,0)==0 or not ident or ident['Birth']!=born or ident['Path'].casefold()!=state['NativePath'].casefold() or ident['Package']!=state['PackageFullName']:
    S.close(handle);raise RuntimeError('Before-show exact process handle identity differs')
   held.append((pid,born,handle,ident))
  def module_census(label):
   output=directory/('root-network-module-census-'+label+'.json')
   call=subprocess.run([PS,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(base/'Lab/NetworkActualHostResearch/Module-Census.ps1'),'-OutputPath',str(output)],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=15)
   return json.loads(output.read_text(encoding='utf-8-sig')) if call.returncode==0 and output.exists() else {'Status':'CensusRefused','Exit':call.returncode,'Error':call.stderr.decode(errors='replace')[-1000:]}
  result['NetworkModuleCensusBeforeShow']=module_census('before-show')
  probe=base/'Lab/NetworkActualHostResearch/Show-Anchored.exe';show=subprocess.run([str(probe),str(directory/'root-show.log')],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=15);result['ShowExit']=show.returncode
  time.sleep(4)
  result['ShowLog']=(directory/'root-show.log').read_text(errors='replace')
  result['FactoryAfterShow']=snapshot_network('after-show')
  result['NetworkModuleCensusAfterShow']=module_census('after-show')
  result['PackageCensusAfterShow']=S.census(state)
  get_exit=S.api('GetExitCodeProcess',W.BOOL,[S.P,S.P]);result['HeldProcessAfterShow']=[]
  for pid,born,handle,ident in held:
   wait=S.wait(handle,0);code=W.DWORD();ok=get_exit(handle,C.byref(code));result['HeldProcessAfterShow'].append(dict(PID=pid,Birth=born,Identity=ident,Wait=wait,ExitCode=code.value if ok else None,ExitHex=hex(code.value)if ok else None,WinError=0 if ok else C.get_last_error(),HeldFromBeforeShow=True))
  result['FactoryTelemetryLimitation']='Exact counter/physical/IAT readback proves selected factories; successful ShowFlyout does not itself prove old visible layout, and zero counters can reflect internal old-DLL construction outside SEH import hooks.'
  result['Status']='trial-target-exited' if any(row['Wait']==0 for row in result['HeldProcessAfterShow']) else 'trial-process-alive-layout-unverified'
except Exception as e:result.update(Status='trial-failed',Error=str(e))
finally:
 for _,_,handle,_ in held:S.close(handle)
 (directory/'root-trial-result.json').write_text(json.dumps(result,indent=2));(directory/'root-stop').touch()
 if guard:
  try:guard.wait(timeout=35)
  except subprocess.TimeoutExpired:result['GuardPending']=True
 if controller:
  try:controller.wait(timeout=15)
  except subprocess.TimeoutExpired:result['ControllerPending']=True
 native=[x for x in S.census(state)if x['Path'].casefold()==state['NativePath'].casefold()]
 if not native:
  subprocess.run([str(base/'Lab/StartCompat/PackageDebugController.exe'),'activate',state['PackageFamilyName']+'!App',''],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=15)
 result['Restored']=(directory/'restored.json').exists();result['Guard']=(directory/'root-guard-result.json').read_text(errors='replace')if(directory/'root-guard-result.json').exists()else None
 (directory/'root-trial-result.json').write_text(json.dumps(result,indent=2))
 print(json.dumps(result,indent=2))
