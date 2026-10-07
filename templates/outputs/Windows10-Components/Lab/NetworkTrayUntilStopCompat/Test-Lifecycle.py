import subprocess,ctypes as C,json,time,uuid,sys
from pathlib import Path
lab=Path(__file__).resolve().parent;root=lab.parents[3];zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
source=(lab/'NetworkTrayUntilStop.c').read_text();a=source.index(' HRESULT hr=CoInitializeEx');b=source.index(' if(stopRequested&&SUCCEEDED(hr))',a)
source=source[:a]+' HRESULT hr=S_OK;BOOL comInitialized=FALSE;HMODULE dll=NULL;IUnknown*object=NULL;BOOL started=FALSE;if(!wcscmp(argv[9],L"stall"))Sleep(INFINITE);\n'+source[b:]
source=source.replace('||actual!=shellPid','').replace('||pid!=shellPid','').replace('seconds<15','seconds<1').replace('stopTick+10000','stopTick+500').replace('if(SUCCEEDED(hr)&&started){FILE*ready','if(SUCCEEDED(hr)){FILE*ready').replace(' cleanup:\n',' cleanup:\n fprintf(f,"FIXTURE cooperative cleanup; no actual SSO was started\\n");\n')
(lab/'LifecycleFixture.c').write_text(source)
(lab/'TargetFixture.c').write_text('#include <windows.h>\nint WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){Sleep(30000);return 0;}')
for stem in ['LifecycleFixture','TargetFixture']:
 cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-Wl,--subsystem,windows',str(lab/(stem+'.c')),'-o',str(lab/(stem+'.exe')),'-lole32','-luuid','-lshell32','-luser32'];p=subprocess.run(cmd,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,text=True);assert p.returncode==0,p.stderr
K=C.WinDLL('kernel32',use_last_error=True);K.OpenProcess.restype=C.c_void_p;K.OpenProcess.argtypes=[C.c_ulong,C.c_int,C.c_ulong];K.GetProcessTimes.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p];K.CloseHandle.argtypes=[C.c_void_p]
def birth(pid):
 h=K.OpenProcess(0x1000,False,pid);times=[C.c_ulonglong() for _ in range(4)]
 assert K.GetProcessTimes(h,*[C.byref(t) for t in times]);K.CloseHandle(h);return times[0].value
results=[]
for mode in ['until-cancel','bounded-deadline','target-death','bootstrap-stall','wrong-birth']:
 target=subprocess.Popen([str(lab/'TargetFixture.exe')],creationflags=subprocess.CREATE_NO_WINDOW);nonce=uuid.uuid4().hex;prefix=lab/('fixture-'+nonce);born=birth(target.pid);args=[str(lab/'LifecycleFixture.exe'),'--run' if mode=='bounded-deadline' else '--until-stop',str(target.pid),str(born+1 if mode=='wrong-birth' else born),str(lab/'TargetFixture.exe'),'1',str(prefix)+'.stop',str(prefix)+'.ready',str(prefix)+'.log','stall' if mode=='bootstrap-stall' else 'none']
 started=time.monotonic();helper=subprocess.Popen(args,creationflags=subprocess.CREATE_NO_WINDOW)
 try:
  if mode in ['until-cancel','target-death']:
   deadline=time.monotonic()+3
   while not Path(str(prefix)+'.ready').exists() and time.monotonic()<deadline and helper.poll() is None:time.sleep(.02)
   assert Path(str(prefix)+'.ready').exists()
   time.sleep(1.6);assert helper.poll() is None,'UntilStop still had total deadline'
   if mode=='until-cancel':Path(str(prefix)+'.stop').write_text('cancel')
   else:target.terminate();target.wait(3)
  helper.wait(4);expected=125 if mode=='bootstrap-stall' else 4 if mode=='wrong-birth' else 0;assert helper.returncode==expected,(mode,helper.returncode)
  results.append(dict(Mode=mode,ExitCode=helper.returncode,Elapsed=time.monotonic()-started,NoIconChanges=True,Log=Path(str(prefix)+'.log').read_text() if Path(str(prefix)+'.log').exists() else 'No bootstrap'))
 finally:
  if helper.poll() is None:helper.terminate();helper.wait(3)
  if target.poll() is None:target.terminate();target.wait(3)
(lab/'lifecycle-own-proof.json').write_text(json.dumps(dict(Tests=results,Changes=['Harmless own target replaces native shell-owner lookup in fixture ONLY','No real COM/factory/SSO initialization in lifecycle fixture','Time scale1s bootstrap/500ms cleanup in fixture ONLY'],ProductionUnchanged=True),indent=2));print(json.dumps([(r['Mode'],r['ExitCode']) for r in results]))
