import hashlib,json,os,pathlib,subprocess
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parents[3]
zig=ROOT/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
source=HERE/'SettingsCaptionCompat.c';dll=HERE/'SettingsCaptionCompat.dll'
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'work/compat-research/zig-cache'))
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O2',str(source),'-o',str(dll),'-lole32','-lbcrypt','-luuid']
r=subprocess.run(cmd,env=env,creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=90)
(HERE/'adapter-compiler.stdout').write_bytes(r.stdout);(HERE/'adapter-compiler.stderr').write_bytes(r.stderr)
if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace'))
sourceCS=HERE/'SettingsApplicabilityProbe.cs';exe=HERE/'SettingsApplicabilityProbe.exe'
r=subprocess.run([r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe','/nologo','/target:winexe','/out:'+str(exe),str(sourceCS)],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=40)
if r.returncode:raise RuntimeError(r.stdout.decode(errors='replace'))
with subprocess.Popen([str(exe),str(HERE/'merged.log'),'public',r'C:\Windows\System32\SystemSettings.DataModel.dll','16450',str(dll)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
 result={'scope':'Own non-UI process only, genuine old/native predicates; own VM lambda install/readback/restore; no live Settings','pid':child.pid,'image':str(exe),'creationFlags':'CREATE_NO_WINDOW'}
 try:out,err=child.communicate(timeout=25);result['timedOut']=False
 except subprocess.TimeoutExpired:child.kill();out,err=child.communicate(timeout=5);result['timedOut']=True
 result['exitCode']=child.returncode
 (HERE/'merged.stdout').write_bytes(out);(HERE/'merged.stderr').write_bytes(err)
result['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,dll,sourceCS,exe]}
log=(HERE/'merged.log').read_text('utf8')
expected={'SettingsPagePCSystemDisplay':1,'SettingsPageAudio':1,'SettingsPageAppsNotifications':0,'SettingsPageAbout_ControlPanelSystem':0,'SettingsPageAbout':1,'SettingsPageAbout_New':0,'SettingsPagePCSystemInfo':1}
rows={parts[1]:parts for parts in (line.split('\t') for line in log.splitlines()) if parts[0]=='MERGED'}
result['allGenuineQueriesMatchPreviouslyObservedProviders']=len(rows)==len(expected) and all(rows[k][2]=='00000000' and rows[k][3]==str(v) and rows[k][4]=='canary=True' for k,v in expected.items())
result['routesExact3Old4Native']='ROUTES\told=3\tnative=4' in log
result['ownPatchAndRestorePass']='OWN_INIT\t00000000' in log and 'OWN_RESTORE\t00000000' in log and 'OWN_ORIGINAL\t48-83-EC-28-48-8B-41-08-4C-8B-41-18-4C-8B-48-30' in log
(HERE/'own-merge-proof.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result))
