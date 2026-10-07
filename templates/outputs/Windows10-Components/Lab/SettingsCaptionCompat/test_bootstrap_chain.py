import hashlib,json,pathlib,subprocess
HERE=pathlib.Path(__file__).resolve().parent
source=HERE/'BootstrapChainProof.cs';exe=HERE/'BootstrapChainProof.exe';dll=HERE/'SettingsCaptionCompat.dll'
r=subprocess.run([r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe','/nologo','/target:winexe','/out:'+str(exe),str(source)],creationflags=subprocess.CREATE_NO_WINDOW,capture_output=True,timeout=40)
if r.returncode:raise RuntimeError(r.stdout.decode(errors='replace'))
with subprocess.Popen([str(exe),str(HERE/'bootstrap-chain.log'),str(dll)],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as child:
 result={'scope':'own MTA non-UI process; compose proven prior initializer plus caption adapter; no Settings activation','pid':child.pid,'creationFlags':'CREATE_NO_WINDOW','dllSHA256':hashlib.sha256(dll.read_bytes()).hexdigest()}
 try:out,err=child.communicate(timeout=25);result['timedOut']=False
 except subprocess.TimeoutExpired:child.kill();out,err=child.communicate(timeout=5);result['timedOut']=True
 result['exitCode']=child.returncode
 (HERE/'bootstrap-chain.stdout').write_bytes(out);(HERE/'bootstrap-chain.stderr').write_bytes(err)
(HERE/'own-bootstrap-chain-proof.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result))
