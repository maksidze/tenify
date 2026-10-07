from pathlib import Path
import subprocess,sys,uuid,json
r=Path(__file__).resolve().parents[1];b=r/'outputs/Windows10-Components';hybrid='--hybrid' in sys.argv;out=b/'state-vfs'/(('preflight-hybrid-theme-' if hybrid else 'preflight-control-theme-')+uuid.uuid4().hex);out.mkdir(parents=True)
with (out/'stdout.txt').open('w') as so,(out/'stderr.txt').open('w') as se:
 p=subprocess.Popen([sys.executable,str(b/'Launch-Explorer10-VFS.py'),'--preflight','--profile','host-dcomp-resource','--xaml-quirk','--icons10',('--hybrid-theme10' if hybrid else '--control-theme10'),'--run-directory',str(out)],stdout=so,stderr=se,creationflags=subprocess.CREATE_NO_WINDOW)
 try:code=p.wait(timeout=75)
 except subprocess.TimeoutExpired:
  (out/'stop').write_text('Bounded preflight exceeded time; root requested own cleanup')
  try:code=p.wait(timeout=20)
  except subprocess.TimeoutExpired:print(json.dumps({'PendingCleanup':True,'controller':p.pid,'run':str(out)}));sys.exit(2)
print(json.dumps({'Exit':code,'Run':str(out)}))
if (out/'status.json').exists():
 s=json.loads((out/'status.json').read_text());print(json.dumps({k:s.get(k)for k in ['status','error','pid','controlTheme10Hook','hybridTheme10Hook','themeFolderProof']},indent=2))
print((out/'stderr.txt').read_text(errors='replace')[-3000:]);sys.exit(code)