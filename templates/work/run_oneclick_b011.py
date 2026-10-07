from pathlib import Path
import subprocess,json,sys
sys.stdout.reconfigure(encoding="utf-8",errors="replace")
root=Path(__file__).resolve().parents[1];base=root/'outputs/Windows10-Components';out=root/'work/b011-deploy';out.mkdir(exist_ok=True)
mode=sys.argv[1]if len(sys.argv)>1 else'Check'
with(out/(mode+'.stdout.txt')).open('w',encoding='utf-8')as so,(out/(mode+'.stderr.txt')).open('w',encoding='utf-8')as se:
 p=subprocess.Popen(['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(base/'Windows10-OneClick.ps1'),'-Mode',mode],creationflags=subprocess.CREATE_NO_WINDOW,stdout=so,stderr=se)
 print(json.dumps(dict(Controller=p.pid,Mode=mode,Output=str(out))),flush=True)
 try:code=p.wait(timeout=240)
 except subprocess.TimeoutExpired:print('Controller still pending; inspect owned logs before further action');sys.exit(2)
print(json.dumps(dict(Exit=code,Mode=mode)),flush=True)
print((out/(mode+'.stdout.txt')).read_text(encoding='utf-8',errors='replace')[-4000:]);print((out/(mode+'.stderr.txt')).read_text(encoding='utf-8',errors='replace')[-2000:]);sys.exit(code)
