"""Bounded ordinary children only; no Explorer attachment or live UI interaction."""
from pathlib import Path
import ctypes, datetime, hashlib, json, subprocess, sys

ROOT=Path(__file__).resolve().parents[1]
LAB=ROOT/'outputs/Windows10-Components/Lab/InputSwitchCompat'
EXE=LAB/'InputSwitchProbe.exe'
manifest=json.loads((LAB/'guard-manifest.json').read_text())
for name,digest in manifest['artifacts'].items():
    assert hashlib.sha256((LAB/name).read_bytes()).hexdigest()==digest, ('stale artifact',name)
user=ctypes.WinDLL('user32',use_last_error=True)
user.OpenDesktopW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32]
user.OpenDesktopW.restype=ctypes.c_void_p
user.CloseDesktop.argtypes=[ctypes.c_void_p]
user.CloseDesktop.restype=ctypes.c_int
results=[]
for arg,limit in [('--fixtures',10),('--native-query',20)]:
    log=LAB/(arg[2:]+'.log')
    with log.open('w',encoding='utf-8') as out:
        child=subprocess.Popen([str(EXE),arg],stdout=out,stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        item={'arg':arg,'pid':child.pid,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'timeoutSeconds':limit,'killedExactOwnPid':False,'executableSha256':manifest['artifacts'][EXE.name]}
        try:
            item['exitCode']=child.wait(limit)
        except subprocess.TimeoutExpired:
            child.kill();item['killedExactOwnPid']=True;item['exitCode']=child.wait(5)
    item['exactChildExited']=child.poll() is not None
    if arg=='--native-query':
        ctypes.set_last_error(0)
        desktop=user.OpenDesktopW(f'InputSwitchReadOnly-{child.pid}',0,False,1)
        error=ctypes.get_last_error()
        if desktop:user.CloseDesktop(desktop)
        item['desktopOpenAfterChildExit']=bool(desktop)
        item['desktopOpenError']=error
        item['desktopReleasedByProcessExit']=not desktop and error==2
    text=log.read_text(encoding='utf-8')
    item['log']=str(log)
    item['passed']=item['exitCode']==0 and item['exactChildExited'] and item.get('desktopReleasedByProcessExit',True)
    results.append(item)
    print(json.dumps(item));print(text)
    if not item['passed']:break
(LAB/'own-probe-results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
sys.exit(0 if len(results)==2 and all(x['passed'] for x in results) else 1)
