from pathlib import Path
import subprocess,json,time
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/AppFrameManagerCompat'
command=[str(lab/'Test-AppFrameManager.exe'),str(lab/'AppFrameManagerCompat.dll')]
start=time.monotonic()
try:
    result=subprocess.run(command,capture_output=True,timeout=20)
    report={'exitCode':result.returncode,'stdout':result.stdout.decode('utf8',errors='replace'),'stderr':result.stderr.decode('utf8',errors='replace'),'seconds':time.monotonic()-start,'ownProbeOnly':True,'noFramesCreatedOrDestroyed':True}
except subprocess.TimeoutExpired as error:
    report={'error':'Owned probe terminated at20second deadline','stdout':(error.stdout or b'').decode('utf8',errors='replace'),'seconds':time.monotonic()-start,'ownProbeOnly':True}
(lab/'own-native-manager-test.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(report)
