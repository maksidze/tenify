from pathlib import Path
import subprocess
lab=Path(__file__).resolve().parent;root=lab.parents[3]
p=subprocess.Popen([str(lab/'ItemProbe.exe'),str(lab/'old-direct-provider.log'),str(root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'),'provider'],creationflags=subprocess.CREATE_NO_WINDOW)
try:print('ownproviderexit',p.wait(timeout=20))
except subprocess.TimeoutExpired:p.kill();p.wait();print('timeout')
