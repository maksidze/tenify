"""Prepare own Settings broker artifacts; never register or activate a package."""
from pathlib import Path
import subprocess
import shutil
root=Path(__file__).resolve().parent.parent
base=root/'outputs/Windows10-Components'; lab=base/'Lab/SettingsBrokerCompat'
lab.mkdir(exist_ok=True); (lab/'state').mkdir(exist_ok=True)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
source=(base/'Lab/FlyoutCompat/FlyoutBrokerProbe.c').read_text()
source=source.replace('BrokerFlyoutCompat.ini','BrokerSettingsCompat.ini').replace('FlyoutCompatTest_','SettingsCompatTest_').replace('FlyoutInitialize','SettingsInitialize')
source=source.replace('\\\\SystemApps\\\\ShellExperienceHost_cw5n1h2txyewy\\\\ShellExperienceHost.exe','\\\\ImmersiveControlPanel\\\\SystemSettings.exe')
assert 'ShellExperienceHost.exe' not in source
(lab/'SettingsBrokerProbe.c').write_text(source)
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(lab/'SettingsBrokerProbe.c'),'-o',str(lab/'SettingsBrokerProbe.exe'),'-luser32','-ladvapi32'],check=True)
# Controller is a private copy; parent agent source/binaries are never edited.
controller=(base/'Lab/StartCompat/PackageDebugController.c').read_text()
(lab/'PackageDebugController.c').write_text(controller)
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1',str(lab/'PackageDebugController.c'),'-o',str(lab/'PackageDebugController.exe'),'-lole32','-luuid'],check=True)
bootstrap='''#include <windows.h>
__declspec(dllexport) DWORD WINAPI SettingsInitialize(void *unused) {
 (void)unused; OutputDebugStringW(L"Settings broker entry reached; private VFS installed; no ABI stubs applied."); return 0;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){(void)module;(void)reason;(void)reserved;return TRUE;}
'''
(lab/'SettingsBootstrap.c').write_text(bootstrap)
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O1',str(lab/'SettingsBootstrap.c'),'-o',str(lab/'SettingsBootstrap.dll')],check=True)
print('Prepared private native artifacts. No process activation/debug registration performed.')
