"""Compile finalized independent Flyout sources without reimporting Start."""
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/FlyoutCompat'
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
for name in ['FlyoutBrokerProbe','FlyoutProxyHarness']:
    subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(lab/(name+'.c')),'-o',str(lab/(name+'.exe')),'-luser32','-ladvapi32'],check=True)
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O1','-g',str(lab/'FlyoutBootstrap.c'),'-o',str(lab/'FlyoutBootstrap.dll')],check=True)
print('Compiled finalized sources; no package/debug/registry/process changes')