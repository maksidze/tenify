from pathlib import Path
import subprocess
root=Path.cwd()
source=(root/'work/ViewDelegateProbe.c').read_text()
start=source.index(' HMODULE ps=')
end=source.index(' hr=get(0,&delegateIID',start)
source=source[:start]+''' HMODULE helper=LoadLibraryW(argv[2]);fprintf(log,"LoadHelper=%p error=%lu\\n",helper,GetLastError());fflush(log);if(!helper)return 3;
 get=(void*)GetProcAddress(helper,"ViewDelegateRoGetAgileReference");if(!get)return 4;
'''+source[end:]
source=source.replace('CoRevokeClassObject(cookie);((ULONG(WINAPI*)(void*))(*(void***)factory)[2])(factory);','')
lab=root/'outputs/Windows10-Components/Lab/ViewDelegateCompat'
(lab/'ViewDelegateHookProbe.c').write_text(source)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1','-g',str(lab/'ViewDelegateHookProbe.c'),'-o',str(lab/'ViewDelegateHookProbe.exe'),'-lole32','-luuid'],check=True)
report=lab/'hook-probe.log'
child=subprocess.Popen([str(lab/'ViewDelegateHookProbe.exe'),str(report),str(lab/'ViewDelegateProxy.dll')],creationflags=subprocess.CREATE_NO_WINDOW)
try:
 code=child.wait(timeout=15)
except subprocess.TimeoutExpired:
 child.kill();child.wait();raise
print(report.read_text())
assert code==0
