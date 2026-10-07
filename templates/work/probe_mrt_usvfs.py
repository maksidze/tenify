from pathlib import Path
import sys
controller=Path('outputs/Windows10-Components/Probe-USVFS.py').resolve()
source=controller.read_text(encoding='utf-8-sig').split('\ntry:\n params=')[0]
sys.argv=[str(controller),'--preset','selftest']
namespace={'__file__':str(controller)}
exec(source,namespace)
globals().update(namespace)
params=None;connected=False;pi=PI()
try:
 params=parametersCreate();setName(params,('CodexMrt_'+uuid.uuid4().hex).encode());setDebug(params,False);setLog(params,1)
 if not connect(params):raise C.WinError(C.get_last_error())
 connected=True
 exe=Path('work/Mrt-Host/MrtProbe.exe').resolve();target=exe.parent/'resources.pri';src=image/'SystemResources/Windows.UI.ShellCommon/Windows.UI.ShellCommon.pri'
 mapFile(src,target)
 resultFile=Path('work/mrt-usvfs-local-result.txt').resolve()
 si=SI();si.cb=C.sizeof(si);si.flags=1;si.show=0
 if not create(str(exe),C.create_unicode_buffer(subprocess.list2cmdline([str(exe),str(resultFile)])),None,None,False,0,None,str(exe.parent),C.byref(si),C.byref(pi)):raise C.WinError(C.get_last_error())
 if wait(pi.process,10000)!=0:term(pi.process,1);raise RuntimeError('MRT child timeout')
 print(resultFile.read_text())
finally:
 if pi.thread:close(pi.thread)
 if pi.process:close(pi.process)
 if connected:disconnect()
 if params:parametersFree(params)
