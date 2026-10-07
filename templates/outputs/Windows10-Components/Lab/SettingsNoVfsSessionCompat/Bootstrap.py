"""Fresh canonical Settings child only, entry-held; no VFS or package mutation."""
from pathlib import Path
import importlib.util,ctypes as C
from ctypes import wintypes as W
LAB=Path(__file__).resolve().parent
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def bootstrap_owned(target,state):
 b=load(LAB/'OwnBootstrap.py','settings_owned').OwnChildBootstrap(target,state['NativePath'])
 b.pause_at_entry(20);b.finish(detach=True,resume_primary=False)
 helper=load(Path(state.get('RouteScript',str(LAB.parent/'SettingsNoVfsCompat/Launch-SettingsNoVfs.py'))),'settings_route')
 report=helper.install_settings_novfs(b)
 check=b.k.CheckRemoteDebuggerPresent;check.restype=W.BOOL;check.argtypes=[C.c_void_p,C.POINTER(W.BOOL)];present=W.BOOL()
 if not check(target.process,C.byref(present)) or present.value:raise RuntimeError('Debugger still attached')
 b.resume_primary();report.update(DebuggerDetached=True,NoVFS=True)
 return report
