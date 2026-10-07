from pathlib import Path
import sys,os,json,subprocess,ctypes
root=Path(__file__).resolve().parents[1];lab=root/'outputs/Windows10-Components/Lab/BrokerGuiEntry'
if '--controller' in sys.argv:
 ctypes.windll.kernel32.GetConsoleWindow.restype=ctypes.c_void_p
 parent_console=ctypes.windll.kernel32.GetConsoleWindow()
 exe=lab/'GuiArgvFixture.exe';log=lab/'gui-argv-fixture.log'
 args=[str(exe),str(log),'аргумент с пробелами','quote"inside','C:'+chr(92)+'endslash'+chr(92),'-p','1234','-tid','5678','--config','INI с пробелом.ini']
 # Default CreateProcess flags intentionally: no CREATE_NO_WINDOW for the GUI child.
 p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0)
 out,err=p.communicate(timeout=10);text=log.read_text(encoding='utf-8-sig');lines=dict(x.split('=',1) for x in text.splitlines());assert p.returncode==42
 assert not parent_console and int(lines['CONSOLE'],16)==0
 assert int(lines['ARGC'])==len(args)
 for i,a in enumerate(args):assert lines['ARG'+str(i)]==a,(i,lines['ARG'+str(i)],a)
 report=dict(controllerPid=os.getpid(),controllerConsole=parent_console,guiChildPid=p.pid,guiChildCreationFlags=0,guiChildConsole=lines['CONSOLE'],argc=len(args),allArgumentsRoundTrip=True,exitCode=p.returncode,stdout=out.decode(errors='replace'),stderr=err.decode(errors='replace'),packageActivationPerformed=False)
 (lab/'gui-argv-fixture-proof.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report));raise SystemExit(0)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(zig),'cc','-target','x86_64-windows-gnu','-municode','-mwindows','-Wl,--subsystem,windows','-Dwmain=BrokerExistingWmain','-O1','-g',str(lab/'GuiArgvFixture.c'),str(lab/'BrokerGuiEntry.c'),'-o',str(lab/'GuiArgvFixture.exe'),'-lshell32','-luser32']
r=subprocess.run(cmd,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW,env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(root/'work/compat-research/zig-cache')),timeout=90)
if r.returncode:raise RuntimeError(r.stderr)
sys.path.insert(0,str(root/'work/pylib'));import pefile
assert pefile.PE(str(lab/'GuiArgvFixture.exe')).OPTIONAL_HEADER.Subsystem==2
r=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--controller'],capture_output=True,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW,timeout=15,env=dict(os.environ,PYTHONIOENCODING='utf8'))
if r.returncode:raise RuntimeError(r.stdout+r.stderr)
print(r.stdout)
