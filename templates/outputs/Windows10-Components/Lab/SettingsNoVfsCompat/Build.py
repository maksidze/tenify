from pathlib import Path
import subprocess,re,hashlib
H=Path(__file__).resolve().parent;z=H.parents[3]/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe';libs=['-lole32','-lapi-ms-win-core-winrt-l1-1-0','-lapi-ms-win-core-winrt-string-l1-1-0','-lshell32','-luser32','-lbcrypt','-lpsapi']
def build(source,out,dll=False):
 args=[str(z),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17',str(H/source),'-o',str(H/out)]+libs+(['-shared']if dll else['-municode','-Wl,--subsystem,windows'])
 p=subprocess.run(args,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=45);(H/(source+'.build.log')).write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr
build('FactoryFixture.cpp','FactoryFixture.exe');p=H/'SelectorPins.h';s=p.read_text();s=re.sub(r'#define OWN_EXE_SHA ".*?"','#define OWN_EXE_SHA "'+hashlib.sha256((H/'FactoryFixture.exe').read_bytes()).hexdigest()+'"',s);p.write_text(s);build('SettingsFactorySelector.cpp','SettingsFactorySelector.dll',True)
