from pathlib import Path
import subprocess,json
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/XamlQuirkCompat'
source=(lab/'XamlQuirkProbe.c').read_text()
start=source.index('static BOOL adaptIslandQuirk(void)')
end=source.index('int main(',start)
path=str(lab/'XamlQuirkCompat.dll').replace('\\','\\\\')
helper='''static BOOL restoreMode;
static BOOL adaptIslandQuirk(void){
 HMODULE module=LoadLibraryW(L"PATH");
 DWORD (WINAPI *initialize)(void*)=module?(void*)GetProcAddress(module,"XamlQuirkInitialize"):NULL;
 DWORD result=initialize?initialize(NULL):0xffffffff;
 printf("DLL Initialize=%08lx\\n",result);
 if(restoreMode&&result==0){DWORD (WINAPI *restore)(void*)=(void*)GetProcAddress(module,"XamlQuirkRestore");DWORD rollback=restore?restore(NULL):0xffffffff;printf("DLL Restore=%08lx\\n",rollback);if(rollback)return FALSE;}
 return result==0;
}
'''.replace('PATH',path)
source=source[:start]+helper+source[end:]
source=source.replace('int main(int argc,char**argv){','int main(int argc,char**argv){restoreMode=argc>2 && !strcmp(argv[2],"restore");')
(lab/'XamlQuirkAdapterProbe.c').write_text(source)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-O1',str(lab/'XamlQuirkAdapterProbe.c'),'-o',str(lab/'XamlQuirkAdapterProbe.exe')],check=True)
test=subprocess.run([str(lab/'XamlQuirkAdapterProbe.exe'),'quirk'],capture_output=True,timeout=30)
result={'exitCode':test.returncode,'stdout':test.stdout.decode('utf8',errors='replace'),'stderr':test.stderr.decode('utf8',errors='replace'),'ownNonShellChild':True,'packageIdentity':'none'}
(lab/'own-child-dll-adapter-probe.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(result)
assert test.returncode==0 and b'Initialize=00000000 nonNull=1' in test.stdout
rollback=subprocess.run([str(lab/'XamlQuirkAdapterProbe.exe'),'quirk','restore'],capture_output=True,timeout=30)
result={'exitCode':rollback.returncode,'stdout':rollback.stdout.decode('utf8',errors='replace'),'stderr':rollback.stderr.decode('utf8',errors='replace'),'ownNonShellChild':True,'packageIdentity':'none'}
(lab/'own-child-rollback-probe.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(result)
assert rollback.returncode==0 and b'DLL Restore=00000000' in rollback.stdout and b'Initialize=8000ffff nonNull=0' in rollback.stdout
