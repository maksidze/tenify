from pathlib import Path
import subprocess,json,sys,hashlib
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile
native=Path('C:/Windows/System32/Windows.UI.Xaml.dll');image=pefile.PE(str(native))
base=root/'outputs/Windows10-Components';lab=base/'Lab/XamlQuirkCompat';lab.mkdir(exist_ok=True)
signature=image.get_data(0x39eb50,24)
helper='''
static BOOL adaptIslandQuirk(void){
 HMODULE module=GetModuleHandleW(L"Windows.UI.Xaml.dll");
 if(!module){puts("QUIRK no native XAML module");return FALSE;}
 BYTE *base=(BYTE*)module; BYTE signature[]={SIGNATURE};
 if(memcmp(base+0x39eb50,signature,sizeof(signature))){puts("QUIRK function version mismatch");return FALSE;}
 typedef BYTE (*BLOCK)(void); /* Native C++ bool result is AL, not full EAX. */
 BOOL before=((BLOCK)(base+0x39eb50))();
 BYTE *cache=*(BYTE**)(base+0xfcb8d0);
 if(cache!=base+0xfcd720 || *(LONG*)(base+0xfcb8dc)!=0){puts("QUIRK cache/suppressions unsupported");return FALSE;}
 BYTE snapshot[8];memcpy(snapshot,cache,8);
 InterlockedAnd((volatile LONG*)(cache+4),~4L);
 BOOL after=((BLOCK)(base+0x39eb50))();
 printf("QUIRK before=%d after=%d bytesBefore=",before,after);for(int i=0;i<8;i++)printf("%02x",snapshot[i]);
 printf(" bytesAfter=");for(int i=0;i<8;i++)printf("%02x",cache[i]);puts("");fflush(stdout);
 snapshot[4]&=~4;
 return !after && !memcmp(snapshot,cache,8);
}
'''.replace('SIGNATURE',','.join('0x%02x'%b for b in signature))
source=(root/'work/xaml_manifest_probe.c').read_text()
source=source.replace('int main(int argc,char**argv){',helper+'\nint main(int argc,char**argv){')
source=source.replace('if(argc>2 && strcmp(argv[1],"package")){','if(argc>2 && strcmp(argv[1],"package") && strcmp(argv[1],"quirk")){')
source=source.replace('if(SUCCEEDED(hr) && factory){','if(argc>1 && !strcmp(argv[1],"quirk") && !adaptIslandQuirk())return 70;\n if(SUCCEEDED(hr) && factory){')
(lab/'XamlQuirkProbe.c').write_text(source)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-O1',str(lab/'XamlQuirkProbe.c'),'-o',str(lab/'XamlQuirkProbe.exe')],check=True)
results={}
for mode in ['baseline','quirk']:
    command=[str(lab/'XamlQuirkProbe.exe')]+(['quirk'] if mode=='quirk' else [])
    result=subprocess.run(command,capture_output=True,timeout=30)
    results[mode]={'exitCode':result.returncode,'stdout':result.stdout.decode('utf8',errors='replace'),'stderr':result.stderr.decode('utf8',errors='replace')}
    print(mode,results[mode])
results['nativeModule']={'path':str(native),'sha256':hashlib.sha256(native.read_bytes()).hexdigest(),'checkRVA':'0x39eb50','checkBytes':signature.hex()}
(lab/'own-child-quirk-probe.json').write_text(json.dumps(results,indent=2),encoding='utf8')
