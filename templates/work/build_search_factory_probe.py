from pathlib import Path
import subprocess,struct
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SearchCompat';lab.mkdir(exist_ok=True)
source=r'''
#include <windows.h>
#include <appmodel.h>
#include <stdio.h>
#include <wchar.h>
typedef void *HSTRING;
typedef HRESULT (WINAPI *GETFACTORY)(HSTRING,void**);
int wmain(int argc,wchar_t **argv){
 if(argc!=3)return 64;
 FILE *log=_wfopen(argv[2],L"wb");if(!log)return 65;
 setvbuf(log,NULL,_IONBF,0);
 wchar_t name[4096]={0};UINT count=4096;
 LONG identity=GetCurrentPackageFullName(&count,name);fprintf(log,"Package=%ld %ls\n",identity,name);
 if(identity||wcsncmp(name,L"MicrosoftWindows.Client.CBS_",27)){fclose(log);return 66;}
 HMODULE combase=LoadLibraryW(L"combase.dll");
 HRESULT(WINAPI *initialize)(int)=(void*)GetProcAddress(combase,"RoInitialize");
 HRESULT(WINAPI *make)(const WCHAR*,UINT32,HSTRING*)=(void*)GetProcAddress(combase,"WindowsCreateString");
 HRESULT(WINAPI *remove)(HSTRING)=(void*)GetProcAddress(combase,"WindowsDeleteString");
 HRESULT hr=initialize(1);fprintf(log,"RoInitialize=%08lx\n",hr);
 HMODULE module=LoadLibraryExW(argv[1],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
 fprintf(log,"LoadOldDLL=%p error=%lu\n",module,GetLastError());
 GETFACTORY factory=module?(void*)GetProcAddress(module,"DllGetActivationFactory"):NULL;
 if(!factory){fclose(log);return 67;}
 const WCHAR *classes[]={L"Cortana.Internal.Search.SearchLaunchOptions",L"Cortana.Internal.Search.WebContentLaunchOptions"};
 for(int i=0;i<2;i++){
  HSTRING text=NULL;make(classes[i],(UINT32)wcslen(classes[i]),&text);void *result=NULL;hr=factory(text,&result);
  fprintf(log,"Factory class=%ls result=%08lx nonNull=%d\n",classes[i],hr,result!=NULL);remove(text);
  if(result){ULONG(WINAPI *release)(void*)=(*(void***)result)[2];release(result);}
 }
 fprintf(log,"No ActivateInstance/Application.Start/COM registration performed.\n");
 fclose(log);return 0;
}
'''
(lab/'SearchFactoryProbe.c').write_text(source)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-municode','-O1',str(lab/'SearchFactoryProbe.c'),'-o',str(lab/'SearchFactoryProbe.exe')],check=True)
# Own test EXE only: suppress console without changing its CRT entrypoint.
file=lab/'SearchFactoryProbe.exe';data=bytearray(file.read_bytes());nt=struct.unpack_from('<I',data,0x3c)[0];struct.pack_into('<H',data,nt+24+68,2);file.write_bytes(data)
print('Built own non-UI factory probe.')
