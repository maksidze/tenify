from pathlib import Path
import subprocess
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SearchCompat'
source=r'''
#include <windows.h>
typedef void *HSTRING;
struct RESULT {DWORD size,done,identity,ro;HRESULT hr[4];DWORD nonnull[4];};
__declspec(dllexport) struct RESULT SearchExeFactoryState={sizeof(struct RESULT)};
__declspec(dllexport) DWORD WINAPI SearchExeFactoryProbe(void *unused){
 (void)unused;HMODULE kernel=GetModuleHandleW(L"kernel32.dll"),combase=LoadLibraryW(L"combase.dll");
 LONG(WINAPI *package)(UINT*,WCHAR*)=(void*)GetProcAddress(kernel,"GetCurrentPackageFullName");
 WCHAR name[4096];UINT n=4096;SearchExeFactoryState.identity=package(&n,name);
 HRESULT(WINAPI *initialize)(int)=(void*)GetProcAddress(combase,"RoInitialize");
 HRESULT(WINAPI *make)(const WCHAR*,UINT32,HSTRING*)=(void*)GetProcAddress(combase,"WindowsCreateString");
 HRESULT(WINAPI *remove)(HSTRING)=(void*)GetProcAddress(combase,"WindowsDeleteString");
 HRESULT(WINAPI *factory)(HSTRING,void**)=(void*)GetProcAddress(GetModuleHandleW(NULL),"DllGetActivationFactory");
 if(!factory)return 0x80004005;
 SearchExeFactoryState.ro=initialize(1);
 const WCHAR *classes[]={L"Cortana.UI.App",L"Cortana.UI.XamlMetadata",L"Cortana.UI.cortanaui_XamlTypeInfo.XamlMetaDataProvider",L"Cortana.UI.Common.BooleanToVisibilityConverter"};
 for(int i=0;i<4;i++){
  HSTRING text=NULL;make(classes[i],(UINT32)lstrlenW(classes[i]),&text);void *result=NULL;
  SearchExeFactoryState.hr[i]=factory(text,&result);SearchExeFactoryState.nonnull[i]=result!=NULL;remove(text);
  if(result){ULONG(WINAPI *release)(void*)=(*(void***)result)[2];release(result);}
 }
 SearchExeFactoryState.done=1;return 0;
}
BOOL WINAPI DllMain(HINSTANCE m,DWORD r,void*p){(void)m;(void)r;(void)p;return TRUE;}
'''
(lab/'SearchExeFactoryProbe.c').write_text(source)
zig=root/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
subprocess.run([str(zig),'cc','-target','x86_64-windows-gnu','-shared','-O1',str(lab/'SearchExeFactoryProbe.c'),'-o',str(lab/'SearchExeFactoryProbe.dll')],check=True)
print('Built own EXE factory-only helper.')
