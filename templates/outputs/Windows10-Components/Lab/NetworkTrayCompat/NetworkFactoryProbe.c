#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <oleidl.h>
#include <docobj.h>
#include <shellapi.h>
#include <stdio.h>
static const GUID CLSID_Network={0xc2796011,0x81ba,0x4148,{0x8f,0xca,0xc6,0x64,0x32,0x45,0x11,0x3f}};
static const GUID IID_SSO={0x8e282aae,0xace9,0x4821,{0x83,0xad,0x84,0x9c,0x1d,0x08,0x93,0x9d}};
static DWORD WINAPI deadline(void*x){Sleep(10000);ExitProcess(124);return 0;}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE p,LPWSTR line,int show){
 int argc;wchar_t**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=3)return 2;
 FILE*f=_wfopen(argv[1],L"w");if(!f)return 3;setvbuf(f,NULL,_IONBF,0);HANDLE watchdog=CreateThread(NULL,0,deadline,NULL,0,NULL);CloseHandle(watchdog);
 HRESULT init=CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);fprintf(f,"CoInitializeEx=%08lx console=%p\n",init,GetConsoleWindow());if(FAILED(init))return 4;
 HMODULE dll=LoadLibraryExW(argv[2],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);fprintf(f,"LoadLibrary=%p error=%lu\n",dll,GetLastError());if(!dll)return 5;
 typedef HRESULT(WINAPI*Factory)(REFCLSID,REFIID,void**);Factory get=(Factory)GetProcAddress(dll,"DllGetClassObject");IClassFactory*factory=NULL;HRESULT hr=get?get(&CLSID_Network,&IID_IClassFactory,(void**)&factory):E_FAIL;fprintf(f,"Factory=%08lx ptr=%p\n",hr,factory);
 IUnknown*object=NULL;HRESULT create=factory?IClassFactory_CreateInstance(factory,NULL,&IID_SSO,(void**)&object):E_FAIL;fprintf(f,"CreateExactSSO=%08lx ptr=%p\n",create,object);
 if(factory)IClassFactory_Release(factory);
 if(object){IOleCommandTarget*ole=NULL;HRESULT qi=IUnknown_QueryInterface(object,&IID_IOleCommandTarget,(void**)&ole);fprintf(f,"QI_IOleCommandTarget=%08lx ptr=%p\n",qi,ole);if(ole)IOleCommandTarget_Release(ole);void**v=*(void***)object;for(int i=0;i<6;i++)fprintf(f,"SSOSlot%d=%llx\n",i,(unsigned long long)((BYTE*)v[i]-(BYTE*)dll));IUnknown_Release(object);fprintf(f,"ObjectReleased; Start/Stop not called\n");}
 FreeLibrary(dll);CoUninitialize();fclose(f);LocalFree(argv);return FAILED(create)?6:0;
}

