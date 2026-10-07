#define UNICODE
#define _UNICODE
#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <shobjidl.h>
#include <stdio.h>
#include <wchar.h>
typedef HRESULT (WINAPI *GETCLASS)(const GUID*,const GUID*,void**);
static HRESULT getDebug(IPackageDebugSettings **out){
 HRESULT hr=CoCreateInstance(&CLSID_PackageDebugSettings,NULL,CLSCTX_INPROC_SERVER,&IID_IPackageDebugSettings,(void**)out);
 if(SUCCEEDED(hr))return hr;
 HMODULE dll=LoadLibraryW(L"twinapi.appcore.dll");GETCLASS get=dll?(GETCLASS)GetProcAddress(dll,"DllGetClassObject"):NULL;if(!get)return hr;
 IClassFactory *factory=NULL;hr=get(&CLSID_PackageDebugSettings,&IID_IClassFactory,(void**)&factory);if(SUCCEEDED(hr)){hr=IClassFactory_CreateInstance(factory,NULL,&IID_IPackageDebugSettings,(void**)out);IClassFactory_Release(factory);}return hr;
}
int wmain(int argc,wchar_t **argv){
 if(argc<3)return 64;setvbuf(stdout,NULL,_IONBF,0);printf("Mode=%ls Package=%ls argc=%d\n",argv[1],argv[2],argc);if(!wcscmp(argv[1],L"enable")&&argc>3)printf("Debugger=%ls\n",argv[3]);HRESULT hr=CoInitializeEx(NULL,COINIT_MULTITHREADED);if(FAILED(hr))return 1;
 if(!wcscmp(argv[1],L"activate")){IApplicationActivationManager *manager=NULL;DWORD pid=0;hr=CoCreateInstance(&CLSID_ApplicationActivationManager,NULL,CLSCTX_LOCAL_SERVER,&IID_IApplicationActivationManager,(void**)&manager);if(SUCCEEDED(hr)){hr=IApplicationActivationManager_ActivateApplication(manager,argv[2],argc>3?argv[3]:L"",AO_NOERRORUI,&pid);IApplicationActivationManager_Release(manager);}printf("ActivateApplication=%08lx pid=%lu\n",hr,pid);CoUninitialize();return FAILED(hr)?2:0;}
 IPackageDebugSettings *debug=NULL;hr=getDebug(&debug);printf("PackageDebugSettings=%08lx\n",hr);if(FAILED(hr)){CoUninitialize();return 3;}
 if(!wcscmp(argv[1],L"disable")){hr=IPackageDebugSettings_DisableDebugging(debug,argv[2]);printf("DisableDebugging=%08lx\n",hr);}
 else if(!wcscmp(argv[1],L"status")){PACKAGE_EXECUTION_STATE state=0;hr=IPackageDebugSettings_GetPackageExecutionState(debug,argv[2],&state);printf("ExecutionState=%08lx state=%d\n",hr,state);}
 else if(!wcscmp(argv[1],L"enable")&&argc>5){hr=IPackageDebugSettings_EnableDebugging(debug,argv[2],!wcscmp(argv[3],L"--null")?NULL:argv[3],NULL);printf("EnableDebugging=%08lx\n",hr);if(SUCCEEDED(hr)){wchar_t enabled[32768];swprintf(enabled,32768,L"%ls.enabled",argv[5]);HANDLE file=CreateFileW(enabled,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,0,NULL);if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);ULONGLONG deadline=GetTickCount64()+1000ULL*wcstoul(argv[4],NULL,10);while(GetTickCount64()<deadline&&GetFileAttributesW(argv[5])==INVALID_FILE_ATTRIBUTES)Sleep(200);hr=IPackageDebugSettings_DisableDebugging(debug,argv[2]);printf("DisableDebugging=%08lx\n",hr);}}
 else hr=E_INVALIDARG;
 IPackageDebugSettings_Release(debug);CoUninitialize();return FAILED(hr)?4:0;
}

