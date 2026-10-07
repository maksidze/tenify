#define UNICODE
#define _UNICODE
#define COBJMACROS
#include <windows.h>
#include <shellapi.h>
#include <initguid.h>
#include <shobjidl.h>
#include <stdio.h>
typedef HRESULT(WINAPI*GetClass)(const GUID*,const GUID*,void**);
static HRESULT debug(IPackageDebugSettings**out){HRESULT hr=CoCreateInstance(&CLSID_PackageDebugSettings,NULL,CLSCTX_INPROC_SERVER,&IID_IPackageDebugSettings,(void**)out);if(SUCCEEDED(hr))return hr;HMODULE h=LoadLibraryW(L"twinapi.appcore.dll");GetClass get=h?(GetClass)GetProcAddress(h,"DllGetClassObject"):NULL;if(!get)return hr;IClassFactory*f=NULL;hr=get(&CLSID_PackageDebugSettings,&IID_IClassFactory,(void**)&f);if(SUCCEEDED(hr)){hr=IClassFactory_CreateInstance(f,NULL,&IID_IPackageDebugSettings,(void**)out);IClassFactory_Release(f);}return hr;}
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){(void)a;(void)b;(void)c;(void)d;int n;WCHAR**v=CommandLineToArgvW(GetCommandLineW(),&n);if(!v||n!=5)return 64;FILE*f=_wfopen(v[4],L"wb");if(!f)return 65;HRESULT hr=CoInitializeEx(NULL,COINIT_MULTITHREADED);IPackageDebugSettings*p=NULL;if(SUCCEEDED(hr)){hr=debug(&p);if(SUCCEEDED(hr)){if(!wcscmp(v[1],L"enable"))hr=IPackageDebugSettings_EnableDebugging(p,v[2],v[3],NULL);else if(!wcscmp(v[1],L"disable"))hr=IPackageDebugSettings_DisableDebugging(p,v[2]);else hr=E_INVALIDARG;IPackageDebugSettings_Release(p);}CoUninitialize();}fprintf(f,"%08lx\n",hr);fclose(f);LocalFree(v);return FAILED(hr)?1:0;}
