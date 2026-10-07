#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <stdint.h>
typedef void *W10_HSTRING;
typedef HRESULT (WINAPI *PFN_CREATE_HSTRING)(const wchar_t *,UINT,W10_HSTRING *);
typedef HRESULT (WINAPI *PDEL)(W10_HSTRING);
typedef HRESULT (WINAPI *PRO)(UINT);
typedef HRESULT (WINAPI *PROFACT)(W10_HSTRING,const GUID*,void**);
typedef HRESULT (WINAPI *PGETFACT)(W10_HSTRING,void**);
typedef HRESULT (WINAPI *PPROXYFACT)(const wchar_t*,const GUID*,void**);
typedef HRESULT (WINAPI *PQI)(void*,const GUID*,void**);
typedef ULONG (WINAPI *PRELEASE)(void*);
typedef HRESULT (WINAPI *PGET)(void*,void**);
typedef HRESULT (WINAPI *PLOAD)(void*,const wchar_t*);
typedef HRESULT (WINAPI *PGETMAP)(void*,const wchar_t*,const GUID*,void**);
typedef HRESULT (WINAPI *PGETSUB)(void*,const wchar_t*,void**);
typedef HRESULT (WINAPI *PGETIIDS)(void*,ULONG*,GUID**);
typedef const wchar_t* (WINAPI *PSTRRAW)(W10_HSTRING,UINT*);
static FILE *logFile;
static BOOL inspectResourceValues;
static PFN_CREATE_HSTRING createString;
static PDEL deleteString;
static PROFACT roFactory;
static const GUID giApp={0x1ecdc9e0,0xbdb1,0x3551,{0x8c,0xee,0x4b,0x77,0x54,0x0c,0x44,0xb3}};
static const GUID giDockedApp={0x4c2caead,0x9da8,0x30ec,{0xb6,0xd3,0xcb,0xd5,0x74,0xed,0xcb,0x35}};
static const GUID giMetadata={0xf2777c41,0xd2cc,0x34b6,{0xa7,0xea,0x19,0xf6,0xc6,0x5f,0x0c,0x19}};
static const GUID giActivationFactory={0x00000035,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const GUID giResources={0x4a8eac58,0xb652,0x459d,{0x8d,0xe1,0x23,0x94,0x71,0xe8,0xb2,0x2b}};
static const GUID giResourceExt2={0x8c25e859,0x1042,0x4da0,{0x92,0x32,0xbf,0x2a,0xa8,0xff,0x37,0x26}};
static const GUID giResourceExt={0xc408a1f1,0x3ede,0x41e9,{0x9a,0x38,0xc2,0x03,0x67,0x8c,0x2d,0xf7}};
static const GUID giMrt={0x130a2f65,0x2be7,0x4309,{0x9a,0x58,0xa9,0x05,0x2f,0xf2,0xb6,0x1c}};
static const GUID giMap={0x6e21e72b,0xb9b0,0x42ae,{0xa6,0x86,0x98,0x3c,0xf7,0x84,0xed,0xcd}};
static void logline(const char *format,...) {
 va_list args;va_start(args,format);vfprintf(logFile,format,args);va_end(args);fputc('\n',logFile);fflush(logFile);
}
static void *slot(void *p,int n){return (*(void***)p)[n];}
static void release(void *p){if(p)((PRELEASE)slot(p,2))(p);}
static HRESULT query(void *p,const GUID *g,void **out){*out=NULL;return ((PQI)slot(p,0))(p,g,out);}
static void inspectInstance(void *p){
 ULONG count=0;GUID *ids=NULL;HRESULT hr=((PGETIIDS)slot(p,3))(p,&count,&ids);logline("Instance.GetIids=%08lx count=%lu",hr,count);
 if(SUCCEEDED(hr)&&ids){for(ULONG i=0;i<count&&i<30;i++)logline("Instance.IID=%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",ids[i].Data1,ids[i].Data2,ids[i].Data3,ids[i].Data4[0],ids[i].Data4[1],ids[i].Data4[2],ids[i].Data4[3],ids[i].Data4[4],ids[i].Data4[5],ids[i].Data4[6],ids[i].Data4[7]);typedef void(WINAPI *PFREE)(void*);((PFREE)GetProcAddress(GetModuleHandleW(L"combase.dll"),"CoTaskMemFree"))(ids);}
 W10_HSTRING name=NULL;hr=((PGET)slot(p,4))(p,&name);if(SUCCEEDED(hr)){PSTRRAW raw=(PSTRRAW)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");logline("Instance.Class=%ls",raw(name,NULL));deleteString(name);}
 MEMORY_BASIC_INFORMATION memory={0};if(VirtualQuery(slot(p,0),&memory,sizeof(memory))){wchar_t module[32768];GetModuleFileNameW((HMODULE)memory.AllocationBase,module,32768);logline("Instance.QIModule=%ls",module);}
}
static LONG WINAPI unhandled(EXCEPTION_POINTERS *e){logline("UNHANDLED_EXCEPTION=%08lx address=%p",e->ExceptionRecord->ExceptionCode,e->ExceptionRecord->ExceptionAddress);return EXCEPTION_EXECUTE_HANDLER;}
static HRESULT resourceProbe(const wchar_t *pri){
 W10_HSTRING s=NULL;void *factory=NULL,*manager=NULL,*ext=NULL,*internal=NULL,*mrt=NULL,*map=NULL,*sub=NULL;HRESULT hr;
 const wchar_t *name=L"Windows.ApplicationModel.Resources.Core.ResourceManager";
 hr=createString(name,(UINT)wcslen(name),&s);if(FAILED(hr))return hr;
 hr=roFactory(s,&giResources,&factory);deleteString(s);logline("ResourceManager.Factory=%08lx",hr);if(FAILED(hr))return hr;
 hr=((PGET)slot(factory,7))(factory,&manager);logline("ResourceManager.CurrentSystemProfile=%08lx",hr);if(FAILED(hr))goto end;
 if(pri && *pri){
  hr=query(manager,&giResourceExt2,&ext);logline("ResourceManager.Extensions2=%08lx",hr);if(FAILED(hr))goto end;
  hr=((PLOAD)slot(ext,6))(ext,pri);logline("ResourceManager.LoadPriFileForSystemUse=%08lx",hr);release(ext);ext=NULL;if(FAILED(hr))goto end;
 }
 hr=query(manager,&giResourceExt,&ext);logline("ResourceManager.Extensions=%08lx",hr);if(FAILED(hr))goto end;
 hr=((PGET)slot(ext,7))(ext,&internal);logline("ResourceManager.GetMrt=%08lx",hr);if(FAILED(hr))goto end;
 hr=query(internal,&giMrt,&mrt);logline("ResourceManager.MrtQI=%08lx",hr);if(FAILED(hr))goto end;
 hr=((PGETMAP)slot(mrt,8))(mrt,L"Windows.UI.ShellCommon",&giMap,&map);logline("ResourceManager.ShellCommonMap=%08lx",hr);if(FAILED(hr))goto end;
 hr=((PGETSUB)slot(map,4))(map,L"StartUI",&sub);logline("ResourceManager.StartUISubtree=%08lx",hr);
 if(inspectResourceValues){
  typedef HRESULT(WINAPI *LOOKUP)(void*,W10_HSTRING,void**);void *maps=NULL,*publicMap=NULL;W10_HSTRING key=NULL;HRESULT vhr=((PGET)slot(manager,7))(manager,&maps);logline("Resources.AllMaps=%08lx ptr=%p",vhr,maps);
  if(maps){createString(L"Windows.UI.ShellCommon",22,&key);vhr=((LOOKUP)slot(maps,6))(maps,key,&publicMap);deleteString(key);logline("Resources.ShellCommonPublicMap=%08lx ptr=%p",vhr,publicMap);}
  if(publicMap){const GUID mapId={0x72284824,0xdb8c,0x42f8,{0xb0,0x8c,0x53,0xff,0x35,0x7d,0xad,0x82}};void *typed=NULL;HRESULT qhr=query(publicMap,&mapId,&typed);logline("Resources.PublicMapQI=%08lx ptr=%p",qhr,typed);release(publicMap);publicMap=typed;}
  if(publicMap){const wchar_t *keys[]={L"StartUI/TileGridView.xaml",L"Files/StartUI/TileGridView.xaml",L"StartUI/TileGridView.xbf",L"Files/StartUI/TileGridView.xbf"};
   for(unsigned i=0;i<4;i++){void *candidate=NULL;createString(keys[i],(UINT)wcslen(keys[i]),&key);vhr=((LOOKUP)slot(publicMap,7))(publicMap,key,&candidate);deleteString(key);logline("Resources.Value %ls=%08lx ptr=%p",keys[i],vhr,candidate);if(candidate){W10_HSTRING value=NULL;HRESULT chr=((PGET)slot(candidate,10))(candidate,&value);if(value){PSTRRAW raw=(PSTRRAW)GetProcAddress(GetModuleHandleW(L"combase.dll"),"WindowsGetStringRawBuffer");logline("Resources.Candidate=%08lx %.200ls",chr,raw(value,NULL));deleteString(value);}release(candidate);}}
  }release(publicMap);release(maps);
 }
end:release(sub);release(map);release(mrt);release(internal);release(ext);release(manager);release(factory);return hr;
}
static HRESULT testFactory(PGETFACT get,const wchar_t *name,const GUID *iid,BOOL activate){
 W10_HSTRING s=NULL;void *factory=NULL,*typed=NULL,*instance=NULL;HRESULT hr;
 hr=createString(name,(UINT)wcslen(name),&s);if(FAILED(hr))return hr;
 logline("FactoryRequest=%ls",name);hr=get(s,&factory);deleteString(s);logline("DllGetActivationFactory=%08lx ptr=%p",hr,factory);if(FAILED(hr))return hr;
 hr=query(factory,iid,&typed);logline("Factory.TypedQI=%08lx ptr=%p",hr,typed);release(typed);
 if(activate){HRESULT instanceHR=((PGET)slot(factory,6))(factory,&instance);logline("Factory.ActivateInstance=%08lx ptr=%p",instanceHR,instance);if(SUCCEEDED(instanceHR)){void *metadata=NULL;HRESULT mh=query(instance,&giMetadata,&metadata);logline("Instance.MetadataClassQI=%08lx ptr=%p",mh,metadata);release(metadata);}release(instance);}
 release(factory);return hr;
}
static HRESULT globalPropertiesProbe(void){
 const GUID userStatics={0x74a37e11,0x2eb5,0x4487,{0xb0,0xd5,0x2c,0x67,0x90,0xe0,0x13,0xe9}};
 const GUID propertiesFactory={0x2c670963,0xf8a9,0x4bbb,{0x9a,0xdf,0x68,0x3a,0x3a,0x89,0x53,0x7e}};
 const GUID propertiesId={0xee807266,0xa2db,0x4c9a,{0xa1,0xb4,0x97,0x0d,0x33,0xf9,0x9c,0x91}};
 const GUID oldPropertiesId={0xc6da4ccf,0xcc4c,0x410e,{0x99,0x23,0x0a,0x10,0xba,0xf1,0x46,0xb2}};
 typedef HRESULT(WINAPI *CREATE)(void*,void*,void**);void *users=NULL,*user=NULL,*factory=NULL,*object=NULL,*typed=NULL;W10_HSTRING name=NULL;
 createString(L"Windows.System.User",19,&name);HRESULT hr=roFactory(name,&userStatics,&users);deleteString(name);logline("User.Statics2=%08lx ptr=%p",hr,users);
 if(users){hr=((PGET)slot(users,6))(users,&user);logline("User.GetDefault=%08lx ptr=%p",hr,user);if(user)inspectInstance(user);}
 const wchar_t *className=L"WindowsInternal.Shell.CDSProperties.StartGlobalProperties";createString(className,(UINT)wcslen(className),&name);hr=roFactory(name,&propertiesFactory,&factory);deleteString(name);logline("StartGlobalProperties.Factory=%08lx ptr=%p",hr,factory);
 if(factory){hr=((CREATE)slot(factory,6))(factory,user,&object);logline("StartGlobalProperties.Create=%08lx ptr=%p user=%p",hr,object,user);if(object){inspectInstance(object);hr=query(object,&propertiesId,&typed);logline("StartGlobalProperties.TypedQI=%08lx ptr=%p",hr,typed);if(typed){BYTE full=255;typedef HRESULT(WINAPI *GETBOOL)(void*,BYTE*);hr=((GETBOOL)slot(typed,6))(typed,&full);logline("StartGlobalProperties.FullScreenMode=%08lx value=%u",hr,full);}}}
 if(object){void *old=NULL;HRESULT legacy=query(object,&oldPropertiesId,&old);logline("StartGlobalProperties.OldTypedQI=%08lx ptr=%p",legacy,old);release(old);}
 {
  const GUID batchedFactory={0x3055f2cd,0xa89f,0x43f3,{0xbe,0x60,0x86,0x7e,0x26,0x44,0xb2,0x83}};void *bf=NULL,*bo=NULL;const wchar_t *bn=L"WindowsInternal.Shell.CDSProperties.CDSTilePropertiesBatched";
  createString(bn,(UINT)wcslen(bn),&name);HRESULT bh=roFactory(name,&batchedFactory,&bf);deleteString(name);logline("Batched.Factory=%08lx ptr=%p",bh,bf);
  if(bf){typedef HRESULT(WINAPI *BATCH)(void*,void*,DWORD,void**);bh=((BATCH)slot(bf,6))(bf,user,7,&bo);logline("Batched.Create=%08lx ptr=%p",bh,bo);if(bo){inspectInstance(bo);const GUID oldId={0xd08a9559,0xb4cc,0x49af,{0x98,0xbb,0x23,0x66,0xc7,0x44,0x94,0x02}};void *old=NULL;HRESULT oldHr=query(bo,&oldId,&old);logline("Batched.OldQI=%08lx ptr=%p",oldHr,old);if(old){void *items=NULL;oldHr=((PGET)slot(old,14))(old,&items);logline("Batched.OldSlot14.GetAllLocalVolatile=%08lx ptr=%p",oldHr,items);release(items);release(old);}}release(bo);release(bf);}
 }
 release(typed);release(object);release(factory);release(user);release(users);return hr;
}
int wmain(int argc,wchar_t **argv){
 if(argc<3)return 64;
 logFile=_wfopen(argv[1],L"wb");if(!logFile)return 65;
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);SetUnhandledExceptionFilter(unhandled);
 logline("StartCompatProbe PID=%lu pointerSize=%u",GetCurrentProcessId(),(unsigned)sizeof(void*));
 typedef LONG(WINAPI* PPACKAGE)(UINT*,wchar_t*);PPACKAGE package=(PPACKAGE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetCurrentPackageFullName");
 UINT size=0;LONG pkg=package?package(&size,NULL):-1;logline("GetCurrentPackageFullName=%ld requiredLength=%u",pkg,size);
 if(pkg==ERROR_INSUFFICIENT_BUFFER){wchar_t *text=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size*sizeof(wchar_t));if(text){pkg=package(&size,text);logline("Package=%ls hr=%ld",text,pkg);HeapFree(GetProcessHeap(),0,text);}}
 HMODULE combase=LoadLibraryW(L"combase.dll");PRO initialize=(PRO)GetProcAddress(combase,"RoInitialize");
 createString=(PFN_CREATE_HSTRING)GetProcAddress(combase,"WindowsCreateString");deleteString=(PDEL)GetProcAddress(combase,"WindowsDeleteString");roFactory=(PROFACT)GetProcAddress(combase,"RoGetActivationFactory");
 HRESULT hr=initialize(0);logline("RoInitializeSTA=%08lx",hr);if(FAILED(hr))return 1;
 if(argc>3&&!wcscmp(argv[2],L"--inspect-factory")){W10_HSTRING name=NULL;void *factory=NULL;createString(argv[3],(UINT)wcslen(argv[3]),&name);hr=roFactory(name,&giActivationFactory,&factory);deleteString(name);logline("InspectFactory=%ls hr=%08lx ptr=%p",argv[3],hr,factory);if(factory){inspectInstance(factory);release(factory);}logline("SUMMARY inspectFactory=%08lx",hr);fclose(logFile);return FAILED(hr)?5:0;}
 if(!wcscmp(argv[2],L"--global-properties")){hr=globalPropertiesProbe();logline("SUMMARY globalProperties=%08lx",hr);fclose(logFile);return FAILED(hr)?5:0;}
 inspectResourceValues=argc>4&&!wcscmp(argv[4],L"--resource-values");HRESULT resources=resourceProbe(argc>3?argv[3]:NULL);logline("ResourceProbe.Result=%08lx",resources);
 if(inspectResourceValues){logline("SUMMARY resourceValues=%08lx",resources);fclose(logFile);return FAILED(resources)?5:0;}
 HMODULE ui=LoadLibraryExW(argv[2],NULL,LOAD_WITH_ALTERED_SEARCH_PATH);logline("LoadStartUI=%p lastError=%lu",ui,GetLastError());if(!ui)return 2;
 PGETFACT get=(PGETFACT)GetProcAddress(ui,"DllGetActivationFactory");if(!get){
  PPROXYFACT proxy=(PPROXYFACT)GetProcAddress(ui,"StartCompatGetFactory");if(!proxy){logline("GetProcAddress.DllGetActivationFactory=%lu",GetLastError());return 3;}
  if(argc>4&&!wcscmp(argv[4],L"--batched-compat")){void *metadata=NULL;HRESULT bhr=proxy(L"StartUI.startui_XamlTypeInfo.XamlMetaDataProvider",&giActivationFactory,&metadata);release(metadata);logline("Batched.LoadProxy=%08lx",bhr);if(SUCCEEDED(bhr))bhr=globalPropertiesProbe();logline("SUMMARY batchedCompat=%08lx",bhr);fclose(logFile);return FAILED(bhr)?5:0;}
  if(argc>4&&!wcscmp(argv[4],L"--theme-compat")){
   const GUID oldTheme={0xc5f80e59,0xa9fc,0x439d,{0x9f,0xc4,0xd2,0x90,0x85,0x8e,0x18,0x67}};void *theme=NULL;HRESULT thr=proxy(L"ApplicationTheme.AppThemeAPI",&oldTheme,&theme);logline("Theme.OldFactory=%08lx ptr=%p",thr,theme);
   if(theme){BYTE value=255;typedef HRESULT(WINAPI *GETBOOL)(void*,BYTE*);thr=((GETBOOL)slot(theme,12))(theme,&value);logline("Theme.AdvancedEffects=%08lx value=%u",thr,value);DWORD color=0;typedef HRESULT(WINAPI *COLOR)(void*,DWORD,DWORD*);thr=((COLOR)slot(theme,9))(theme,0,&color);logline("Theme.GetThemeColor=%08lx color=%08lx",thr,color);release(theme);}logline("SUMMARY themeCompat=%08lx",thr);fclose(logFile);return FAILED(thr)?5:0;
  }
  if(argc>5 && !wcscmp(argv[4],L"--activate-class")){
   void *factory=NULL,*object=NULL;HRESULT chr=proxy(argv[5],&giActivationFactory,&factory);logline("CustomClass=%ls Factory=%08lx ptr=%p",argv[5],chr,factory);if(factory){inspectInstance(factory);chr=((PGET)slot(factory,6))(factory,&object);logline("CustomClass.ActivateInstance=%08lx ptr=%p",chr,object);if(object)inspectInstance(object);release(object);release(factory);}logline("SUMMARY customClass=%08lx",chr);fclose(logFile);return FAILED(chr)?4:0;
  }
  void *app=NULL,*metadata=NULL,*instance=NULL;HRESULT appHR=proxy(L"StartDocked.App",&giDockedApp,&app);logline("Proxy.StartDockedToStartUI.App=%08lx ptr=%p",appHR,app);release(app);
  HRESULT metaHR=proxy(L"StartDocked.startdocked_XamlTypeInfo.XamlMetaDataProvider",&giActivationFactory,&metadata);logline("Proxy.StartDockedToStartUI.Metadata=%08lx ptr=%p",metaHR,metadata);
  if(SUCCEEDED(metaHR)){HRESULT ahr=((PGET)slot(metadata,6))(metadata,&instance);logline("Proxy.Metadata.ActivateInstance=%08lx ptr=%p",ahr,instance);if(instance){inspectInstance(instance);void *m=NULL;HRESULT qhr=query(instance,&giMetadata,&m);logline("Proxy.Metadata.InstanceQI=%08lx ptr=%p",qhr,m);release(m);}release(instance);release(metadata);}
  logline("SUMMARY proxyApp=%08lx proxyMetadata=%08lx resources=%08lx",appHR,metaHR,resources);fclose(logFile);return FAILED(appHR)||FAILED(metaHR)?4:0;
 }
 HRESULT app=testFactory(get,L"StartUI.App",&giApp,FALSE);
 HRESULT meta=testFactory(get,L"StartUI.startui_XamlTypeInfo.XamlMetaDataProvider",&giActivationFactory,argc>4&&!wcscmp(argv[4],L"--activate-metadata"));
 logline("SUMMARY app=%08lx metadata=%08lx resources=%08lx",app,meta,resources);fclose(logFile);
 return FAILED(app)||FAILED(meta)?4:0;
}
