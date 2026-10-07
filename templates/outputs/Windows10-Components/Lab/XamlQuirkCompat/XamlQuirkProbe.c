#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>
typedef void* HSTRING;
static HRESULT (WINAPI *RoInitialize)(int);
static HRESULT (WINAPI *RoGetActivationFactory)(HSTRING,REFIID,void**);
static HRESULT (WINAPI *WindowsCreateString)(const WCHAR*,UINT32,HSTRING*);
static HRESULT (WINAPI *WindowsDeleteString)(HSTRING);
static const GUID statics={0x28258a12,0x7d82,0x505b,{0xb2,0x10,0x71,0x2b,0x04,0xa5,0x88,0x82}};
typedef HRESULT(WINAPI *InitializeFn)(void*,void**);

static BOOL adaptIslandQuirk(void){
 HMODULE module=GetModuleHandleW(L"Windows.UI.Xaml.dll");
 if(!module){puts("QUIRK no native XAML module");return FALSE;}
 BYTE *base=(BYTE*)module; BYTE signature[]={0x40,0x53,0x48,0x83,0xec,0x20,0x33,0xdb,0x39,0x1d,0x7e,0xcd,0xc2,0x00,0x75,0x3d,0x45,0x33,0xc9,0x4c,0x8d,0x05,0x66,0xcd};
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

int main(int argc,char**argv){
 if(argc>2 && !strcmp(argv[1],"package"))freopen(argv[2],"wb",stdout);
 HMODULE cb=LoadLibraryW(L"combase.dll");RoInitialize=(void*)GetProcAddress(cb,"RoInitialize");RoGetActivationFactory=(void*)GetProcAddress(cb,"RoGetActivationFactory");WindowsCreateString=(void*)GetProcAddress(cb,"WindowsCreateString");
 HANDLE context=NULL;ULONG_PTR cookie=0;
 if(argc>2 && strcmp(argv[1],"package") && strcmp(argv[1],"quirk")){
  WCHAR path[4096];MultiByteToWideChar(CP_UTF8,0,argv[2],-1,path,4096);
  ACTCTXW a={0};a.cbSize=sizeof(a);a.lpSource=path;
  if(!strcmp(argv[1],"default"))a.dwFlags=0x10;
  context=CreateActCtxW(&a);printf("CreateActCtx handle=%p error=%lu flags=%lx\n",context,GetLastError(),a.dwFlags);
  if(context!=INVALID_HANDLE_VALUE){BOOL ok=ActivateActCtx(context,&cookie);printf("Activate=%d error=%lu\n",ok,GetLastError());}
 }
 BYTE info[512]={0};SIZE_T length=0;
 BOOL queried=QueryActCtxW(4,NULL,NULL,6,info,sizeof(info),&length);printf("QueryActive=%d err=%lu len=%llu bytes=",queried,GetLastError(),(unsigned long long)length);
 for(SIZE_T i=0;i<length && i<96;i++)printf("%02x",info[i]);puts("");fflush(stdout);
 HRESULT hr=RoInitialize(0);printf("RoInitialize=%08lx\n",hr);
 HSTRING name=NULL;WindowsCreateString(L"Windows.UI.Xaml.Hosting.WindowsXamlManager",42,&name);void *factory=NULL;
 hr=RoGetActivationFactory(name,&statics,&factory);printf("GetFactory=%08lx nonNull=%d\n",hr,factory!=NULL);fflush(stdout);
 if(argc>1 && !strcmp(argv[1],"quirk") && !adaptIslandQuirk())return 70;
 if(SUCCEEDED(hr) && factory){void *manager=NULL;hr=((InitializeFn)(*(void***)factory)[6])(factory,&manager);printf("Initialize=%08lx nonNull=%d\n",hr,manager!=NULL);fflush(stdout);
  if(FAILED(hr)){
   HRESULT (WINAPI *geterror)(void**)=(void*)GetProcAddress(cb,"GetRestrictedErrorInfo");void *error=NULL;
   if(geterror && SUCCEEDED(geterror(&error)) && error){WCHAR *description=NULL,*restricted=NULL,*capability=NULL;HRESULT detail=0;
    typedef HRESULT(WINAPI *DetailFn)(void*,WCHAR**,HRESULT*,WCHAR**,WCHAR**);
    ((DetailFn)(*(void***)error)[3])(error,&description,&detail,&restricted,&capability);
    WCHAR *strings[2]={description,restricted};for(int i=0;i<2;i++){if(strings[i]){char buffer[8192];WideCharToMultiByte(CP_UTF8,0,strings[i],-1,buffer,sizeof(buffer),NULL,NULL);printf("Error%d=%s\n",i,buffer);}}
   }
  }
 }
 /* Process exit owns cleanup; no shell singleton, no visible application. */
 return 0;
}

