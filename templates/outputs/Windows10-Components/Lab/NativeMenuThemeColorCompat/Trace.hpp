#include <uxtheme.h>
#include <stdio.h>
static HMODULE ux;
static LONG traceCount;
static const int traceLimit=1200;
static FILE*traceFile;
struct ThemeRecord{HTHEME theme;WCHAR name[128];};static ThemeRecord themes[512];static int themeCount;
static PCWSTR themeName(HTHEME h){for(int i=themeCount-1;i>=0;i--)if(themes[i].theme==h)return themes[i].name;return L"<unobserved>";}
static bool mapMenu,fullOld;static LONG mapHits;
static int mappedPart(HTHEME h,int p){PCWSTR c=themeName(h);if(mapMenu&&fullOld&&p==27&&(!wcscmp(c,L"Menu")||!wcscmp(c,L"ImmersiveStart::Menu")||!wcscmp(c,L"DarkMode_ImmersiveStart::Menu"))){mapHits++;return 14;}return p;}
static void registerTheme(HTHEME h,PCWSTR c,PCSTR api){if(!h)return;if(themeCount<512){themes[themeCount].theme=h;wcsncpy(themes[themeCount].name,c?c:L"<null>",127);themeCount++;}if(traceCount++<traceLimit){fprintf(traceFile,"OPEN api=%s h=%p class=%ls\n",api,h,c?c:L"<null>");fflush(traceFile);}}
using Open=HTHEME(WINAPI*)(HWND,PCWSTR);using OpenDpi=HTHEME(WINAPI*)(HWND,PCWSTR,UINT);using OpenEx=HTHEME(WINAPI*)(HWND,PCWSTR,DWORD);
static Open openReal;static OpenDpi dpiReal;static OpenEx exReal;
static HTHEME WINAPI traceOpen(HWND w,PCWSTR c){auto h=openReal(w,c);registerTheme(h,c,"OpenThemeData");return h;}
static HTHEME WINAPI traceDpi(HWND w,PCWSTR c,UINT d){auto h=dpiReal(w,c,d);registerTheme(h,c,"OpenThemeDataForDpi");return h;}
static HTHEME WINAPI traceEx(HWND w,PCWSTR c,DWORD f){auto h=exReal(w,c,f);registerTheme(h,c,"OpenThemeDataEx");return h;}
using BG=HRESULT(WINAPI*)(HTHEME,HDC,int,int,const RECT*,const RECT*);using BGEx=HRESULT(WINAPI*)(HTHEME,HDC,int,int,const RECT*,const DTBGOPTS*);using SZ=HRESULT(WINAPI*)(HTHEME,HDC,int,int,RECT*,THEMESIZE,SIZE*);using COLOR=HRESULT(WINAPI*)(HTHEME,int,int,int,COLORREF*);using MARG=HRESULT(WINAPI*)(HTHEME,HDC,int,int,int,RECT*,MARGINS*);
static BG bgReal;static BGEx bgExReal;static SZ szReal;static COLOR colorReal;static MARG marginsReal;
static void event(PCSTR api,HTHEME h,int part,int state,HRESULT hr,int a=0,int b=0){if(traceCount++<traceLimit){fprintf(traceFile,"API=%s h=%p class=%ls part=%d state=%d hr=%08lx a=%d b=%d\n",api,h,themeName(h),part,state,hr,a,b);fflush(traceFile);}}
static HRESULT WINAPI traceBG(HTHEME h,HDC dc,int p,int s,const RECT*r,const RECT*c){HRESULT hr=bgReal(h,dc,mappedPart(h,p),s,r,c);event("DrawThemeBackground",h,p,s,hr,r?r->right-r->left:0,r?r->bottom-r->top:0);return hr;}
static HRESULT WINAPI traceBGEx(HTHEME h,HDC dc,int p,int s,const RECT*r,const DTBGOPTS*c){HRESULT hr=bgExReal(h,dc,mappedPart(h,p),s,r,c);event("DrawThemeBackgroundEx",h,p,s,hr,r?r->right-r->left:0,r?r->bottom-r->top:0);return hr;}
static HRESULT WINAPI traceSize(HTHEME h,HDC dc,int p,int s,RECT*r,THEMESIZE mode,SIZE*out){HRESULT hr=szReal(h,dc,mappedPart(h,p),s,r,mode,out);event("GetThemePartSize",h,p,s,hr,SUCCEEDED(hr)&&out?out->cx:0,SUCCEEDED(hr)&&out?out->cy:0);return hr;}
static HRESULT WINAPI traceColor(HTHEME h,int p,int s,int prop,COLORREF*out){HRESULT hr=colorReal(h,mappedPart(h,p),s,prop,out);event("GetThemeColor",h,p,s,hr,prop,SUCCEEDED(hr)&&out?(int)*out:0);return hr;}
static HRESULT WINAPI traceMargins(HTHEME h,HDC dc,int p,int s,int prop,RECT*r,MARGINS*out){HRESULT hr=marginsReal(h,dc,mappedPart(h,p),s,prop,r,out);event("GetThemeMargins",h,p,s,hr,SUCCEEDED(hr)&&out?out->cxLeftWidth:0,SUCCEEDED(hr)&&out?out->cyTopHeight:0);return hr;}
using TEXT=HRESULT(WINAPI*)(HTHEME,HDC,int,int,PCWSTR,int,DWORD,RECT*,const DTTOPTS*);static TEXT textReal;
static HRESULT WINAPI traceText(HTHEME h,HDC dc,int p,int s,PCWSTR text,int n,DWORD flags,RECT*r,const DTTOPTS*o){HRESULT hr=textReal(h,dc,mappedPart(h,p),s,text,n,flags,r,o);event("DrawThemeTextEx",h,p,s,hr);return hr;}
struct Binding{PCSTR name;void*replacement;};static Binding bindings[]={{"OpenThemeData",(void*)traceOpen},{"OpenThemeDataForDpi",(void*)traceDpi},{"OpenThemeDataEx",(void*)traceEx},{"DrawThemeBackground",(void*)traceBG},{"DrawThemeBackgroundEx",(void*)traceBGEx},{"GetThemePartSize",(void*)traceSize},{"GetThemeColor",(void*)traceColor},{"GetThemeMargins",(void*)traceMargins},{"DrawThemeTextEx",(void*)traceText}};
static void publish(void**slot,void*p){DWORD prot,ignore;if(!VirtualProtect(slot,8,PAGE_READWRITE,&prot))ExitProcess(0xdec1);InterlockedExchangePointer(slot,p);if(!VirtualProtect(slot,8,prot,&ignore))ExitProcess(0xdec2);}
static void patchImports(HMODULE m){BYTE*b=(BYTE*)m;auto dos=(IMAGE_DOS_HEADER*)b;auto nt=(IMAGE_NT_HEADERS64*)(b+dos->e_lfanew);auto dir=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];if(dir.VirtualAddress)for(auto d=(IMAGE_IMPORT_DESCRIPTOR*)(b+dir.VirtualAddress);d->Name;d++)if(d->OriginalFirstThunk){auto names=(IMAGE_THUNK_DATA64*)(b+d->OriginalFirstThunk),iat=(IMAGE_THUNK_DATA64*)(b+d->FirstThunk);for(int i=0;names[i].u1.AddressOfData;i++){if(IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal))continue;PCSTR name=(PCSTR)((IMAGE_IMPORT_BY_NAME*)(b+names[i].u1.AddressOfData))->Name;for(auto &x:bindings)if(!strcmp(name,x.name))publish((void**)&iat[i].u1.Function,x.replacement);}}
 struct Delay{DWORD attrs,name,hmod,iat,names,bound,unload,timestamp;};dir=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];if(dir.VirtualAddress)for(auto d=(Delay*)(b+dir.VirtualAddress);d->name;d++){if(d->attrs!=1)ExitProcess(0xdec3);auto names=(ULONGLONG*)(b+d->names);auto iat=(void**)(b+d->iat);for(int i=0;names[i];i++){if(IMAGE_SNAP_BY_ORDINAL64(names[i]))continue;PCSTR name=(PCSTR)(b+names[i]+2);for(auto &x:bindings)if(!strcmp(name,x.name))publish(&iat[i],x.replacement);}}}
static void initTrace(HMODULE pcs,HMODULE shell){ux=LoadLibraryW(L"C:\\Windows\\System32\\uxtheme.dll");openReal=(Open)GetProcAddress(ux,"OpenThemeData");dpiReal=(OpenDpi)GetProcAddress(ux,"OpenThemeDataForDpi");exReal=(OpenEx)GetProcAddress(ux,"OpenThemeDataEx");bgReal=(BG)GetProcAddress(ux,"DrawThemeBackground");bgExReal=(BGEx)GetProcAddress(ux,"DrawThemeBackgroundEx");szReal=(SZ)GetProcAddress(ux,"GetThemePartSize");colorReal=(COLOR)GetProcAddress(ux,"GetThemeColor");marginsReal=(MARG)GetProcAddress(ux,"GetThemeMargins");textReal=(TEXT)GetProcAddress(ux,"DrawThemeTextEx");patchImports(pcs);patchImports(shell);}
