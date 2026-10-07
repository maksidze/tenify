#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <thumbcache.h>
#include <stdio.h>
#include <string>
static FILE*logFile;static std::wstring outdir;static unsigned serial;
static void quote(PCWSTR text){char b[32768];WideCharToMultiByte(CP_UTF8,0,text?text:L"",-1,b,sizeof(b),nullptr,nullptr);fputc('"',logFile);for(char*p=b;*p;p++){if(*p=='\\')fputc('/',logFile);else if(*p=='"')fputs("\\\"",logFile);else fputc(*p,logFile);}fputc('"',logFile);}
static bool bitmap(HBITMAP bm,PCWSTR name){BITMAP v={};if(!GetObjectW(bm,sizeof(v),&v))return false;BITMAPINFO info={};info.bmiHeader.biSize=40;info.bmiHeader.biWidth=v.bmWidth;info.bmiHeader.biHeight=-v.bmHeight;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;size_t n=(size_t)v.bmWidth*v.bmHeight*4;auto bytes=new BYTE[n];HDC dc=CreateCompatibleDC(nullptr);int got=GetDIBits(dc,bm,0,v.bmHeight,bytes,&info,DIB_RGB_COLORS);DeleteDC(dc);FILE*f=_wfopen((outdir+L"/"+name+L".bgra").c_str(),L"wb");bool ok=f&&got;if(f){fwrite(bytes,1,n,f);fclose(f);}delete[]bytes;fprintf(logFile,",\"width\":%ld,\"height\":%ld,\"drawn\":%s",v.bmWidth,v.bmHeight,ok?"true":"false");return ok;}
static void icon(HICON h,PCWSTR name,int size=48){if(!h){fputs(",\"drawn\":false",logFile);return;}BITMAPINFO info={};info.bmiHeader.biSize=40;info.bmiHeader.biWidth=size;info.bmiHeader.biHeight=-size;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;void*bits;HDC dc=CreateCompatibleDC(nullptr);HBITMAP b=CreateDIBSection(dc,&info,DIB_RGB_COLORS,&bits,nullptr,0);if(!dc||!b)return;auto old=SelectObject(dc,b);ZeroMemory(bits,size*size*4);DrawIconEx(dc,0,0,h,size,size,0,nullptr,DI_NORMAL);GdiFlush();SelectObject(dc,old);bitmap(b,name);DeleteObject(b);DeleteDC(dc);}
static void row(PCWSTR name,HRESULT hr,PCWSTR path=nullptr,int index=0){if(serial++)fputs(",\n",logFile);fputs("{\"name\":",logFile);quote(name);fprintf(logFile,",\"hr\":\"%08lx\",\"path\":",hr);quote(path);fprintf(logFile,",\"index\":%d",index);}
static void method(IUnknown*o,PCWSTR tag){HMODULE m=nullptr;void*p=(*(void***)o)[3];WCHAR path[32768]={},label[160];if(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(PCWSTR)p,&m))GetModuleFileNameW(m,path,32768);swprintf(label,160,L"%ls-location-method",tag);row(label,S_OK,path);fprintf(logFile,",\"rva\":%llu,\"vtableRva\":%llu}",(unsigned long long)((BYTE*)p-(BYTE*)m),(unsigned long long)((BYTE*)(*(void***)o)-(BYTE*)m));if(m)FreeLibrary(m);}
static void direct(PCWSTR label,PCWSTR path,int index,int size){HICON h=nullptr;UINT id=0;UINT n=PrivateExtractIconsW(path,index,size,size,&h,&id,1,0);row(label,n&&h?S_OK:E_FAIL,path,index);icon(h,label,size);fputs("}",logFile);if(h)DestroyIcon(h);}
static void folder(PCWSTR path,PCWSTR tag){
 for(UINT flags:{SHGFI_ICON|SHGFI_LARGEICON,SHGFI_ICON|SHGFI_LARGEICON|SHGFI_USEFILEATTRIBUTES,SHGFI_ICON|SHGFI_LARGEICON|SHGFI_OPENICON}){WCHAR label[160];swprintf(label,160,L"%ls-fileinfo-%x",tag,flags);SHFILEINFOW info={};auto value=SHGetFileInfoW(path,FILE_ATTRIBUTE_DIRECTORY,&info,sizeof(info),flags);row(label,value?S_OK:E_FAIL,path,info.iIcon);icon(info.hIcon,label,32);fputs("}",logFile);if(info.hIcon)DestroyIcon(info.hIcon);}
 PIDLIST_ABSOLUTE pidl=nullptr;HRESULT hr=SHParseDisplayName(path,nullptr,&pidl,0,nullptr);if(SUCCEEDED(hr)){IShellFolder*parent=nullptr;PCUITEMID_CHILD last=nullptr;hr=SHBindToParent(pidl,IID_PPV_ARGS(&parent),&last);if(SUCCEEDED(hr)){IExtractIconW*extractor=nullptr;hr=parent->GetUIObjectOf(nullptr,1,&last,IID_IExtractIconW,nullptr,(void**)&extractor);if(SUCCEEDED(hr)){method(extractor,tag);WCHAR source[32768],label[160];int index=0;UINT flags=0;hr=extractor->GetIconLocation(GIL_FORSHELL,source,32768,&index,&flags);swprintf(label,160,L"%ls-location",tag);row(label,hr,SUCCEEDED(hr)?source:L"",index);fprintf(logFile,",\"flags\":%u}",flags);HICON large=nullptr,small=nullptr;hr=extractor->Extract(source,index,&large,&small,MAKELONG(48,16));swprintf(label,160,L"%ls-extract",tag);row(label,hr,source,index);icon(large,label,48);fputs("}",logFile);if(large)DestroyIcon(large);if(small)DestroyIcon(small);extractor->Release();}parent->Release();}CoTaskMemFree(pidl);}
 IShellItemImageFactory*factory=nullptr;hr=SHCreateItemFromParsingName(path,nullptr,IID_PPV_ARGS(&factory));if(SUCCEEDED(hr)){for(SIIGBF flags:{(SIIGBF)SIIGBF_ICONONLY,(SIIGBF)SIIGBF_THUMBNAILONLY,(SIIGBF)0}){WCHAR label[160];swprintf(label,160,L"%ls-factory-%x",tag,(UINT)flags);HBITMAP b=nullptr;hr=factory->GetImage(SIZE{96,96},flags,&b);row(label,hr,path);if(b){bitmap(b,label);DeleteObject(b);}fputs("}",logFile);}factory->Release();}
}
static void forceOwnThumbnail(PCWSTR path){
 static const CLSID localCache={0x50ef4544,0xac9f,0x4a8e,{0xb2,0x1b,0x8a,0x26,0x18,0x0d,0xb1,0x3f}};
 IShellItem*item=nullptr;IThumbnailCache*cache=nullptr;ISharedBitmap*shared=nullptr;WTS_CACHEFLAGS flags={};WTS_THUMBNAILID id={};
 HRESULT hr=SHCreateItemFromParsingName(path,nullptr,IID_PPV_ARGS(&item));
 if(SUCCEEDED(hr))hr=CoCreateInstance(localCache,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&cache));
 if(SUCCEEDED(hr))hr=cache->GetThumbnail(item,96,(WTS_FLAGS)(WTS_FORCEEXTRACTION|WTS_EXTRACTINPROC|WTS_SCALETOREQUESTEDSIZE),&shared,&flags,&id);
 row(L"own-force-thumbnail",hr,path);fprintf(logFile,",\"cacheFlags\":%u",flags);
 if(shared){HBITMAP b=nullptr;HRESULT bh=shared->GetSharedBitmap(&b);fprintf(logFile,",\"bitmapHr\":\"%08lx\"",bh);if(SUCCEEDED(bh)&&b)bitmap(b,L"own-force-thumbnail");shared->Release();}
 fputs("}",logFile);if(cache)cache->Release();if(item)item->Release();
}
static DWORD WINAPI watchdog(void*event){if(WaitForSingleObject((HANDLE)event,45000)==WAIT_TIMEOUT)ExitProcess(0xdeca);return 0;}
static bool keyChecks(HMODULE helper){
 using Location=HRESULT(STDMETHODCALLTYPE*)(void*,UINT,PWSTR,UINT,int*,UINT*);
 auto module=GetModuleHandleW(L"windows.storage.dll");auto original=(Location)((BYTE*)module+0x257930);bool all=true;
 for(int test=0;test<4;test++){
  IDefaultExtractIconInit*setup=nullptr;IExtractIconW*item=nullptr;HRESULT hr=SHCreateDefaultExtractIcon(IID_PPV_ARGS(&setup));
  PCWSTR path=test==2?L"C:\\Windows\\explorer.exe":L"C:\\Windows\\system32\\imageres.dll";int wanted=test==1?-1:test==2?0:-3;UINT length=test==3?65:260;
  if(SUCCEEDED(hr))hr=setup->SetNormalIcon(path,wanted);if(SUCCEEDED(hr))hr=setup->QueryInterface(IID_IExtractIconW,(void**)&item);
  struct Guard {ULONGLONG before;WCHAR text[260];ULONGLONG after;} native={0xabcddcba12344321,{},0x1122334455667788},routed=native;int ni=0,ri=0;UINT nf=0,rf=0;HRESULT nh=E_FAIL,rh=E_FAIL;
  if(item){nh=original(item,0,native.text,length,&ni,&nf);rh=item->GetIconLocation(0,routed.text,length,&ri,&rf);}
  bool guards=routed.before==native.before&&routed.after==native.after;
  bool pass=item&&SUCCEEDED(hr)&&nh==rh&&ni==ri&&nf==rf&&guards;
  if(test==0)pass=pass&&SUCCEEDED(rh)&&_wcsicmp(native.text,routed.text)!=0;
  else pass=pass&&!memcmp(native.text,routed.text,sizeof(native.text));
  WCHAR label[80];swprintf(label,80,L"cachekey-case-%d",test);row(label,rh,routed.text,ri);fprintf(logFile,",\"pass\":%s,\"canaries\":%s}",pass?"true":"false",guards?"true":"false");all&=pass;
  if(item)item->Release();if(setup)setup->Release();
 }
 return all;
}
int wmain(int argc,wchar_t**argv){if(argc!=8)return 2;outdir=argv[1];logFile=_wfopen((outdir+L"/icons.json").c_str(),L"wb");if(!logFile)return 3;HANDLE done=CreateEventW(nullptr,TRUE,FALSE,nullptr),guard=CreateThread(nullptr,0,watchdog,done,0,nullptr);if(!done||!guard)return 4;HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(hr))return 5;
 HMODULE adapter=nullptr;typedef DWORD(WINAPI*Init)(void*);Init restore=nullptr;DWORD initStatus=0;
 if(wcscmp(argv[5],L"-")){adapter=LoadLibraryW(argv[5]);if(!adapter)return 6;auto init=(Init)GetProcAddress(adapter,"InitializeIconRoutesFixture");restore=(Init)GetProcAddress(adapter,"RestoreIconRoutes");if(!init||!restore)return 7;initStatus=init(nullptr);if(initStatus)return (int)initStatus;}
 Init cacheRestore=nullptr;if(adapter&&!wcscmp(argv[7],L"no-vfs-key")){auto f=(Init)GetProcAddress(adapter,"InitializeFolderCacheKeyFixture");cacheRestore=(Init)GetProcAddress(adapter,"RestoreFolderCacheKeyFixture");if(!f||!cacheRestore)return 9;DWORD r=f(nullptr);if(r)return (int)r;}fprintf(logFile,"{\"pid\":%lu,\"init\":%lu,\"icons\":[\n",GetCurrentProcessId(),initStatus);bool keysOkay=!cacheRestore||keyChecks(adapter);folder(argv[2],L"empty");folder(argv[3],L"nonempty");folder(argv[6],L"custom");
 if(adapter){forceOwnThumbnail(argv[3]);folder(argv[3],L"after-force");}
 for(int id:{3,4}){SHSTOCKICONINFO info={sizeof(info)};hr=SHGetStockIconInfo((SHSTOCKICONID)id,SHGSI_ICON|SHGSI_LARGEICON,&info);WCHAR name[50];swprintf(name,50,L"stock-%d",id);row(name,hr,info.szPath,info.iIcon);icon(info.hIcon,name,32);fputs("}",logFile);if(info.hIcon)DestroyIcon(info.hIcon);}
 direct(L"explorer-native",L"C:\\Windows\\explorer.exe",0,32);std::wstring base=argv[4];direct(L"explorer-private",(base+L"/Lab/IconResourceMaximum/ResourceOnlyContainers/explorer.exe.mun").c_str(),0,32);direct(L"explorer-old",(base+L"/Image/4/Windows/explorer.exe").c_str(),0,32);
 DWORD patches=0,hits=0;if(adapter){auto count=(Init)GetProcAddress(adapter,"GetIconRoutePatchCount"),hit=(Init)GetProcAddress(adapter,"GetIconRouteHits");patches=count?count(nullptr):0;hits=hit?hit(nullptr):0;}DWORD cacheHits=0,cacheRestored=0;if(cacheRestore){auto f=(Init)GetProcAddress(adapter,"GetFolderCacheKeyHits");cacheHits=f?f(nullptr):0;cacheRestored=cacheRestore(nullptr);}DWORD restored=restore?restore(nullptr):0;
 fprintf(logFile,"],\"patches\":%lu,\"routeHits\":%lu,\"restore\":%lu,\"cacheHits\":%lu,\"cacheRestore\":%lu}\n",patches,hits,restored,cacheHits,cacheRestored);fclose(logFile);CoUninitialize();SetEvent(done);WaitForSingleObject(guard,1000);CloseHandle(guard);CloseHandle(done);return restored?8:keysOkay?0:10;
}
