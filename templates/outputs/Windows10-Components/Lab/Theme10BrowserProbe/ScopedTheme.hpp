// Own-process feasibility probe, not a production hook. Exact matched native x64 ABI.
using ThemeCreateFn=HRESULT(WINAPI*)(void*,PWSTR,UINT,int,PWSTR,UINT,int,int);
using ThemeLoadFn=HRESULT(WINAPI*)(HANDLE,HMODULE,PCWSTR,PCWSTR,PCWSTR,HANDLE*,PWSTR,UINT,HANDLE*,PWSTR,UINT,ThemeCreateFn,HANDLE*,USHORT,int);
using ThemeFileOpenFn=HRESULT(WINAPI*)(void*,HANDLE,HANDLE,void**);
using ThemeFileCloseFn=void(WINAPI*)(void*,void*);
using ThemeDataOpenFn=HTHEME(WINAPI*)(void*,HWND,PCWSTR,int);
using ThemeFileFromDataFn=HRESULT(WINAPI*)(HTHEME,void**);
struct ScopedTheme {
 HMODULE ux=nullptr;void*app=nullptr;void*before=nullptr;void*file=nullptr;HTHEME button=nullptr,edit=nullptr,native=nullptr;
 bool stable(){return app&&*(void**)((BYTE*)app+8)==before;}
 static DWORD pixels(HTHEME theme,int part,HRESULT*result){
  BITMAPINFO bmi={};bmi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bmi.bmiHeader.biWidth=140;bmi.bmiHeader.biHeight=-48;bmi.bmiHeader.biPlanes=1;bmi.bmiHeader.biBitCount=32;bmi.bmiHeader.biCompression=BI_RGB;
  HDC dc=CreateCompatibleDC(nullptr);void*bits=nullptr;HBITMAP bitmap=dc?CreateDIBSection(dc,&bmi,DIB_RGB_COLORS,&bits,nullptr,0):nullptr;DWORD digest=0;
  *result=E_OUTOFMEMORY;if(dc&&bitmap&&bits){HGDIOBJ prior=SelectObject(dc,bitmap);memset(bits,0xff,140*48*4);RECT rc={0,0,140,48};*result=DrawThemeBackground(theme,dc,part,1,&rc,nullptr);GdiFlush();digest=2166136261u;for(size_t i=0;i<140*48*4;i++){digest^=((BYTE*)bits)[i];digest*=16777619u;}SelectObject(dc,prior);}
  if(bitmap)DeleteObject(bitmap);if(dc)DeleteDC(dc);return digest;
 }
 bool open(PCWSTR path){
  if(!hashMatches(L"C:\\Windows\\System32\\uxtheme.dll","8c5347d464b4b74a17fbc7ab84e2e1f18c1b77fae964caf4f8566df5a7a4a07b")||!hashMatches(path,"847aaa1e347631f353119d9c483d88111c4a29d0c0abafdd650447d3cbf8831e"))return false;
  ux=LoadLibraryExW(L"C:\\Windows\\System32\\uxtheme.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!ux)return false;
  auto load=(ThemeLoadFn)GetProcAddress(ux,MAKEINTRESOURCEA(92));auto dataOpen=(ThemeDataOpenFn)GetProcAddress(ux,MAKEINTRESOURCEA(16));auto fromData=(ThemeFileFromDataFn)GetProcAddress(ux,MAKEINTRESOURCEA(17));
  if((BYTE*)load!=(BYTE*)ux+0x4720||(BYTE*)dataOpen!=(BYTE*)ux+0x493f0||(BYTE*)fromData!=(BYTE*)ux+0x609c0)return false;
  native=OpenThemeData(nullptr,L"Button");if(!native)return false;
  app=*(void**)((BYTE*)ux+0x9cab8);if(!app){CloseThemeData(native);native=nullptr;return false;}before=*(void**)((BYTE*)app+8);
  void*nativeFile=nullptr;HRESULT hr=fromData(native,&nativeFile);logHr("OpenThemeFileFromData native borrowed",hr);
  HRESULT nativeDraw=E_FAIL;DWORD nativePixels=pixels(native,1,&nativeDraw);
  HANDLE source=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);if(source==INVALID_HANDLE_VALUE)return false;
  HANDLE shared=nullptr,nonshared=nullptr;
  hr=load(source,nullptr,path,L"NormalColor",L"NormalSize",&shared,nullptr,0,&nonshared,nullptr,0,nullptr,nullptr,0,0);
  CloseHandle(source);logHr("LoaderLoadTheme standalone",hr);fprintf(logFile,"sectionShared=%p sectionNonShared=%p currentUnchangedAfterLoad=%d\n",shared,nonshared,stable());fflush(logFile);
  if(FAILED(hr)||!shared||!nonshared){if(shared)CloseHandle(shared);if(nonshared)CloseHandle(nonshared);return false;}
  // a7f8 consumes both section handles when CUxThemeFile::OpenFromHandle succeeds.
  // Its failure paths are not normalized here: this disposable probe exits immediately
  // on failure, so kernel teardown frees any remaining handles without a double-close.
  auto fileOpen=(ThemeFileOpenFn)((BYTE*)ux+0xa7f8);hr=fileOpen(app,shared,nonshared,&file);logHr("CAppInfo OpenThemeFile separate",hr);
  if(FAILED(hr)||!file){fflush(logFile);ExitProcess(0xdec5);}
  button=dataOpen(file,nullptr,L"Button",1);edit=dataOpen(file,nullptr,L"Edit",1);
  void*oldFile=nullptr;hr=button?fromData(button,&oldFile):E_HANDLE;logHr("OpenThemeFileFromData old borrowed",hr);
  HRESULT oldDraw=E_FAIL,editDraw=E_FAIL;DWORD oldPixels=button?pixels(button,1,&oldDraw):0,editPixels=edit?pixels(edit,1,&editDraw):0;
  fprintf(logFile,"scopedFile=%p nativeFile=%p oldDataSameFile=%d currentUnchanged=%d nativeDraw=%08lx oldDraw=%08lx editDraw=%08lx nativePixels=%08lx oldPixels=%08lx editPixels=%08lx\n",file,nativeFile,oldFile==file,stable(),nativeDraw,oldDraw,editDraw,nativePixels,oldPixels,editPixels);fflush(logFile);
  return stable()&&button&&edit&&oldFile==file&&SUCCEEDED(hr)&&SUCCEEDED(nativeDraw)&&SUCCEEDED(oldDraw)&&SUCCEEDED(editDraw)&&nativePixels!=oldPixels;
 }
 bool close(){
  if(button){CloseThemeData(button);button=nullptr;}if(edit){CloseThemeData(edit);edit=nullptr;}
  if(file){auto closeFile=(ThemeFileCloseFn)((BYTE*)ux+0x2c210);closeFile(app,file);file=nullptr;}
  bool okay=!app||stable();fprintf(logFile,"scopedThemeClosed=1 currentUnchangedAfterClose=%d\n",okay);if(native){CloseThemeData(native);native=nullptr;}if(ux){FreeLibrary(ux);ux=nullptr;}return okay;
 }
};
