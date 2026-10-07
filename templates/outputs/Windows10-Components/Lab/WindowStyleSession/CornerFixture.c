#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <stdio.h>
static wchar_t root[32768];
static BOOL exists(const wchar_t*n){wchar_t p[32768];swprintf(p,32768,L"%ls\\%ls",root,n);return GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}
static LRESULT CALLBACK proc(HWND h,UINT m,WPARAM w,LPARAM l){return DefWindowProcW(h,m,w,l);}
static HWND make(HINSTANCE i,const wchar_t*c,int pref){HWND h=CreateWindowExW(0,c,L"Own hidden corner fixture",WS_OVERLAPPEDWINDOW,-32000,-32000,400,300,NULL,NULL,i,NULL);DwmSetWindowAttribute(h,33,&pref,4);return h;}
int WINAPI wWinMain(HINSTANCE i,HINSTANCE prev,wchar_t*cmd,int show){(void)prev;(void)cmd;(void)show;int argc=0;wchar_t**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=2)return 64;wcsncpy(root,argv[1],32767);LocalFree(argv);
 WNDCLASSW wc={0};wc.lpfnWndProc=proc;wc.hInstance=i;wc.lpszClassName=L"CodexCornerFixture";if(!RegisterClassW(&wc))return 65;wc.lpszClassName=L"CodexCornerForeign";RegisterClassW(&wc);
 HWND a=make(i,L"CodexCornerFixture",2),b=NULL,f=make(i,L"CodexCornerForeign",3);if(!a||!f)return 66;
 wchar_t p[32768],tmp[32768];swprintf(p,32768,L"%ls\\windows.json",root);swprintf(tmp,32768,L"%ls\\windows.tmp",root);
 while(!exists(L"exit")){
  if(!b&&exists(L"new"))b=make(i,L"CodexCornerFixture",3);
  int av=-1,bv=-1,fv=-1;HRESULT ar=DwmGetWindowAttribute(a,33,&av,4),br=b?DwmGetWindowAttribute(b,33,&bv,4):E_FAIL,fr=DwmGetWindowAttribute(f,33,&fv,4);
  FILE*out=_wfopen(tmp,L"wb");if(out){fprintf(out,"{\"pid\":%lu,\"a\":%llu,\"b\":%llu,\"foreign\":%llu,\"av\":%d,\"bv\":%d,\"fv\":%d,\"ar\":%ld,\"br\":%ld,\"fr\":%ld,\"visibleA\":%d,\"visibleB\":%d}\n",GetCurrentProcessId(),(unsigned long long)a,(unsigned long long)b,(unsigned long long)f,av,bv,fv,(long)ar,(long)br,(long)fr,IsWindowVisible(a),b?IsWindowVisible(b):0);fclose(out);MoveFileExW(tmp,p,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);}
  MSG m;while(PeekMessageW(&m,NULL,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}Sleep(100);
 }
 DestroyWindow(a);if(b)DestroyWindow(b);DestroyWindow(f);return 0;
}
