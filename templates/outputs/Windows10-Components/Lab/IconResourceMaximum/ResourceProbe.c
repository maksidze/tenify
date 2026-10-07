#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
static FILE*out;static unsigned index;
static void quoted(const char*s){fputc('"',out);for(;*s;s++){if(*s=='"'||*s=='\\')fputc('\\',out);fputc(*s,out);}fputc('"',out);}
static BOOL CALLBACK visit(HMODULE h,LPCWSTR type,LPWSTR name,LONG_PTR parameter){
 HRSRC group=FindResourceW(h,name,RT_GROUP_ICON);DWORD selected=0,nonzero=0;unsigned long long hash=1469598103934665603ULL;BOOL drawn=FALSE;
 if(group){BYTE*data=LockResource(LoadResource(h,group));if(data)selected=LookupIconIdFromDirectoryEx(data,TRUE,32,32,LR_DEFAULTCOLOR);}
 HRSRC res=selected?FindResourceW(h,MAKEINTRESOURCEW(selected),RT_ICON):NULL;HICON icon=NULL;
 if(res){DWORD n=SizeofResource(h,res);BYTE*data=LockResource(LoadResource(h,res));if(data)icon=CreateIconFromResourceEx(data,n,TRUE,0x30000,32,32,LR_DEFAULTCOLOR);}
 if(icon){BITMAPINFO bi={0};bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bi.bmiHeader.biWidth=32;bi.bmiHeader.biHeight=-32;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;HDC dc=CreateCompatibleDC(NULL);void*bits=NULL;HBITMAP bmp=CreateDIBSection(dc,&bi,DIB_RGB_COLORS,&bits,NULL,0);if(bmp){HGDIOBJ old=SelectObject(dc,bmp);ZeroMemory(bits,4096);drawn=DrawIconEx(dc,0,0,icon,32,32,0,NULL,DI_NORMAL);GdiFlush();for(int i=0;i<4096;i++){hash^=((BYTE*)bits)[i];hash*=1099511628211ULL;}for(int i=0;i<1024;i++)if(((DWORD*)bits)[i])nonzero++;SelectObject(dc,old);DeleteObject(bmp);}DeleteDC(dc);DestroyIcon(icon);}
 fprintf(out,"{\"file\":%u,\"group\":",index);if(IS_INTRESOURCE(name))fprintf(out,"%u",(unsigned)(ULONG_PTR)name);else{char text[1024];WideCharToMultiByte(CP_UTF8,0,name,-1,text,sizeof(text),NULL,NULL);quoted(text);}fprintf(out,",\"selected\":%lu,\"drawn\":%d,\"nonzero\":%lu,\"hash\":\"%016llx\"}\n",selected,drawn,nonzero,hash);return TRUE;
}
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){int argc=0;WCHAR**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=3)return 64;FILE*f=_wfopen(argv[1],L"rb");out=_wfopen(argv[2],L"wb");if(!f||!out)return 65;WORD bom;fread(&bom,2,1,f);if(bom!=0xfeff)return 66;WCHAR path[32768];index=0;for(;;){unsigned n=0;WCHAR ch;while(n<32767&&fread(&ch,2,1,f)==1&&ch!=L'\n')if(ch!=L'\r')path[n++]=ch;path[n]=0;if(!n)break;HMODULE h=LoadLibraryExW(path,NULL,LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE|LOAD_LIBRARY_AS_IMAGE_RESOURCE);if(h){EnumResourceNamesW(h,RT_GROUP_ICON,visit,0);FreeLibrary(h);}else fprintf(out,"{\"file\":%u,\"loadError\":%lu}\n",index,GetLastError());index++;}fclose(f);fclose(out);LocalFree(argv);return 0;}
