#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
static void quoted(FILE*f,const wchar_t*w){char s[8192];WideCharToMultiByte(CP_UTF8,0,w,-1,s,sizeof(s),NULL,NULL);fputc('"',f);for(char*p=s;*p;p++){if(*p=='\\')fputc('/',f);else if(*p=='"')fputs("\\\"",f);else fputc(*p,f);}fputc('"',f);}
int WINAPI wWinMain(HINSTANCE i,HINSTANCE prev,wchar_t*cmd,int show){(void)i;(void)prev;(void)cmd;(void)show;int argc;wchar_t**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=2)return 64;wchar_t p[32768];swprintf(p,32768,L"%ls\\icons.json",argv[1]);FILE*f=_wfopen(p,L"wb");if(!f)return 65;
 int ids[201];for(int i=0;i<201;i++)ids[i]=i;fprintf(f,"{\"pid\":%lu,\"icons\":[",GetCurrentProcessId());
 for(unsigned j=0;j<sizeof(ids)/sizeof(ids[0]);j++){
  SHSTOCKICONINFO s={0};s.cbSize=sizeof(s);HRESULT hr=SHGetStockIconInfo(ids[j],SHGSI_ICON|SHGSI_LARGEICON,&s);BOOL drawn=FALSE;unsigned nonzero=0;
  BITMAPINFO bi={0};bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bi.bmiHeader.biWidth=32;bi.bmiHeader.biHeight=-32;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;bi.bmiHeader.biCompression=BI_RGB;void*bits=NULL;HDC dc=CreateCompatibleDC(NULL);HBITMAP bmp=CreateDIBSection(dc,&bi,DIB_RGB_COLORS,&bits,NULL,0),old=NULL;
  if(bmp&&s.hIcon&&bits){old=SelectObject(dc,bmp);ZeroMemory(bits,4096);drawn=DrawIconEx(dc,0,0,s.hIcon,32,32,0,NULL,DI_NORMAL);GdiFlush();for(int k=0;k<1024;k++)if(((DWORD*)bits)[k])nonzero++;swprintf(p,32768,L"%ls\\stock-%d.bgra",argv[1],ids[j]);FILE*b=_wfopen(p,L"wb");if(b){fwrite(bits,1,4096,b);fclose(b);}}
  if(j)fputc(',',f);fprintf(f,"{\"id\":%d,\"hr\":%ld,\"iconIndex\":%d,\"path\":",ids[j],(long)hr,s.iIcon);quoted(f,s.szPath);fprintf(f,",\"drawn\":%s,\"nonzeroPixels\":%u}",drawn?"true":"false",nonzero);
  if(old)SelectObject(dc,old);if(bmp)DeleteObject(bmp);if(dc)DeleteDC(dc);if(s.hIcon)DestroyIcon(s.hIcon);
 }fputs("]}\n",f);fclose(f);LocalFree(argv);return 0;
}
