#include <wingdi.h>
static BOOL themeContrast=TRUE;
static BOOL highContrast(){HIGHCONTRASTW contrast={0};contrast.cbSize=sizeof(contrast);if(!SystemParametersInfoW(SPI_GETHIGHCONTRAST,sizeof(contrast),&contrast,0))return TRUE;return (contrast.dwFlags&HCF_HIGHCONTRASTON)!=0;}
static DWORD themeLight=0;static BOOL themeKnown=FALSE;static NOTIFYICONDATAW lastGenuine;static BOOL lastGenuineValid;
static BOOL readSystemLight(DWORD*out){DWORD value=0,size=sizeof(value);LSTATUS s=RegGetValueW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",L"SystemUsesLightTheme",RRF_RT_REG_DWORD,NULL,&value,&size);if(s!=ERROR_SUCCESS||size!=4)return FALSE;*out=value!=0;return TRUE;}
// Source pixels remain immutable. Only white/gray monochrome glyph pixels become
// black on a light taskbar. Alpha and colored status decorations remain exact.
static unsigned themePixels(BYTE*dst,const BYTE*src,size_t count){unsigned changed=0;for(size_t i=0;i<count;i++){BYTE b=src[i*4],g=src[i*4+1],r=src[i*4+2],a=src[i*4+3];memcpy(dst+i*4,src+i*4,4);if(a&&abs((int)b-g)<=2&&abs((int)g-r)<=2&&(r>=a-3||r>=240)){dst[i*4]=dst[i*4+1]=dst[i*4+2]=0;changed++;}}return changed;}
static HICON lightIcon(HICON source){ICONINFO info={0};if(!source||!GetIconInfo(source,&info))return NULL;HICON output=NULL;HDC dc=NULL;BYTE*src=NULL;HBITMAP dib=NULL;void*bits=NULL;BITMAP bm={0};
 if(!info.hbmColor||!GetObjectW(info.hbmColor,sizeof(bm),&bm)||bm.bmWidth<=0||bm.bmHeight<=0||bm.bmWidth>512||bm.bmHeight>512)goto done;
 BITMAPINFO bi={0};bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bi.bmiHeader.biWidth=bm.bmWidth;bi.bmiHeader.biHeight=-bm.bmHeight;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;bi.bmiHeader.biCompression=BI_RGB;
 size_t size=(size_t)bm.bmWidth*bm.bmHeight*4;src=HeapAlloc(GetProcessHeap(),0,size);dc=GetDC(NULL);if(!src||!dc||GetDIBits(dc,info.hbmColor,0,bm.bmHeight,src,&bi,DIB_RGB_COLORS)!=(UINT)bm.bmHeight)goto done;
 dib=CreateDIBSection(dc,&bi,DIB_RGB_COLORS,&bits,NULL,0);if(!dib||!bits)goto done;
 if(!themePixels(bits,src,(size_t)bm.bmWidth*bm.bmHeight))goto done;
 ICONINFO adapted=info;adapted.hbmColor=dib;output=CreateIconIndirect(&adapted);
 done:if(dc)ReleaseDC(NULL,dc);if(src)HeapFree(GetProcessHeap(),0,src);if(dib)DeleteObject(dib);if(info.hbmMask)DeleteObject(info.hbmMask);if(info.hbmColor)DeleteObject(info.hbmColor);return output;
}
static HICON themeIcon(HICON source,DWORD light,BOOL contrast){return light&&!contrast?lightIcon(source):NULL;}
static LSTATUS(WINAPI*realNetworkReg)(HKEY,LPCWSTR,LPCWSTR,DWORD,LPDWORD,PVOID,LPDWORD);
static LSTATUS WINAPI networkReg(HKEY key,LPCWSTR sub,LPCWSTR value,DWORD flags,LPDWORD type,PVOID data,LPDWORD size){LSTATUS result=realNetworkReg(key,sub,value,flags,type,data,size);DWORD error=GetLastError();if(result==ERROR_FILE_NOT_FOUND&&key==HKEY_LOCAL_MACHINE&&sub&&value&&!_wcsicmp(sub,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Settings\\Network")&&!wcscmp(value,L"ReplaceVan")&&data&&size&&*size>=sizeof(DWORD)&&(flags&RRF_RT_REG_DWORD)){*(DWORD*)data=0;*size=sizeof(DWORD);if(type)*type=REG_DWORD;result=ERROR_SUCCESS;}SetLastError(error);return result;}
static BOOL installNetworkReg(HMODULE module){void**slot=(void**)((BYTE*)module+0x48980);HMODULE registry=LoadLibraryW(L"api-ms-win-core-registry-l1-1-0.dll");void*expected=registry?(void*)GetProcAddress(registry,"RegGetValueW"):NULL;if(!expected||*slot!=expected)return FALSE;DWORD old=0,unused=0;realNetworkReg=*slot;if(!VirtualProtect(slot,8,PAGE_READWRITE,&old))return FALSE;*slot=networkReg;return VirtualProtect(slot,8,old,&unused)&&*slot==(void*)networkReg;}
