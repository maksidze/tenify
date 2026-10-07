#define wWinMain FactoryProbeEntry
#include "../NetworkTrayCompat/NetworkFactoryProbe.c"
#undef wWinMain

#include <bcrypt.h>
static FILE*networkTrace;
static GUID privateIconGuid;
static volatile LONG realAddSucceeded;
static BOOL privateGuid(void){WCHAR path[32768];DWORD n=GetModuleFileNameW(NULL,path,32768);if(!n||n>=32768)return FALSE;CharUpperBuffW(path,n);BCRYPT_ALG_HANDLE algorithm=NULL;BYTE bytes[32];if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)return FALSE;NTSTATUS status=BCryptHash(algorithm,NULL,0,(BYTE*)path,n*2,bytes,32);BCryptCloseAlgorithmProvider(algorithm,0);if(status<0)return FALSE;memcpy(&privateIconGuid,bytes,16);privateIconGuid.Data3=(privateIconGuid.Data3&0x0fff)|0x5000;privateIconGuid.Data4[0]=(privateIconGuid.Data4[0]&0x3f)|0x80;return TRUE;}
static BOOL(WINAPI*realNotify)(DWORD,PNOTIFYICONDATAW);
static const GUID networkGuid={0x7820ae74,0x23e3,0x4229,{0x82,0xc1,0xe4,0x1c,0xb6,0x7d,0x5b,0x9c}};
static BOOL WINAPI privateNotify(DWORD message,PNOTIFYICONDATAW data){
 NOTIFYICONDATAW adapted={0};PNOTIFYICONDATAW passed=data;BOOL changed=FALSE;
 if(data&&data->cbSize==sizeof(NOTIFYICONDATAW)&&(data->uFlags&NIF_GUID)&&!memcmp(&data->guidItem,&networkGuid,sizeof(GUID))){adapted=*data;adapted.guidItem=privateIconGuid;passed=&adapted;changed=TRUE;}
 BOOL result=realNotify(message,passed);DWORD error=GetLastError();
 if(changed&&message==NIM_ADD&&result)InterlockedExchange(&realAddSucceeded,1);
 if(networkTrace)fprintf(networkTrace,"GenuineNotify msg=%lu return=%d privateNetworkGuid=%d\n",message,result,changed);
 SetLastError(error);return result;
}
static BOOL installPrivateNotify(HMODULE module){
 void**notify=(void**)((BYTE*)module+0x48490);HMODULE shell=GetModuleHandleW(L"shell32.dll");
 void*expected=shell?(void*)GetProcAddress(shell,"Shell_NotifyIconW"):NULL;
 if(!expected||*notify!=expected)return FALSE;
 DWORD old=0,unused=0;realNotify=*notify;
 if(!VirtualProtect(notify,sizeof(void*),PAGE_READWRITE,&old))return FALSE;
 *notify=privateNotify;
 if(!VirtualProtect(notify,sizeof(void*),old,&unused))return FALSE;
 return *notify==(void*)privateNotify;
}

static NOTIFYICONDATAW captured;static DWORD capturedMessage;static BOOL answer;
static BOOL WINAPI ownNotify(DWORD m,PNOTIFYICONDATAW d){captured=*d;capturedMessage=m;SetLastError(123);return answer;}
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){
 NOTIFYICONDATAW input={0};input.cbSize=sizeof(input);input.uFlags=NIF_GUID|NIF_ICON;input.guidItem=networkGuid;input.uID=1234;input.hWnd=(HWND)0x456;
 realNotify=ownNotify;if(!privateGuid())return 1;GUID first=privateIconGuid;if(!privateGuid()||memcmp(&first,&privateIconGuid,16))return 2;
 NOTIFYICONDATAW saved=input;answer=FALSE;if(privateNotify(NIM_ADD,&input)||realAddSucceeded||GetLastError()!=123)return 3;
 answer=TRUE;if(!privateNotify(NIM_ADD,&input)||!realAddSucceeded||memcmp(&captured.guidItem,&first,16)||memcmp(&input,&saved,sizeof(input)))return 4;
 if(!privateNotify(NIM_DELETE,&input)||capturedMessage!=NIM_DELETE||memcmp(&captured.guidItem,&first,16))return 5;
 input.guidItem.Data1++;saved=input;if(!privateNotify(NIM_MODIFY,&input)||memcmp(&captured,&saved,sizeof(input)))return 6;
 input=saved;input.cbSize--;saved=input;if(!privateNotify(NIM_MODIFY,&input)||memcmp(&captured,&saved,sizeof(input)))return 7;
 return GetConsoleWindow()!=NULL?8:0;
}
