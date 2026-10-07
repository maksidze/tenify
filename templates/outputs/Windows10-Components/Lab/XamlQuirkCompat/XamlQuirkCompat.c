
#include <windows.h>
#include <string.h>
#include <bcrypt.h>
struct QUIRK_STATE {DWORD size,version,result,suppressions; ULONGLONG module,cache; BYTE before[8],after[8];};
__declspec(dllexport) struct QUIRK_STATE XamlQuirkState={sizeof(struct QUIRK_STATE),1};
static BOOL verifyHash(const WCHAR *path){
 BYTE expected[]={0x7a,0x2f,0xb4,0xf7,0x93,0x3a,0x8d,0x74,0x70,0x8a,0x4b,0x78,0x08,0x5b,0x7c,0x67,0x33,0x2f,0xaf,0xcc,0x9c,0xd5,0xc3,0xd2,0xd2,0x40,0xbf,0xf4,0x04,0xc4,0xb5,0x44},digest[32],buffer[65536];
 BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;BYTE *object=NULL;DWORD length=0,used=0,bytes=0;BOOL ok=FALSE;
 HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto end;
 if(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,(BYTE*)&length,sizeof(length),&used,0)<0)goto end;
 object=HeapAlloc(GetProcessHeap(),0,length);if(!object)goto end;
 if(BCryptCreateHash(algorithm,&hash,object,length,NULL,0,0)<0)goto end;
 for(;;){if(!ReadFile(file,buffer,sizeof(buffer),&bytes,NULL))goto end;if(!bytes)break;if(BCryptHashData(hash,buffer,bytes,0)<0)goto end;}
 if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)goto end;
 ok=!memcmp(digest,expected,sizeof(expected));
end: if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);if(object)HeapFree(GetProcessHeap(),0,object);CloseHandle(file);return ok;
}
static BYTE *cache;
static BOOL priorBit,applied;
static SRWLOCK lock=SRWLOCK_INIT;
__declspec(dllexport) DWORD WINAPI XamlQuirkInitialize(void *argument) {
 (void)argument; DWORD result=0; AcquireSRWLockExclusive(&lock);
 if(applied){ReleaseSRWLockExclusive(&lock);return 0;}
 WCHAR path[MAX_PATH];UINT n=GetSystemDirectoryW(path,MAX_PATH);
 if(!n||n>MAX_PATH-24){result=HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);goto end;}
 wcscat(path,L"\\Windows.UI.Xaml.dll");
 if(!verifyHash(path)){result=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);goto end;}
 HMODULE module=LoadLibraryW(path);if(!module){result=HRESULT_FROM_WIN32(GetLastError());goto end;}
 BYTE *base=(BYTE*)module;IMAGE_DOS_HEADER *dos=(void*)base;
 XamlQuirkState.module=(ULONGLONG)base;
 IMAGE_NT_HEADERS64 *nt=(void*)(base+dos->e_lfanew);
 BYTE signature[]={0x40,0x53,0x48,0x83,0xec,0x20,0x33,0xdb,0x39,0x1d,0x7e,0xcd,0xc2,0x00,0x75,0x3d,0x45,0x33,0xc9,0x4c,0x8d,0x05,0x66,0xcd};
 if(nt->FileHeader.TimeDateStamp!=742116993U||nt->OptionalHeader.SizeOfImage!=17858560U||memcmp(base+0x39eb50,signature,sizeof(signature))){result=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);goto end;}
 typedef BYTE (*BLOCK)(void);
 BLOCK block=(BLOCK)(base+0x39eb50); block(); /* Native cache initialization. */
 cache=*(BYTE**)(base+0xfcb8d0);
 XamlQuirkState.cache=(ULONGLONG)cache;XamlQuirkState.suppressions=*(DWORD*)(base+0xfcb8dc);
 if(cache!=base+0xfcd720||*(LONG*)(base+0xfcb8dc)!=0){result=HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);cache=NULL;goto end;}
 BYTE previous[8];memcpy(previous,cache,8);priorBit=(previous[4]&4)!=0;
 memcpy(XamlQuirkState.before,previous,8);
 InterlockedAnd((volatile LONG*)(cache+4),~4L);previous[4]&=~4;
 if(block()||memcmp(previous,cache,8)){
  if(priorBit)InterlockedOr((volatile LONG*)(cache+4),4);
  result=E_UNEXPECTED;cache=NULL;goto end;
 }
 applied=TRUE;
 memcpy(XamlQuirkState.after,cache,8);
 OutputDebugStringW(L"XamlQuirkCompat: native XAML cache initialized; only quirk 0x20106 (cache byte4 bit2) suppressed in this process.");
end: XamlQuirkState.result=result;ReleaseSRWLockExclusive(&lock);return result;
}
__declspec(dllexport) DWORD WINAPI XamlQuirkRestore(void *argument){
 (void)argument;AcquireSRWLockExclusive(&lock);
 if(applied&&cache){if(priorBit)InterlockedOr((volatile LONG*)(cache+4),4);else InterlockedAnd((volatile LONG*)(cache+4),~4L);applied=FALSE;}
 ReleaseSRWLockExclusive(&lock);return 0;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID p){(void)h;(void)r;(void)p;return TRUE;}
