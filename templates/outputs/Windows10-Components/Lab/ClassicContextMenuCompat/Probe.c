#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <stdio.h>
#include <wchar.h>
static LONG calls;
static BOOL WINAPI cancelMenu(HMENU menu,UINT flags,int x,int y,HWND owner,LPTPMPARAMS params){(void)flags;(void)x;(void)y;(void)owner;(void)params;InterlockedIncrement(&calls);return 0;}
static BOOL WINAPI cancelMenuOld(HMENU menu,UINT flags,int x,int y,int reserved,HWND owner,const RECT*rect){(void)reserved;(void)rect;return cancelMenu(menu,flags,x,y,owner,NULL);}
static int hook(HMODULE module,const char*name,void*target){
 BYTE*b=(BYTE*)module;IMAGE_NT_HEADERS64*n=(void*)(b+((IMAGE_DOS_HEADER*)b)->e_lfanew);
 IMAGE_IMPORT_DESCRIPTOR*d=(void*)(b+n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);int count=0;
 for(;d->Name;d++){if(!d->OriginalFirstThunk)continue;IMAGE_THUNK_DATA64 *names=(void*)(b+d->OriginalFirstThunk),*iat=(void*)(b+d->FirstThunk);
  for(;names->u1.AddressOfData;names++,iat++){if(IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal))continue;IMAGE_IMPORT_BY_NAME*imp=(void*)(b+names->u1.AddressOfData);if(strcmp((char*)imp->Name,name))continue;
   DWORD old;if(!VirtualProtect(&iat->u1.Function,8,PAGE_READWRITE,&old))return -1;InterlockedExchangePointer((void**)&iat->u1.Function,target);DWORD ignored;VirtualProtect(&iat->u1.Function,8,old,&ignored);count++;
  }
 }return count;
}
static void pump(DWORD ms){ULONGLONG end=GetTickCount64()+ms;MSG m;do{while(PeekMessageW(&m,NULL,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}Sleep(20);}while(GetTickCount64()<end);}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,LPWSTR line,int show){
 (void)previous;(void)line;(void)show;int argc;LPWSTR*argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(argc!=4)return 2;
 FILE*f=_wfopen(argv[3],L"w");if(!f)return 3;setvbuf(f,NULL,_IONBF,0);
 WCHAR desktopName[128];swprintf(desktopName,128,L"CodexClassicMenuProbe_%lu",GetCurrentProcessId());HDESK desktop=CreateDesktopW(desktopName,NULL,NULL,0,DESKTOP_CREATEWINDOW|DESKTOP_CREATEMENU|DESKTOP_READOBJECTS|DESKTOP_WRITEOBJECTS|DESKTOP_ENUMERATE|DESKTOP_SWITCHDESKTOP,NULL);
 if(!desktop||!SetThreadDesktop(desktop)){fprintf(f,"desktop error=%lu\n",GetLastError());return 4;}
 HRESULT hr=CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);fprintf(f,"COM=%08lx\n",hr);if(FAILED(hr))return 5;
 HWND parent=CreateWindowExW(0,L"STATIC",L"Owned isolated classic menu probe",WS_OVERLAPPEDWINDOW,0,0,640,480,NULL,NULL,instance,NULL);if(!parent)return 6;
 IExplorerBrowser*browser=NULL;hr=CoCreateInstance(&CLSID_ExplorerBrowser,NULL,CLSCTX_INPROC_SERVER,&IID_IExplorerBrowser,(void**)&browser);fprintf(f,"Factory=%08lx\n",hr);if(FAILED(hr))return 7;
 RECT rect={0,0,640,480};FOLDERSETTINGS folder={FVM_DETAILS,FWF_NONE};hr=IExplorerBrowser_Initialize(browser,parent,&rect,&folder);fprintf(f,"Initialize=%08lx\n",hr);if(FAILED(hr))return 8;
 IExplorerBrowser_SetOptions(browser,EBO_NOTRAVELLOG|EBO_NOBORDER);
 PIDLIST_ABSOLUTE pidl=NULL;hr=SHParseDisplayName(argv[2],NULL,&pidl,0,NULL);if(SUCCEEDED(hr))hr=IExplorerBrowser_BrowseToIDList(browser,pidl,SBSP_ABSOLUTE);fprintf(f,"Browse=%08lx\n",hr);CoTaskMemFree(pidl);ShowWindow(parent,SW_SHOWNOACTIVATE);pump(1500);
 IShellView*view=NULL;hr=IExplorerBrowser_GetCurrentView(browser,&IID_IShellView,(void**)&view);fprintf(f,"GetView=%08lx\n",hr);if(FAILED(hr))return 9;
 HWND viewWindow=NULL;IShellView_GetWindow(view,&viewWindow);WCHAR cls[128];GetClassNameW(viewWindow,cls,128);fprintf(f,"View=%p class=%ls\n",viewWindow,cls);
 HMODULE shell=GetModuleHandleW(L"shell32.dll");int hooks=hook(shell,"TrackPopupMenuEx",cancelMenu)+hook(shell,"TrackPopupMenu",cancelMenuOld);fprintf(f,"CancelHooks=%d\n",hooks);if(hooks<1)return 10;
 HMODULE helper=LoadLibraryW(argv[1]);if(!helper)return 11;DWORD(WINAPI*init)(void*)=(void*)GetProcAddress(helper,"ClassicContextInitialize");DWORD(WINAPI*restore)(void*)=(void*)GetProcAddress(helper,"ClassicContextRestore");
 DWORD result=init(NULL);fprintf(f,"Patch=%lu\n",result);if(result)return 12;
 /* Invoke only our genuine CDefView after proving the exact interface layout.
  * This avoids input-desktop restrictions; no messages/input reach user windows. */
 fprintf(f,"ViewTableRva=%llx GetWindowRva=%llx\n",(unsigned long long)((BYTE*)view->lpVtbl-(BYTE*)shell),(unsigned long long)((BYTE*)view->lpVtbl->GetWindow-(BYTE*)shell));
 if((BYTE*)view->lpVtbl!=(BYTE*)shell+0x5ab6f8||(BYTE*)view->lpVtbl->GetWindow!=(BYTE*)shell+0x123bc0||*(HWND*)((BYTE*)view+0x2b8)!=viewWindow)return 14;
 IContextMenu*context=NULL;hr=IShellView_GetItemObject(view,SVGIO_BACKGROUND,&IID_IContextMenu,(void**)&context);fprintf(f,"GenuineBackgroundContext=%08lx object=%p\n",hr,context);
 typedef HRESULT(WINAPI*Popup)(void*,IUnknown*,UINT,POINT,int);POINT at={40,50};
 if(SUCCEEDED(hr)&&context){hr=((Popup)((BYTE*)shell+0x2b20a4))(view,(IUnknown*)context,0x20,at,0);fprintf(f,"NativePopupResult=%08lx\n",hr);IContextMenu_Release(context);}
 WCHAR selectedPath[32768];swprintf(selectedPath,32768,L"%ls\\probe.txt",argv[2]);pidl=NULL;hr=SHParseDisplayName(selectedPath,NULL,&pidl,0,NULL);
 if(SUCCEEDED(hr)){hr=IShellView_SelectItem(view,ILFindLastID(pidl),SVSI_SELECT|SVSI_FOCUSED|SVSI_DESELECTOTHERS|SVSI_ENSUREVISIBLE);CoTaskMemFree(pidl);}fprintf(f,"SelectOwnedFixture=%08lx\n",hr);pump(100);
 context=NULL;hr=IShellView_GetItemObject(view,SVGIO_SELECTION,&IID_IContextMenu,(void**)&context);fprintf(f,"GenuineSelectionContext=%08lx object=%p\n",hr,context);
 if(SUCCEEDED(hr)&&context){hr=((Popup)((BYTE*)shell+0x2b20a4))(view,(IUnknown*)context,0x90,at,0);fprintf(f,"SelectionNativePopupResult=%08lx\n",hr);IContextMenu_Release(context);}
 pump(200);fprintf(f,"ClassicNativePopupCalls=%ld; hooks cancel all menus, no commands executed\n",calls);
 DWORD restored=restore(NULL);fprintf(f,"Restore=%lu\n",restored);
 BYTE*site=(BYTE*)shell+0x2b2362;BYTE saved=*site;DWORD protection,ignored;VirtualProtect(site,13,PAGE_EXECUTE_READWRITE,&protection);*site=0x90;DWORD rejected=init(NULL);BOOL untouched=*site==0x90;*site=saved;FlushInstructionCache(GetCurrentProcess(),site,13);VirtualProtect(site,13,protection,&ignored);fprintf(f,"WrongByteGuard=%lu untouched=%d\n",rejected,untouched);
 IShellView_Release(view);IExplorerBrowser_Destroy(browser);IExplorerBrowser_Release(browser);DestroyWindow(parent);CoUninitialize();fclose(f);LocalFree(argv);return calls==2&&!restored&&rejected==4&&untouched?0:13;
}
