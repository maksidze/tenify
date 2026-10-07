struct STATE{DWORD size,version,result,active,fullTheme,fallback8,fallback11,passed,tracked,rejected,failures,restores,quarantined,dpiStable,nativeHeaderFallbacks,generationRejected;ULONGLONG oldFile,nativeFile,slots[2],original[2],replacement[2],processDpiBefore,processDpiAfter,threadDpiBefore,threadDpiAfter;};
using InitFn=DWORD(WINAPI*)(void*);using DpiFn=HTHEME(WINAPI*)(HWND,PCWSTR,UINT);using ColorFn=HRESULT(WINAPI*)(HTHEME,int,int,int,COLORREF*);
static HMODULE helper;static InitFn initHybrid,restoreHybrid;static STATE*stateHybrid;static bool hybridOkay=true,capacityMode,generationMode;static unsigned before8,before11;
static void check(const char*name,bool ok){fprintf(logFile,"check=%s pass=%d\n",name,ok);fflush(logFile);hybridOkay=hybridOkay&&ok;}
static void setSlot(void**slot,void*expect,void*value){DWORD old,ignore;if(!VirtualProtect(slot,8,PAGE_READWRITE,&old)||InterlockedCompareExchangePointer(slot,value,expect)!=expect)ExitProcess(0xdec7);if(!VirtualProtect(slot,8,old,&ignore))ExitProcess(0xdec8);}
static DWORD WINAPI otherThread(void*){
 auto dpi=(DpiFn)*(void**)stateHybrid->slots[0];auto color=(ColorFn)*(void**)stateHybrid->slots[1];
 HTHEME h=dpi(nullptr,L"ItemsViewAccessible::Header",96);COLORREF c=0;HRESULT hr=h?color(h,1,11,3803,&c):E_FAIL;if(h)CloseThemeData(h);return SUCCEEDED(hr)?0:1;
}
static bool fixtureInstall(){
 WCHAR path[32768];GetModuleFileNameW(nullptr,path,32768);*wcsrchr(path,L'\\')=0;wcscat(path,L"\\ThemeFolderHybrid.dll");helper=LoadLibraryW(path);if(!helper)return false;
 auto production=(InitFn)GetProcAddress(helper,"ThemeFolderHybridInitialize");initHybrid=(InitFn)GetProcAddress(helper,"ThemeFolderHybridFixtureInitialize");restoreHybrid=(InitFn)GetProcAddress(helper,"ThemeFolderHybridRestore");stateHybrid=(STATE*)GetProcAddress(helper,"ThemeFolderHybridState");
 if(!production||!initHybrid||!restoreHybrid||!stateHybrid)return false;
 check("schema",stateHybrid->size==sizeof(STATE));check("wrongHost",production(nullptr)==ERROR_ACCESS_DENIED);
 HMODULE ux=LoadLibraryExW(L"C:\\Windows\\System32\\uxtheme.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);BYTE*guard=(BYTE*)ux+0x4720;BYTE saved=*guard;DWORD prev,ignore;
 if(!VirtualProtect(guard,1,PAGE_EXECUTE_READWRITE,&prev))return false;*guard=saved^1;FlushInstructionCache(GetCurrentProcess(),guard,1);VirtualProtect(guard,1,prev,&ignore);
 check("wrongInstructionRefused",initHybrid(nullptr)==ERROR_REVISION_MISMATCH&&!stateHybrid->fullTheme);
 if(!VirtualProtect(guard,1,PAGE_EXECUTE_READWRITE,&prev))return false;*guard=saved;FlushInstructionCache(GetCurrentProcess(),guard,1);VirtualProtect(guard,1,prev,&ignore);
 DWORD result=initHybrid(nullptr);fprintf(logFile,"initialize=%lu state=%lu active=%lu fullTheme=%lu dpiStable=%lu\n",result,stateHybrid->result,stateHybrid->active,stateHybrid->fullTheme,stateHybrid->dpiStable);fflush(logFile);
 if(result)return false;check("initialized",stateHybrid->active&&stateHybrid->fullTheme&&stateHybrid->dpiStable);check("idempotent",initHybrid(nullptr)==0);
 auto slot=(void**)stateHybrid->slots[1];setSlot(slot,(void*)stateHybrid->replacement[1],(void*)production);
 check("foreignReinitialize",initHybrid(nullptr)==ERROR_BUSY);check("foreignRestoreRefused",restoreHybrid(nullptr)==ERROR_BUSY&&stateHybrid->active&&stateHybrid->fullTheme);
 setSlot(slot,(void*)production,(void*)stateHybrid->replacement[1]);check("repairedIdempotent",initHybrid(nullptr)==0);
 auto dpi=(DpiFn)*(void**)stateHybrid->slots[0];auto color=(ColorFn)*(void**)stateHybrid->slots[1];
 HTHEME h=dpi(nullptr,L"ItemsViewAccessible::Header",96),other=dpi(nullptr,L"Button",96);check("realHandles",h&&other);
 auto explicitData=(HTHEME(WINAPI*)(void*,HWND,LPCWSTR,int))GetProcAddress(GetModuleHandleW(L"uxtheme.dll"),MAKEINTRESOURCEA(16));HTHEME native=explicitData((void*)stateHybrid->nativeFile,nullptr,L"ItemsViewAccessible::Header",1);
 struct Output{DWORD before;COLORREF color;DWORD after;};struct Case{HTHEME handle;int part,st,prop;bool fallback;};
 Case cases[]={{h,1,8,3803,true},{h,1,11,3803,true},{h,1,0,3803,false},{h,2,11,3803,false},{h,1,11,3802,false},{other,1,11,3803,false},{nullptr,1,11,3803,false}};
 for(unsigned i=0;i<7;i++){auto c=cases[i];Output a={0x12345678,0xdeadbeef,0xabcdef12},b=a;DWORD hits=stateHybrid->fallback8+stateHybrid->fallback11;HRESULT want=GetThemeColor(c.fallback?native:c.handle,c.part,c.st,c.prop,&a.color),got=color(c.handle,c.part,c.st,c.prop,&b.color);
  bool ok=want==got&&a.color==b.color&&b.before==0x12345678&&b.after==0xabcdef12&&stateHybrid->fallback8+stateHybrid->fallback11-hits==(c.fallback?1:0);fprintf(logFile,"queryCase=%u pass=%d expected=%08lx actual=%08lx\n",i,ok,want,got);hybridOkay=hybridOkay&&ok;
 }
 if(native)CloseThemeData(native);if(h)CloseThemeData(h);if(other)CloseThemeData(other);
 HANDLE thread=CreateThread(nullptr,0,otherThread,nullptr,0,nullptr);if(!thread)return false;
 if(WaitForSingleObject(thread,2000)!=WAIT_OBJECT_0)ExitProcess(0xdec9);DWORD exit=1;GetExitCodeThread(thread,&exit);CloseHandle(thread);check("otherThreadGenuineColor",exit==0);
 if(capacityMode){auto capacity=(InitFn)GetProcAddress(helper,"ThemeFolderHybridFixtureSetCapacity");check("forceCapacity0",capacity&&capacity(nullptr)==0);HTHEME n=dpi(nullptr,L"ItemsViewAccessible::Header",96);void*backing=nullptr;auto from=(HRESULT(WINAPI*)(HTHEME,void**))GetProcAddress(GetModuleHandleW(L"uxtheme.dll"),MAKEINTRESOURCEA(17));check("capacityRealNativeHandle",n&&SUCCEEDED(from(n,&backing))&&backing==(void*)stateHybrid->nativeFile);if(n)CloseThemeData(n);}
 if(generationMode){
  HTHEME beforeReload=dpi(nullptr,L"ItemsViewAccessible::Header",96);
  struct P{DWORD Size,Reserved04;PCWSTR Path,Color,SizeName;DWORD Reserved20,Dpi,ConnectedDpi[7],Flags,HighContrast,Reserved4c;void*ThemeFile;};P p={};p.Size=sizeof(p);p.Path=L"C:\\Windows\\Resources\\Themes\\aero\\aero.msstyles";p.Color=L"NormalColor";p.SizeName=L"NormalSize";
  auto reload=(HRESULT(WINAPI*)(P*))GetProcAddress(GetModuleHandleW(L"uxtheme.dll"),MAKEINTRESOURCEA(127));check("genuineForeignGeneration",SUCCEEDED(reload(&p))&&p.ThemeFile);check("reinitPreservesForeignTheme",initHybrid(nullptr)==ERROR_BUSY);check("restorePreservesForeignTheme",restoreHybrid(nullptr)==ERROR_BUSY&&stateHybrid->active);
  for(int i=0;i<2;i++)check("foreignGenerationIatUnchanged",*(void**)stateHybrid->slots[i]==(void*)stateHybrid->replacement[i]);
  Output expected={0x12345678,0xdeadbeef,0xabcdef12},actual=expected;DWORD hits=stateHybrid->fallback8+stateHybrid->fallback11;
  DWORD rejected=stateHybrid->generationRejected;HRESULT got=color(beforeReload,1,11,3803,&actual.color);
  check("foreignStaleHandleRejectedBeforeNative",got==E_HANDLE&&actual.color==expected.color&&actual.before==0x12345678&&actual.after==0xabcdef12&&stateHybrid->fallback8+stateHybrid->fallback11==hits&&stateHybrid->generationRejected==rejected+1);
  // Do not dereference/close the stale value after forced127 invalidation. This
  // exact bounded disposable process now exits; its kernel/resources are reclaimed.
 }
 before8=stateHybrid->fallback8;before11=stateHybrid->fallback11;return hybridOkay;
}
static bool fixtureRestore(){
 if(!stateHybrid)return false;
 fprintf(logFile,"browserFallback8=%lu browserFallback11=%lu tracked=%lu failures=%lu\n",stateHybrid->fallback8-before8,stateHybrid->fallback11-before11,stateHybrid->tracked,stateHybrid->failures);
 if(generationMode){check("foreignGenerationNoFallback",stateHybrid->fallback8==before8&&stateHybrid->fallback11==before11);check("foreignRestoreStillRefused",restoreHybrid(nullptr)==ERROR_BUSY);WCHAR c[32768];check("foreignThemeStillNative",SUCCEEDED(GetCurrentThemeName(c,32768,nullptr,0,nullptr,0))&&!_wcsicmp(c,L"C:\\Windows\\Resources\\Themes\\aero\\aero.msstyles"));fprintf(logFile,"generationResourcesRetainedUntilOwnProcessExit=1 FIXTURE_PASS=%d\n",hybridOkay);return hybridOkay;}
 check("browserTwoMissingStatesOrNativeCapacity",capacityMode?(stateHybrid->nativeHeaderFallbacks>=2&&stateHybrid->fallback8==before8&&stateHybrid->fallback11==before11):(stateHybrid->fallback8-before8==1&&stateHybrid->fallback11-before11==1));
 DWORD r=restoreHybrid(nullptr);check("restore",r==0&&!stateHybrid->active&&!stateHybrid->fullTheme);
 for(int i=0;i<2;i++)check("slotOriginal",*(void**)stateHybrid->slots[i]==(void*)stateHybrid->original[i]);
 WCHAR current[32768],color[100],size[100];HRESULT hr=GetCurrentThemeName(current,32768,color,100,size,100);check("nativeThemeRestored",SUCCEEDED(hr)&&!_wcsicmp(current,L"C:\\Windows\\Resources\\Themes\\aero\\aero.msstyles"));
 check("restoreIdempotent",restoreHybrid(nullptr)==0);fprintf(logFile,"FIXTURE_PASS=%d\n",hybridOkay);fflush(logFile);return hybridOkay;
}
