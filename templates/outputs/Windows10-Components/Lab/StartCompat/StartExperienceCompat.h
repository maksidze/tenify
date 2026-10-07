/* Process-local ABI adapter following ExplorerPatcher StartExperience.cpp/.h.
 * Source: https://github.com/valinet/ExplorerPatcher, GPL-2.0.
 * The obsolete ShellModeChanged subscription is ignored as in that source.
 */
static const GUID experienceStaticsId={0xfb2e3e59,0xb442,0x4b5b,{0x91,0x28,0x23,0x19,0xbf,0x8d,0xe3,0xb0}};
static const GUID experienceId={0x4c4d0c66,0x5bd5,0xfd8c,{0x61,0x7f,0x3c,0x77,0x78,0xf4,0x6b,0xb6}};
static const GUID inspectableId={0xaf86e2e0,0xb12d,0x4c6a,{0x9c,0x5a,0xd7,0xaa,0x65,0x10,0x1e,0x90}};
static const GUID unknownId={0,0,0,{0xc0,0,0,0,0,0,0,0x46}};
typedef struct ExperienceAdapter {void **vtable;LONG references;void *inner;BOOL statics;} ExperienceAdapter;
static HRESULT wrapExperience(void **value,BOOL statics);
static ULONG WINAPI adapterAddRef(ExperienceAdapter *self){return InterlockedIncrement(&self->references);}
static ULONG WINAPI adapterRelease(ExperienceAdapter *self){LONG count=InterlockedDecrement(&self->references);if(!count){release(self->inner);HeapFree(GetProcessHeap(),0,self);}return count;}
static HRESULT WINAPI adapterQuery(ExperienceAdapter *self,const GUID *iid,void **out){
 if(!out)return E_POINTER;*out=NULL;if(IsEqualGUID(iid,&unknownId)||IsEqualGUID(iid,&inspectableId)||IsEqualGUID(iid,self->statics?&experienceStaticsId:&experienceId)){*out=self;adapterAddRef(self);return S_OK;}return ((PFN_QI)slot(self->inner,0))(self->inner,iid,out);
}
static HRESULT WINAPI adapterIids(ExperienceAdapter *self,ULONG *count,GUID **ids){typedef HRESULT(WINAPI *FN)(void*,ULONG*,GUID**);return ((FN)slot(self->inner,3))(self->inner,count,ids);}
static HRESULT WINAPI adapterClass(ExperienceAdapter *self,W10_HSTRING *name){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING*);return ((FN)slot(self->inner,4))(self->inner,name);}
static HRESULT WINAPI adapterTrust(ExperienceAdapter *self,int *trust){typedef HRESULT(WINAPI *FN)(void*,int*);return ((FN)slot(self->inner,5))(self->inner,trust);}
static HRESULT WINAPI adapterGetCurrent(ExperienceAdapter *self,void **out){HRESULT hr=((PFN_GET)slot(self->inner,6))(self->inner,out);return SUCCEEDED(hr)?wrapExperience(out,FALSE):hr;}
static HRESULT WINAPI adapterGetIfNone(ExperienceAdapter *self,void **out){HRESULT hr=((PFN_GET)slot(self->inner,7))(self->inner,out);return SUCCEEDED(hr)?wrapExperience(out,FALSE):hr;}
static HRESULT WINAPI adapterBackground(ExperienceAdapter *self,void *image,int mode,LONGLONG *value){typedef HRESULT(WINAPI *FN)(void*,void*,int,LONGLONG*);return ((FN)slot(self->inner,6))(self->inner,image,mode,value);}
static HRESULT WINAPI adapterHandle(ExperienceAdapter *self,ULONGLONG *handle){typedef HRESULT(WINAPI *FN)(void*,ULONGLONG*);return ((FN)slot(self->inner,7))(self->inner,handle);}
static HRESULT WINAPI adapterPromote(ExperienceAdapter *self,void *apps){typedef HRESULT(WINAPI *FN)(void*,void*);return ((FN)slot(self->inner,8))(self->inner,apps);}
static HRESULT WINAPI adapterAddAnimation(ExperienceAdapter *self,void *handler,LONGLONG *token){typedef HRESULT(WINAPI *FN)(void*,void*,LONGLONG*);return ((FN)slot(self->inner,9))(self->inner,handler,token);}
static HRESULT WINAPI adapterRemoveAnimation(ExperienceAdapter *self,LONGLONG token){typedef HRESULT(WINAPI *FN)(void*,LONGLONG);return ((FN)slot(self->inner,10))(self->inner,token);}
static HRESULT WINAPI adapterAddShellMode(ExperienceAdapter *self,void *handler,LONGLONG *token){(void)self;(void)handler;if(!token)return E_POINTER;*token=0;trace(L"[StartCompat] Obsolete ShellModeChanged subscription bypassed");return S_OK;}
static HRESULT WINAPI adapterRemoveShellMode(ExperienceAdapter *self,LONGLONG token){(void)self;(void)token;return S_OK;}
static void *staticsVtable[]={adapterQuery,adapterAddRef,adapterRelease,adapterIids,adapterClass,adapterTrust,adapterGetCurrent,adapterGetIfNone};
static void *experienceVtable[]={adapterQuery,adapterAddRef,adapterRelease,adapterIids,adapterClass,adapterTrust,adapterBackground,adapterHandle,adapterPromote,adapterAddAnimation,adapterRemoveAnimation,adapterAddShellMode,adapterRemoveShellMode};
static HRESULT wrapExperience(void **value,BOOL statics){
 if(!value||!*value)return E_POINTER;ExperienceAdapter *object=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*object));if(!object){release(*value);*value=NULL;return E_OUTOFMEMORY;}object->vtable=statics?staticsVtable:experienceVtable;object->references=1;object->inner=*value;object->statics=statics;*value=object;return S_OK;
}
