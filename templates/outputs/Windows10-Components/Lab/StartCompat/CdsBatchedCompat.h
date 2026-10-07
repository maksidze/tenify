/* Process-local old ICDSTilePropertiesBatched adapter. PDB-proven insertion:
   host slot 6 is get_PropertyKinds; all 19 old methods shift by one.
   Only this class's six native QI vtable entries are hooked in the owned child. */
static const GUID oldBatchedId={0xd08a9559,0xb4cc,0x49af,{0x98,0xbb,0x23,0x66,0xc7,0x44,0x94,0x02}};
static const GUID hostBatchedId={0x0bf1fd14,0xa677,0x4159,{0x83,0x85,0x0b,0xce,0x43,0x47,0x35,0x4a}};
typedef struct BatchedAdapter {void **vtable;LONG references;void *inner;} BatchedAdapter;
static PFN_QI batchedOriginal[6];
static HRESULT wrapBatched(void *inner,void **out);
static ULONG WINAPI batchedAddRef(BatchedAdapter *self){return InterlockedIncrement(&self->references);}
static ULONG WINAPI batchedRelease(BatchedAdapter *self){LONG n=InterlockedDecrement(&self->references);if(!n){release(self->inner);HeapFree(GetProcessHeap(),0,self);}return n;}
static HRESULT WINAPI batchedQuery(BatchedAdapter *self,const GUID *iid,void **out){if(!out)return E_POINTER;*out=NULL;if(IsEqualGUID(iid,&oldBatchedId)||IsEqualGUID(iid,&inspectableId)){batchedAddRef(self);*out=self;return S_OK;}return ((PFN_QI)slot(self->inner,0))(self->inner,iid,out);}
static HRESULT WINAPI batchedIids(BatchedAdapter *self,ULONG *count,GUID **ids){(void)self;if(!count||!ids)return E_POINTER;typedef void*(WINAPI *ALLOC)(SIZE_T);ALLOC allocate=(ALLOC)GetProcAddress(GetModuleHandleW(L"combase.dll"),"CoTaskMemAlloc");*count=0;*ids=allocate(sizeof(GUID));if(!*ids)return E_OUTOFMEMORY;**ids=oldBatchedId;*count=1;return S_OK;}
static HRESULT WINAPI batchedClass(BatchedAdapter *self,void **name){return ((PFN_GET)slot(self->inner,4))(self->inner,name);}
static HRESULT WINAPI batchedTrust(BatchedAdapter *self,int *trust){typedef HRESULT(WINAPI *FN)(void*,int*);return ((FN)slot(self->inner,5))(self->inner,trust);}
static HRESULT WINAPI batched6(BatchedAdapter *self,void **value){typedef HRESULT(WINAPI *FN)(void*,void**);return ((FN)slot(self->inner,7))(self->inner,value);}
static HRESULT WINAPI batched7(BatchedAdapter *self,W10_HSTRING key,BYTE *value){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING,BYTE*);return ((FN)slot(self->inner,8))(self->inner,key,value);}
static HRESULT WINAPI batched8(BatchedAdapter *self,W10_HSTRING key,BYTE *value){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING,BYTE*);return ((FN)slot(self->inner,9))(self->inner,key,value);}
static HRESULT WINAPI batched9(BatchedAdapter *self,W10_HSTRING key,BYTE *value){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING,BYTE*);return ((FN)slot(self->inner,10))(self->inner,key,value);}
static HRESULT WINAPI batched10(BatchedAdapter *self,W10_HSTRING key,void **value){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING,void**);return ((FN)slot(self->inner,11))(self->inner,key,value);}
static HRESULT WINAPI batched11(BatchedAdapter *self,W10_HSTRING key,void **value){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING,void**);return ((FN)slot(self->inner,12))(self->inner,key,value);}
static HRESULT WINAPI batched12(BatchedAdapter *self,W10_HSTRING key,void **value){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING,void**);return ((FN)slot(self->inner,13))(self->inner,key,value);}
static HRESULT WINAPI batched13(BatchedAdapter *self,void **value){typedef HRESULT(WINAPI *FN)(void*,void**);return ((FN)slot(self->inner,14))(self->inner,value);}
static HRESULT WINAPI batched14(BatchedAdapter *self,void **value){typedef HRESULT(WINAPI *FN)(void*,void**);return ((FN)slot(self->inner,15))(self->inner,value);}
static HRESULT WINAPI batched15(BatchedAdapter *self,void **value){typedef HRESULT(WINAPI *FN)(void*,void**);return ((FN)slot(self->inner,16))(self->inner,value);}
static HRESULT WINAPI batched16(BatchedAdapter *self,W10_HSTRING key){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING);return ((FN)slot(self->inner,17))(self->inner,key);}
static HRESULT WINAPI batched17(BatchedAdapter *self,W10_HSTRING key){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING);return ((FN)slot(self->inner,18))(self->inner,key);}
static HRESULT WINAPI batched18(BatchedAdapter *self,W10_HSTRING key){typedef HRESULT(WINAPI *FN)(void*,W10_HSTRING);return ((FN)slot(self->inner,19))(self->inner,key);}
static HRESULT WINAPI batched19(BatchedAdapter *self,void *handler,LONGLONG *token){typedef HRESULT(WINAPI *FN)(void*,void*,LONGLONG*);return ((FN)slot(self->inner,20))(self->inner,handler,token);}
static HRESULT WINAPI batched20(BatchedAdapter *self,LONGLONG token){typedef HRESULT(WINAPI *FN)(void*,LONGLONG);return ((FN)slot(self->inner,21))(self->inner,token);}
static HRESULT WINAPI batched21(BatchedAdapter *self,void *handler,LONGLONG *token){typedef HRESULT(WINAPI *FN)(void*,void*,LONGLONG*);return ((FN)slot(self->inner,22))(self->inner,handler,token);}
static HRESULT WINAPI batched22(BatchedAdapter *self,LONGLONG token){typedef HRESULT(WINAPI *FN)(void*,LONGLONG);return ((FN)slot(self->inner,23))(self->inner,token);}
static HRESULT WINAPI batched23(BatchedAdapter *self,void *handler,LONGLONG *token){typedef HRESULT(WINAPI *FN)(void*,void*,LONGLONG*);return ((FN)slot(self->inner,24))(self->inner,handler,token);}
static HRESULT WINAPI batched24(BatchedAdapter *self,LONGLONG token){typedef HRESULT(WINAPI *FN)(void*,LONGLONG);return ((FN)slot(self->inner,25))(self->inner,token);}
static void *batchedTable[]={batchedQuery,batchedAddRef,batchedRelease,batchedIids,batchedClass,batchedTrust,batched6,batched7,batched8,batched9,batched10,batched11,batched12,batched13,batched14,batched15,batched16,batched17,batched18,batched19,batched20,batched21,batched22,batched23,batched24};
static HRESULT wrapBatched(void *inner,void **out){BatchedAdapter *object=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*object));if(!object){release(inner);return E_OUTOFMEMORY;}object->vtable=batchedTable;object->references=1;object->inner=inner;*out=object;return S_OK;}
static HRESULT batchedQueryAt(unsigned index,void *self,const GUID *iid,void **out){if(!out)return E_POINTER;*out=NULL;if(!IsEqualGUID(iid,&oldBatchedId))return batchedOriginal[index](self,iid,out);void *inner=NULL;HRESULT hr=batchedOriginal[index](self,&hostBatchedId,&inner);if(SUCCEEDED(hr))hr=wrapBatched(inner,out);static LONG calls;LONG sequence=InterlockedIncrement(&calls);if(FAILED(hr)||sequence<=16||(sequence%512)==0)trace(L"[StartCompat] CDS batched old-QI adapter=%08lx source=%u calls=%ld",hr,index,sequence);return hr;}
static HRESULT WINAPI batchedQi0(void *self,const GUID *iid,void **out){return batchedQueryAt(0,self,iid,out);}
static HRESULT WINAPI batchedQi1(void *self,const GUID *iid,void **out){return batchedQueryAt(1,self,iid,out);}
static HRESULT WINAPI batchedQi2(void *self,const GUID *iid,void **out){return batchedQueryAt(2,self,iid,out);}
static HRESULT WINAPI batchedQi3(void *self,const GUID *iid,void **out){return batchedQueryAt(3,self,iid,out);}
static HRESULT WINAPI batchedQi4(void *self,const GUID *iid,void **out){return batchedQueryAt(4,self,iid,out);}
static HRESULT WINAPI batchedQi5(void *self,const GUID *iid,void **out){return batchedQueryAt(5,self,iid,out);}
static void installBatchedAdapter(void){
 BYTE *base=(BYTE*)GetModuleHandleW(L"StartTileData.dll");if(!base)return;
 const DWORD sites[]={0x3f4b00,0x3f4ac8,0x3f4c48,0x3f4b58,0x3f4c90,0x3f4b78};
 const DWORD expected[]={0x4ac30,0x320960,0x320980,0x320940,0x320970,0x320950};
 void *hooks[]={batchedQi0,batchedQi1,batchedQi2,batchedQi3,batchedQi4,batchedQi5};
 for(unsigned i=0;i<6;i++){if(*(void**)(base+sites[i])!=(void*)(base+expected[i])){trace(L"[StartCompat] CDS adapter refused mismatched native vtable %u",i);return;}}
 for(unsigned i=0;i<6;i++){batchedOriginal[i]=(PFN_QI)*(void**)(base+sites[i]);if(!replaceBytes(base+sites[i],&hooks[i],8)){trace(L"[StartCompat] CDS adapter patch failed at %u",i);return;}}
 trace(L"[StartCompat] CDS batched adapter installed for six native QI tables");
}
