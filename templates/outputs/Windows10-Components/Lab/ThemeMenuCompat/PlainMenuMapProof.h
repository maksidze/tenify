#pragma once
// Own disposable pre-popup fixture only; not the production initializer.
struct PlainSite {DWORD rva;BYTE size,offset,value;BYTE before[6];};
static const PlainSite plainSites[]={
{0x1872d,3,2,6,{0x8d,0x57,0x13}},
{0x187fc,4,3,14,{0x44,0x8d,0x47,0x1b}},
{0x3fd8f,5,1,14,{0xba,0x1b,0x00,0x00,0x00}},
{0x3ff0e,6,2,14,{0x41,0xb8,0x1b,0x00,0x00,0x00}},
{0x40028,6,2,14,{0x41,0xb8,0x1b,0x00,0x00,0x00}},
{0x4008d,6,2,14,{0x41,0xb8,0x1b,0x00,0x00,0x00}},
{0x40884,4,3,14,{0x45,0x8d,0x41,0x1b}},
};
static bool plainMapProof(HMODULE module,bool install){
BYTE*base=(BYTE*)module;
for(auto&s:plainSites){BYTE expected[6];memcpy(expected,s.before,s.size);if(!install)expected[s.offset]=s.value;if(memcmp(base+s.rva,expected,s.size))return false;}
for(auto&s:plainSites){DWORD old=0,unused=0;if(!VirtualProtect(base+s.rva,s.size,PAGE_EXECUTE_READWRITE,&old))return false;base[s.rva+s.offset]=install?s.value:s.before[s.offset];bool ok=FlushInstructionCache(GetCurrentProcess(),base+s.rva,s.size)&&VirtualProtect(base+s.rva,s.size,old,&unused);if(!ok)return false;}return true;}
