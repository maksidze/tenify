from pathlib import Path
import sys,json,hashlib
LAB=Path(__file__).resolve().parent;ROOT=LAB.parents[3];BASE=LAB.parents[1];sys.path.insert(0,str(ROOT/'work/pylib'));import pefile
paths=[Path('C:/Windows/System32/uxtheme.dll'),Path('C:/Windows/System32/twinui.pcshell.dll'),Path('C:/Windows/System32/shell32.dll')]
names=['UX','PCS','SHELL'];apis=['GetThemeInt','GetThemeMargins','IsThemeBackgroundPartiallyTransparent','DrawThemeBackground','DrawThemeText','GetThemeTextExtent','GetThemeColor','DrawThemeTextEx']
sites=[(0,0x18730,0),(0,0x1880f,1),(0,0x3fd98,2),(0,0x3ff34,3),(0,0x40049,4),(0,0x400b4,4),(0,0x40896,5),
       (1,0x65fa66,6),(1,0x660365,1),(1,0x66042e,3),(1,0x66090a,6),(1,0x66211a,7),
       (2,0x1c67ea,6),(2,0x5537f4,1),(2,0x5538bd,3),(2,0x553d9d,6),(2,0x1372d2,7)]
pins={};lines=['#pragma once'];pes=[pefile.PE(str(p))for p in paths]
def pin(name,path):
 pins[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest();lines.append('#define %s_PATH L"%s"'%(name,str(path).replace('\\','\\\\')));lines.append('#define %s_SHA "%s"'%(name,pins[str(path)]))
for name,path in zip(names,paths):pin(name,path)
pin('EXPLORER',BASE/'Runtime/Explorer10/explorer.exe');pin('OLD_AERO',BASE/'Image/4/Windows/Resources/Themes/aero/aero.msstyles')
fixture=BASE/'Lab/NativeMenuThemeColorCompat/MenuThemeFixture.exe'
if fixture.exists():pin('FIXTURE',fixture)
else:lines+=['#define FIXTURE_PATH L"disabled"','#define FIXTURE_SHA "disabled"']
pin('UNIT',LAB/'UnitFixture.exe') if (LAB/'UnitFixture.exe').exists() else lines.extend(['#define UNIT_PATH L"disabled"','#define UNIT_SHA "disabled"'])
lines+=['struct SiteDef{DWORD module,rva,api,length;BYTE expected[8];BYTE context[32];};','static const SiteDef siteDefs[]={']
contract=[]
for module,rva,api in sites:
 p=pes[module];length=5 if module==0 else 7;b=p.get_data(rva,length)
 assert b[0]==0xe8 if module==0 else b[:3]==bytes.fromhex('48ff15')
 context=p.get_data(rva-16,32)
 lines.append('{%d,0x%x,%d,%d,{%s},{%s}},'%(module,rva,api,length,','.join('0x%02x'%x for x in b),','.join('0x%02x'%x for x in context)))
 contract.append(dict(module=module,rva=rva,api=api,apiName=apis[api],length=length,expected=b.hex(),contextRva=rva-16,context=context.hex()))
lines+=['};','static const DWORD apiRvas[]={'+','.join(hex(next(e.address for e in pes[0].DIRECTORY_ENTRY_EXPORT.symbols if e.name and e.name.decode()==a))for a in apis)+'};']
for label,rva in [('fromData',0x609c0),('getClass',0x37f70)]:lines.append('static const BYTE %sGuard[32]={%s};'%(label,','.join('0x%02x'%v for v in pes[0].get_data(rva,32))))
(LAB/'Pins.h').write_text('\n'.join(lines)+'\n');(LAB/'contract.json').write_text(json.dumps(dict(Dependencies=pins,CallSites=contract,ApiNames=apis,ApiRvas=[next(e.address for e in pes[0].DIRECTORY_ENTRY_EXPORT.symbols if e.name and e.name.decode()==a)for a in apis]),indent=2))
print('pins',len(pins),'sites',len(sites))
