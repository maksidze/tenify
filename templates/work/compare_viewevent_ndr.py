from pathlib import Path
import json,sys,struct,uuid
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
prefix='___x_Windows_CInternal_CShell_CViewManagerInterop_C'
names={'sender':prefix+'IViewWrapper','args':prefix+'IViewEventArgs','delegate':'___FITypedEventHandler_2_Windows__CInternal__CShell__CViewManagerInterop__CIViewWrapper_Windows__CInternal__CShell__CViewManagerInterop__CIViewEventArgs'}
results={}
for tag,path in [('old','work/windowwatcher/old/4/Windows/System32/OneCoreUAPCommonProxyStub.dll'),('host','C:/Windows/System32/OneCoreUAPCommonProxyStub.dll')]:
    p=pefile.PE(path);base=p.OPTIONAL_HEADER.ImageBase
    symbols=json.loads(Path(f'work/compat-research/{tag}-viewevent-proxy/all-public-symbols.json').read_text())
    rows={}
    for role,name in names.items():
        proxy=next(x['rva'] for x in symbols if x['name']==name+'ProxyVtbl')
        stub=next(x['rva'] for x in symbols if x['name']==name+'StubVtbl')
        info,iid=struct.unpack('<QQ',p.get_data(proxy,16));desc,fmt,table=struct.unpack('<QQQ',p.get_data(info-base,24))
        types=struct.unpack('<Q',p.get_data(desc-base+64,8))[0]-base
        def describe_type(offset,depth=0):
            data=p.get_data(types+offset,20)
            if depth>8:return 'depth limit'
            if data[:2]==b'\x2f\x5a':return {'interfaceIID':str(uuid.UUID(bytes_le=data[2:18]))}
            if data[0] in (0x11,0x12,0x13,0x14):
                if data[1]&8:return {'pointer':hex(data[0]),'simpleType':hex(data[2])}
                target=offset+2+struct.unpack_from('<h',data,2)[0]
                return {'pointer':hex(data[0]),'to':describe_type(target,depth+1)}
            return {'typeCode':hex(data[0]),'bytes':data.hex()}
        count=struct.unpack('<I',p.get_data(stub+16,4))[0];methods=[]
        for slot in range(3 if role=='delegate' else 6,count):
            delta=struct.unpack('<H',p.get_data(table-base+slot*2,2))[0]
            data=p.get_data(fmt-base+delta,512)
            assert data[:2]==b'\x33\x6c',(tag,role,slot,data[:4].hex())
            opnum,stack,client,server=struct.unpack_from('<4H',data,6);nargs,extsize=data[15:17];at=16+extsize;params=[]
            for i in range(nargs):
                flags,stackoff,typeval=struct.unpack_from('<HHH',data,at+i*6)
                row={'attributes':hex(flags),'stackOffset':stackoff}
                if flags&0x40:row['baseType']=hex(typeval&255)
                else:
                    typedata=p.get_data(types+typeval,40);row['typeOffset']=hex(typeval);row['typeBytes']=typedata.hex()
                    row['resolvedType']=describe_type(typeval)
                    if typedata[:2]==b'\x2f\x5a':row['IID']=str(uuid.UUID(bytes_le=typedata[2:18]))
                params.append(row)
            methods.append({'slot':slot,'opnum':opnum,'stackBytes':stack,'clientBufferBytes':client,'serverBufferBytes':server,'parameters':params,'procedureRVA':hex(fmt-base+delta)})
        rows[role]={'IID':str(uuid.UUID(bytes_le=p.get_data(iid-base,16))),'methodCount':count,'proxyRVA':hex(proxy),'methods':methods}
    results[tag]=rows
out=Path('outputs/Windows10-Components/Lab/ViewDelegateCompat/viewevent-ndr-comparison.json')
out.write_text(json.dumps(results,indent=2))
for tag,rows in results.items():
    print(tag)
    for role,item in rows.items():
        print(role,item['IID'],'slots',item['methodCount'])
        if role!='sender':
            for m in item['methods']:print(m['slot'],[{k:v for k,v in p.items() if k not in ['typeBytes','typeOffset']} for p in m['parameters']])
