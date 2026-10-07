from pathlib import Path
import sys,json,struct
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile
base=root/'outputs/Windows10-Components'
rows=[]
for kind,file in [('old',base/'Image/4/Windows/System32/ApplicationFrame.dll'),('host',Path('C:/Windows/System32/ApplicationFrame.dll'))]:
    symbols=json.loads((root/f'work/compat-research/{kind}-appframe/all-public-symbols.json').read_text());names={x['rva']:x['name'] for x in symbols}
    image=pefile.PE(str(file)); row={'kind':kind,'path':str(file),'tables':[],'methods':[],'iids':[]}
    for symbol in symbols:
        name=symbol['name']
        if 'ApplicationFrameManager' in name and name.startswith('??_7CApplicationFrameManager'):
            table={'rva':hex(symbol['rva']),'name':name,'slots':[]}
            for i in range(24):
                address=struct.unpack('<Q',image.get_data(symbol['rva']+i*8,8))[0];rva=address-image.OPTIONAL_HEADER.ImageBase
                table['slots'].append({'slot':i,'rva':hex(rva),'name':names.get(rva)})
            row['tables'].append(table)
        if '@CApplicationFrameManager@@' in name and not name.startswith('??'):row['methods'].append({'rva':hex(symbol['rva']),'name':name})
        if name.startswith('IID_IApplicationFrameManager') or name=='CLSID_ApplicationFrameManager':
            import uuid
            row['iids'].append({'name':name,'rva':hex(symbol['rva']),'guid':str(uuid.UUID(bytes_le=image.get_data(symbol['rva'],16)))})
    import uuid
    if kind=='host':row['iids'].append({'name':'IApplicationFrameManager_from_AsIID','rva':'0x7fc78','guid':str(uuid.UUID(bytes_le=image.get_data(0x7fc78,16)))})
    rows.append(row)
out=base/'Lab/AppFrameManagerCompat';out.mkdir(exist_ok=True)
(out/'manager-vtables.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
for row in rows:
    print(row['kind'],row['iids']);print('methods',row['methods']);print('vtables',[(x['rva'],[(v['slot'],v['name']) for v in x['slots'][:10]]) for x in row['tables']])
