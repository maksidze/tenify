from pathlib import Path
import bisect, json
root=Path(__file__).resolve().parent.parent
run=root/'outputs/Windows10-Components/state-vfs/3686bba15ab24dbc80884fead8247eac'
events=[json.loads(line) for line in (run/'pss-all-threads.jsonl').read_text(encoding='utf-8').splitlines()]
mods={e['base']:e for e in events if e['event']=='module'}
symbol_paths={'twinui.pcshell.dll':'work/compat-research/host-twinui/all-public-symbols.json','shcore.dll':'work/compat-research/host-shcore/all-public-symbols.json','windows.ui.xaml.dll':'work/compat-research/host-xaml/all-public-symbols.json','user32.dll':'work/compat-research/host-user32/all-public-symbols.json','explorer.exe':'work/explorer-public-symbols.json'}
symbols={}
for name,p in symbol_paths.items():
    data=json.loads((root/p).read_text(encoding='utf-8-sig'))
    data=[(int(x['rva'],0) if isinstance(x['rva'],str) else x['rva'],x['name']) if isinstance(x,dict) else tuple(x) for x in data]
    data.sort();symbols[name]=([x[0] for x in data],data)
out=[];allout=[]
for e in events:
    if e['event']=='thread':
        line=f"\nTHREAD {e['tid']} suspend={e['suspendCountAtCapture']} contextBytes={e['contextSize']}"
        allout.append(line)
        if e['tid'] in (7352,7308):out.append(line)
    if e['event']!='frame':continue
    m=mods.get(e['moduleBase'],{});p=m.get('physicalPath','?');name=Path(p).name.lower();rva=int(e['rva'],16)
    label=e['symbol']+('+'+hex(e['displacement']) if e['displacement'] else '')
    if name in symbols:
        addresses,data=symbols[name];index=bisect.bisect_right(addresses,rva)-1
        if index>=0:
            addr,sym=data[index];label=sym+'+'+hex(rva-addr)
    line=f"{e['index']:02d} {name}+{e['rva']}  {label}"
    allout.append(line)
    if e['tid'] in (7352,7308):out.append(line)
(run/'pss-selected-stacks.txt').write_text('\n'.join(out)+'\n',encoding='utf-8')
(run/'pss-formatted-stacks.txt').write_text('\n'.join(allout)+'\n',encoding='utf-8')
print('\n'.join(out))
for name in ('twinui.pcshell.dll','shcore.dll','windows.ui.xaml.dll'):
    for m in mods.values():
        if Path(m['physicalPath']).name.lower()==name:
            print(json.dumps(m))
