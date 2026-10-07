from pathlib import Path
import bisect,json
root=Path(__file__).resolve().parent.parent
lab=root/'outputs/Windows10-Components/Lab/SettingsBrokerCompat'
prefix=lab/'broker-settings-16b40c5c5f60'
events=[json.loads(s) for s in Path(str(prefix)+'.pss.jsonl').read_text(encoding='utf-8').splitlines()]
mods={e['base']:e for e in events if e['event']=='module'}
sources={'systemsettings.exe':'host-settings-exe','systemsettings.dll':'old-settings-dll','windows.ui.xaml.dll':'host-xaml','twinapi.appcore.dll':'host-twinapi','shcore.dll':'host-shcore','systemsettings.datamodel.dll':'old-settings-datamodel','systemsettings.viewmodel.dll':'old-settings-viewmodel','windowsudk.shellcommon.dll':'host-udkshellcommon','windows.ui.immersive.dll':'host-immersive','coremessaging.dll':'host-coremsg','coreuicomponents.dll':'host-coreui'}
symbols={}
for name,folder in sources.items():
    p=root/'work/compat-research'/folder/'all-public-symbols.json'
    if p.exists():
        entries=sorted((x['rva'],x['name']) for x in json.loads(p.read_text(encoding='utf-8-sig')))
        symbols[name]=([x[0] for x in entries],entries)
lines=['Nearest public symbols are labels, not guaranteed function boundaries.']
for e in events:
    if e['event']=='thread':lines.append('\nTID %s contextBytes%s'%(e['tid'],e['contextSize']))
    if e['event']!='frame':continue
    m=mods.get(e['moduleBase'],{});name=Path(m.get('physicalPath','?')).name.lower();rva=int(e['rva'],16);label=e['symbol']+'+'+hex(e['displacement'])
    if name in symbols:
        addresses,entries=symbols[name];idx=bisect.bisect_right(addresses,rva)-1
        if idx>=0:addr,sym=entries[idx];label=sym+'+'+hex(rva-addr)
    lines.append('%02d %s+%s %s'%(e['index'],name,e['rva'],label))
text='\n'.join(lines)+'\n';Path(str(prefix)+'.pss-stacks.txt').write_text(text,encoding='utf-8');print(text)
