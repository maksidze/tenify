from pathlib import Path
import hashlib
base=Path('outputs/Windows10-Components');manifest=base/'Lab/IconResourceCompat/merged-resource-manifest.json';sha=hashlib.sha256(manifest.read_bytes()).hexdigest()
p=base/'Launch-Explorer10-VFS.py';s=p.read_text(encoding='utf-8-sig').replace("p.add_argument('--xaml-quirk',action='store_true')","p.add_argument('--xaml-quirk',action='store_true')\np.add_argument('--icons10',action='store_true')")
s=s.replace("'noLegacyTouchpad':a.no_legacy_touchpad,","'noLegacyTouchpad':a.no_legacy_touchpad,'icons10':a.icons10,")
needle="    if a.no_legacy_touchpad and a.profile!='legacy-watchers':"
validation="""    iconResources=[]
    if a.icons10:
        if a.profile!='host-dcomp-resource':raise RuntimeError('Icons10 currently tested only with host-dcomp-resource')
        iconLab=base/'Lab/IconResourceCompat';iconManifest=iconLab/'merged-resource-manifest.json'
        if hashlib.sha256(iconManifest.read_bytes()).hexdigest()!='MANIFESTSHA':raise RuntimeError('Icons10 manifest hash mismatch')
        entries=json.loads(iconManifest.read_text(encoding='utf-8'))
        if len(entries)!=2:raise RuntimeError('Icons10 resource set mismatch')
        for entry,name in zip(entries,['imageres.dll.mun','shell32.dll.mun']):
            native=win/'SystemResources'/name;merged=iconLab/'MergedResources'/name
            if hashlib.sha256(native.read_bytes()).hexdigest()!=entry['hostSHA256']:raise RuntimeError('Native MUN changed; rebuild and verify Icons10: '+name)
            if hashlib.sha256(merged.read_bytes()).hexdigest()!=entry['sha256']:raise RuntimeError('Icons10 merged MUN hash mismatch: '+name)
            iconResources.append((merged,native,entry))
        state['icons10Validation']={'manifestSHA256':'MANIFESTSHA','nativeResourceHashesMatched':True,'mergedResourceHashesMatched':True,'stockOnly':True}
""".replace('MANIFESTSHA',sha)
s=s.replace(needle,validation+needle)
s=s.replace("    si=SI();si.cb=C.sizeof(si)","    for merged,native,entry in iconResources:\n        mapfile(merged,native)\n        state['mappings'][-1].update({'resourceOnly':True,'sha256':entry['sha256'],'hostSHA256':entry['hostSHA256']})\n    si=SI();si.cb=C.sizeof(si)")
p.write_text(s,encoding='utf8')
p=base/'Start-Explorer10-VFS.ps1';s=p.read_text(encoding='utf-8-sig').replace('[switch]$XamlQuirk,','[switch]$XamlQuirk, [switch]$Icons10,')
for variable in ['preflightArguments','packageArguments','controllerArguments']:
 needle=f'if($XamlQuirk){{$'+variable+"+='--xaml-quirk'}"
 s=s.replace(needle,needle+f"\n if($Icons10){{$"+variable+"+='--icons10'}")
p.write_text(s,encoding='utf-8-sig')
print('manifestSHA',sha)
compile((base/'Launch-Explorer10-VFS.py').read_text(),str(base/'Launch-Explorer10-VFS.py'),'exec');print('python syntax PASS')
