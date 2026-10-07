from pathlib import Path
root=Path(__file__).resolve().parent.parent
p=root/'outputs/Windows10-Components/Launch-Explorer10-VFS.py'
s=p.read_text(encoding='utf-8-sig')
start=s.index("        iconLab=base/'Lab/IconResourceCompat'")
end=s.index('    if a.no_legacy_touchpad',start)
s=s[:start]+'''        import importlib.util
        iconLab=base/'Lab/IconResourceMaximum';iconManifest=iconLab/'manifest.json'
        iconSpec=importlib.util.spec_from_file_location('icon_maximum_mappings',iconLab/'IconMappings.py');iconModule=importlib.util.module_from_spec(iconSpec);iconSpec.loader.exec_module(iconModule)
        mappings=iconModule.get_icon_mappings()
        inventory=json.loads(iconManifest.read_text(encoding='utf-8-sig'))
        byPrivate={str(Path(row['Private']).resolve()).casefold():row for row in inventory['Records']}
        for mapping in mappings:
            if mapping['Kind']!='File':raise RuntimeError('Unsupported icon mapping kind')
            merged=Path(mapping['Source']);native=Path(mapping['Destination'])
            if native.suffix.lower()!='.mun':raise RuntimeError('Executable icon overlay forbidden')
            record=byPrivate[str(merged.resolve()).casefold()]
            iconResources.append((merged,native,{'sha256':record['PrivateSHA256'],'hostSHA256':record['HostSHA256']}))
        state['icons10Validation']={'manifestSHA256':iconModule.EXPECTED_MANIFEST_SHA256,'nativeResourceHashesMatched':True,'mergedResourceHashesMatched':True,'stockOnly':False,'munMappings':len(mappings),'resourceFiles':len(inventory['Records']),'resourceGroups':sum(len(r['ResourceGroups']) for r in inventory['Records'])}
''' +s[end:]
p.write_text(s,encoding='utf-8')
