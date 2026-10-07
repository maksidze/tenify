exec(Path('work/inspect_pfn_av.py').read_text().split('s=Path')[0])
o=pefile.PE('outputs/Windows10-Components/Image/4/Windows/explorer.exe');print('LAB',p.get_data(0x154114,44).hex());print('ORIGINAL',o.get_data(0x154114,44).hex())
