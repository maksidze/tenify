"""Read-only PE inventory/import comparison for extracted x64 shell components.

Usage: python analyze_shell_pe.py EXTRACTED_ROOT OUTPUT_JSON
Does not load DLLs or run extracted binaries.
"""
import sys, pathlib, json, uuid
sys.path.insert(0, str(pathlib.Path(__file__).parent / 'pylib'))
import pefile

root = pathlib.Path(sys.argv[1]).resolve()
out = pathlib.Path(sys.argv[2]).resolve()
host = pathlib.Path('C:/Windows/System32')
export_cache = {}
def exports(path):
    key = str(path).lower()
    if key not in export_cache:
        try:
            p = pefile.PE(str(path), fast_load=True)
            p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            items = getattr(getattr(p, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
            export_cache[key] = ({x.name for x in items if x.name}, {x.ordinal for x in items})
            p.close()
        except (OSError, pefile.PEFormatError):
            export_cache[key] = None
    return export_cache[key]

rows = []
for f in root.rglob('*'):
    if not f.is_file() or f.suffix.lower() not in ('.exe', '.dll'):
        continue
    try:
        p = pefile.PE(str(f), fast_load=True)
        p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[x] for x in ('IMAGE_DIRECTORY_ENTRY_IMPORT','IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT','IMAGE_DIRECTORY_ENTRY_DEBUG')])
    except (OSError, pefile.PEFormatError):
        continue
    row = {'path':str(f.relative_to(root)), 'machine':hex(p.FILE_HEADER.Machine), 'forceIntegrity':bool(p.OPTIONAL_HEADER.DllCharacteristics & 0x80), 'imports':[], 'pdb':[]}
    for typ, dirs in [('regular',getattr(p,'DIRECTORY_ENTRY_IMPORT',[])),('delay',getattr(p,'DIRECTORY_ENTRY_DELAY_IMPORT',[]))]:
        for d in dirs:
            name = d.dll.decode(errors='replace')
            item = {'name':name,'type':typ,'count':len(d.imports)}
            if name.lower().startswith(('api-', 'ext-')):
                item['hostCheck'] = 'API-set contract; requires API-set resolution, not a disk DLL comparison'
            elif p.FILE_HEADER.Machine != 0x8664:
                item['hostCheck'] = 'Skipped: this analyzer compares only x64 System32'
            else:
                ex = exports(host/name)
                if ex is None:
                    item['hostCheck'] = 'Not found/readable in System32; may be supplied by package or other path'
                else:
                    missing = [x.name.decode(errors='replace') if x.name else '#'+str(x.ordinal) for x in d.imports if (x.name not in ex[0] if x.name else x.ordinal not in ex[1])]
                    item['missingHostExports'] = missing
            row['imports'].append(item)
    for d in getattr(p,'DIRECTORY_ENTRY_DEBUG',[]):
        if d.struct.Type == 2:
            b = p.get_data(d.struct.AddressOfRawData,d.struct.SizeOfData)
            if len(b)>=24 and b[:4]==b'RSDS':
                guid = uuid.UUID(bytes_le=b[4:20]).hex.upper()
                age = int.from_bytes(b[20:24],'little')
                name = b[24:].split(b'\0')[0].decode(errors='replace').replace('\\','/').split('/')[-1]
                row['pdb'].append({'name':name,'guid':guid,'age':age,'symbolServerUrl':f'https://msdl.microsoft.com/download/symbols/{name}/{guid}{age:X}/{name}'})
    rows.append(row)
    p.close()
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps({'root':str(root),'warning':'Import presence does not establish ABI, COM, WinRT or resource compatibility. No binaries executed.','files':rows},ensure_ascii=False,indent=2),encoding='utf-8')
print(f'{len(rows)} PE files inventoried -> {out}')
