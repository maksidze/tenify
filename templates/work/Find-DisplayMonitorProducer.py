"""Read-only search of host shell binaries for the monitor server class."""
from pathlib import Path
import mmap, json

needles = [s.encode('utf-16-le') for s in (
    'DisplayMonitorInfoCollectionServer', 'DisplayMonitorInfoConversation_',
    'DisplayMonitorInfoCollection')]
paths = list(Path(r'C:\Windows\System32').glob('*.dll'))
paths += list(Path(r'C:\Windows\System32').glob('*.exe'))
paths += list(Path(r'C:\Windows\SystemApps').rglob('*.dll'))
paths += list(Path(r'C:\Windows\SystemApps').rglob('*.exe'))
paths += [Path(r'C:\Windows\explorer.exe')]
hits, errors = [], []
for path in paths:
    try:
        if not path.stat().st_size:
            continue
        with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            found = [needle.decode('utf-16-le') for needle in needles if data.find(needle) >= 0]
            if found:
                hits.append({'path':str(path), 'strings':found})
    except (OSError, ValueError) as exc:
        errors.append({'path':str(path), 'error':str(exc)})
result = {'scanned':len(paths), 'hits':hits, 'errors':errors}
Path(__file__).with_name('display-monitor-producer-search.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2))
