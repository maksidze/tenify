from pathlib import Path
import json
r=json.loads(Path('work/compat-research/host-twinui/all-public-symbols.json').read_text());print('\n'.join(f"{x['rva']:x} {x['name']}" for x in r if 'WindowManagerBridge' in x['name'] and any(y in x['name'] for y in ['StartWindowWatcher','RuntimeClassInitialize','OnWindowEnumerationCompleted','OnWindowWatcherStopped'])))
