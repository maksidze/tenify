from pathlib import Path
import sys
sys.path.insert(0,'work/pylib');import pefile
files=[p for p in Path('C:/Windows/SystemApps').rglob('*') if p.suffix.lower() in ('.dll','.exe')]
for p in files:
 try:
  b=p.read_bytes()
  if b'DisplayMonitorInfoCollectionServer' in b or 'DisplayMonitorInfoCollectionServer'.encode('utf-16-le') in b:
   print('MATCH',p)
 except OSError:pass
print('Scanned',len(files),'targeted DLLs')

