from pathlib import Path
import sys
sys.path.insert(0,'work/pylib');import pefile
files=[Path('C:/Windows/System32')/x for x in ['dwm.exe','dwmcore.dll','udwm.dll','winlogon.exe','LogonUI.exe','csrss.exe','InputHost.exe','svchost.exe']]
for p in files:
 try:
  b=p.read_bytes()
  if b'DisplayMonitorInfoCollectionServer' in b or 'DisplayMonitorInfoCollectionServer'.encode('utf-16-le') in b:
   print('MATCH',p)
 except OSError:pass
print('Scanned',len(files),'targeted DLLs')

