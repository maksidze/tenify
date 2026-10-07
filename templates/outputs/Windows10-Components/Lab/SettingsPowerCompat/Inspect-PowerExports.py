from pathlib import Path
import sys,json
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile
for label,p in [('old',root/'outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'),('host',Path('C:/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'))]:
 pe=pefile.PE(str(p));print(label,[e.name.decode() if e.name else '#'+str(e.ordinal) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]);raw=p.read_bytes()
 for s in ['SystemSettings_PowerAndSleep_DisplayOffTimeoutAC','SystemSettings_PowerAndSleep_SleepTimeoutAC','Value','Items','PossibleValues']:
  print(s,raw.find(s.encode('utf-16le')))
