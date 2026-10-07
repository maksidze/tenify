from pathlib import Path
p=Path('outputs/Windows10-Components/Lab/SettingsEnumCompat');p.mkdir(exist_ok=True)
s=Path('outputs/Windows10-Components/Lab/SettingsControlTextCompat/ControlResourceProbe.cs').read_text();s=s.replace('"Taskbar","TaskBar","Display","NightLight","ColorProfile"','"Power","Sleep","ScreenOff","Timeout","Hibernate"');(p/'ControlResourceProbe.cs').write_text(s)
(p/'probe_resources.py').write_text(Path('outputs/Windows10-Components/Lab/SettingsControlTextCompat/probe_resources.py').read_text())
