from pathlib import Path
H=Path(__file__).resolve().parent
source=(H/'probe_taskbar_provider.py').read_text().replace("native-oldpri","native-ntpri").replace("old-oldpri","old-ntpri").replace("Windows.UI.SettingsAppThreshold/Windows.UI.SettingsAppThreshold.pri","Windows.UI.SettingsHandlers-nt/Windows.UI.SettingsHandlers-nt.pri").replace('taskbar-provider-oldpri-proof.json','taskbar-provider-ntpri-proof.json')
exec(compile(source,str(H/'probe_nt_map.py'),'exec'))
