from pathlib import Path
import json
H=Path(__file__).resolve().parent
source=(H.parent/'SettingsCaptionCompat/inspect_xbf.py').read_text()
source=source.replace("HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parents[3]","HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parents[3]")
source=source.replace("path=ROOT/'work/settings-viewmodel-actual.xbf'","path=HERE/'old/014-TaskbarPageViewModel.xbf'")
source=source.replace("assert hashlib.sha256(b).hexdigest()=='61212b95dde521924c56925b14718473ea3dd5d88a95d8d74e581c7311eecdd0'",'')
source=source.replace("about=[x for x in objects if x['type']=='SettingsPageEntry' and x['properties'].get('Id') in ['SettingsPageAbout_ControlPanelSystem','SettingsPageAbout','SettingsPageAbout_New','SettingsPagePCSystemInfo']]","about=objects")
source=source.replace("xbf-about-evidence.json","xbf-taskbar-evidence.json")
source=source.replace('begin,end=streams[1]','begin,end=streams[0]')
source=source.replace("'decodedStream':1","'decodedStream':0")
source=source.replace("'rootCustomRuntimeDataStreamDecoded':False","'rootCustomRuntimeDataStreamDecoded':True")
exec(compile(source,str(H/'decode_taskbar.py'),'exec'))
