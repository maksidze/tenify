from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'decode_taskbar.py').read_text().replace('old/014-TaskbarPageViewModel.xbf','old/013-PCSystemDisplayPageViewModel.xbf').replace('xbf-taskbar-evidence.json','xbf-display-evidence.json')
exec(compile(s,str(H/'decode_display.py'),'exec'))
