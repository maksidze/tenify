from pathlib import Path
import json
root=Path(__file__).resolve().parent.parent
for label in ['shell32','explorerframe']:
 d=json.loads((root/'work/explorer-ui-routes.json').read_text())[label]
 for s in d['symbols']:
  n=s['name']
  if any(k in n for k in ['DoCuratedMenu','_DoPopupMenu','ContextMenuPresenter','ContextMenu@CDefView','_OnContextMenu','ShouldShowMiniMenu','IsXamlIslandAvailable','CreateExplorerRibbon','ContextMenuOptions','ShowPopupMenu','FileDialog_Create','CreateFileDialog']):print(label,hex(s['rva']),n)
