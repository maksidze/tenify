"""Read-only validation for the current context menu and resource adapters."""
from pathlib import Path
import hashlib, importlib.util, json

BASE=Path(__file__).resolve().parent
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def validate():
    results={}
    classic=BASE/'Lab/ClassicContextMenuCompat/manifest.json'
    for item in json.loads(classic.read_text(encoding='utf-8-sig'))['Files']:
        if sha(item['Path'])!=item['SHA256'].lower():raise RuntimeError('Classic context dependency changed: '+item['Path'])
    results['ClassicContextManifest']=sha(classic)
    winx=BASE/'Lab/WinXCompat/manifest.json'
    wm=json.loads(winx.read_text(encoding='utf-8-sig'))
    for item in wm['dependencies'].values():
        if sha(item['path'])!=item['sha256'].lower():raise RuntimeError('WinX dependency changed: '+item['path'])
    for relative,digest in wm['artifacts'].items():
        if sha(winx.parent/relative)!=digest.lower():raise RuntimeError('WinX artifact changed: '+relative)
    results['WinXManifest']=sha(winx)
    spec=importlib.util.spec_from_file_location('icons_maximum',BASE/'Lab/IconResourceMaximum/IconMappings.py')
    icons=importlib.util.module_from_spec(spec);spec.loader.exec_module(icons)
    mappings=icons.get_icon_mappings()
    results['IconsMaximumManifest']=icons.EXPECTED_MANIFEST_SHA256
    results['MunMappings']=len(mappings)
    hook_spec=importlib.util.spec_from_file_location('icons_maximum_hook',BASE/'Launch-IconResourceMaximum.py')
    hook=importlib.util.module_from_spec(hook_spec);hook_spec.loader.exec_module(hook)
    if sha(BASE/'Lab/IconResourceMaximum/IconRoutes.ChildSafe.dll')!=hook.HELPER_SHA256:
        raise RuntimeError('Resource-only icon helper changed')
    results['IconRouteHelper']=hook.HELPER_SHA256
    menu=json.loads((BASE/'Lab/MenuAppearanceCompatV2/manifest.json').read_text(encoding='utf-8-sig'))
    for row in menu['Files']:
        if sha(row['Path'])!=row['SHA256'].lower():raise RuntimeError('Menu V2 artifact changed: '+row['Path'])
    for row in menu['NativeCallers']:
        if sha(row['path'])!=row['sha256'].lower():raise RuntimeError('Menu V2 native caller changed: '+row['path'])
    if sha(BASE/'Lab/MenuAppearanceCompatV2/MenuSquareV2.dll')!=menu['HelperSHA256'].lower():raise RuntimeError('Menu V2 helper mismatch')
    results['MenuSquareHelper']=menu['HelperSHA256']
    hybrid=BASE/'Lab/HybridThemeBootstrap/manifest.json'
    for row in json.loads(hybrid.read_text(encoding='utf-8-sig'))['Files']:
        if sha(row['Path'])!=row['SHA256'].lower():raise RuntimeError('Hybrid theme dependency changed: '+row['Path'])
    results['HybridThemeManifest']=sha(hybrid)
    menu_theme=BASE/'Lab/ThemeMenuBootstrap/manifest.json'
    for row in json.loads(menu_theme.read_text(encoding='utf-8-sig'))['Files']:
        if sha(row['Path'])!=row['SHA256'].lower():raise RuntimeError('Menu theme dependency changed: '+row['Path'])
    results['MenuThemeManifest']=sha(menu_theme)
    return results

if __name__=='__main__':print(json.dumps(validate(),indent=2))
