"""Rebuild only laboratory copies; Explorer disk image is deliberately not for live use."""
from pathlib import Path
import runpy
for name in ['build_pfn_compat.py','build_csr_size_compat.py','build_selector22_compat.py','build_selector13_compat.py','build_hwndparam5e_compat.py','build_kernel_callback_reuse.py']:
    runpy.run_path(str(Path('work')/name),run_name='__main__')
print('DLL compatibility build finished. For signed-shell tests, use the intact signed Explorer image and redirect only the owned child IAT in memory.')
import hashlib,json
root=Path('outputs/Windows10-Components/Lab/PfnCompat')
(root/'pfn-runtime-hashes.json').write_text(json.dumps({name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ['UZER32.dll','W1N32U.dll']},indent=2),encoding='utf8')
