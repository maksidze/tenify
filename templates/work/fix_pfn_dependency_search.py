from pathlib import Path
p=Path('work/probe_pfn_signed_injected.py');s=p.read_text();needle="shutil.copy2(base/'Runtime/Explorer10/explorer.exe',lab/'explorer.exe');shutil.copytree(base/'Runtime/Explorer10/ru-RU',lab/'ru-RU',dirs_exist_ok=True)";s=s.replace(needle,needle+"\nfor name in ['UZER32.dll','W1N32U.dll']:shutil.copy2(base/'Lab/PfnCompat'/name,lab/name)")
s=s.replace("shim=base/'Lab/PfnCompat/UZER32.dll'","shim=base/'Lab/PfnCompat/SignedInjected/UZER32.dll'");p.write_text(s)
