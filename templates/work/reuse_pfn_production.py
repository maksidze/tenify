from pathlib import Path
p=Path('work/probe_pfn_resource_entry.py');s=p.read_text();s=s.replace("['UZER32.dll','W1N32U.dll']","['UZER32.dll','W1N32U.dll','pfn-runtime-hashes.json']")
a=s.index("  shim=exe.parent/'UZER32.dll';");b=s.index("  boot.install_resource_hook",a)
s=s[:a]+"  spec2=importlib.util.spec_from_file_location('pfnbootstrap',base/'Launch-PfnCompat.py');pfnmod=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(pfnmod)\n  pfn_result=pfnmod.install_pfn_hook(boot,exe.parent)\n"+s[b:];s=s.replace("'user32Slots':len(changes),'sameForwardersPreserved':preserved", "'pfn':pfn_result");p.write_text(s)
