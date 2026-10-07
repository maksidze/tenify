from pathlib import Path
p=Path('work/probe_pfn_signed_injected.py');s=p.read_text();s=s.replace("     suspend=api(kernel,'SuspendThread',D,[P])\n     if suspend(pi.thread)==0xffffffff:raise C.WinError(C.get_last_error())",'     # Primary continues through loader initialization, as in proven resource probe.')
p.write_text(s)
