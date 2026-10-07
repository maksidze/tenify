from pathlib import Path
p=Path('work/probe_pfn_signed_injected.py');s=p.read_text();s=s.replace("source=source.replace(old,prep+inject)","source=source.replace(old,prep+inject)\nsource=source.replace('except Exception as e:result.update(error=str(e))',\"except Exception as e:\\n import traceback\\n result.update(error=str(e),errorType=type(e).__name__,traceback=traceback.format_exc())\")")
p.write_text(s)
