from pathlib import Path
import subprocess,json,hashlib
LAB=Path(__file__).resolve().parent
log=LAB/'route-own-results.jsonl'
result=subprocess.run([str(LAB/'IconRouteProbe.exe'),str(LAB/'IconRoutes.dll'),str(log)],creationflags=subprocess.CREATE_NO_WINDOW,timeout=35)
rows=[json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
extract=[x for x in rows if x.get('type')=='extract']
proof=dict(ExitCode=result.returncode,Rows=rows,Passed=result.returncode==0 and bool(rows) and all(x.get('pass',True) for x in rows),CodeDLLOverlay=False,LiveUI=False,NoWindowProcessCreation=True,
           RenderedExtractCases=sum(x['actual']!='0' for x in extract),ExtractCountSentinelBaselineCases=[x['case'] for x in extract if x['actual']=='0'],
           BaselineLimitation='ExtractIconEx index -1 requests group count, rather than a rendered HICON; resource group1 is covered separately by exhaustive resource renderer.')
(LAB/'route-own-proof.json').write_text(json.dumps(proof,indent=2),encoding='utf-8')
print(json.dumps(proof,indent=2))
if not proof['Passed']:raise SystemExit(1)
