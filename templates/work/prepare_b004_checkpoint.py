from pathlib import Path
import json,datetime
root=Path(__file__).resolve().parent.parent
out=root/'outputs/Windows10-Builds'
path=out/'checkpoint.py'
s=path.read_text(encoding='utf-8')
start=s.index("'settings':'Windows10 Settings repeat opening")
end=s.index("'}\n",start)
s=s[:start]+"'settings':'Current-system oneclick-04 UntilStop snapshot. See outputs/Windows10-Components/b004-live-proof.json and Shell-Menus-and-Icons-2026-10-05.txt for exact runtime evidence. Classic context route, WinX right-click/keyboard adapters, network GUID/individual visibility fix and 2620 PE icon groups included. Own fixtures and combined isolated Explorer preflight pass; two real OneClick starts passed with reuse. Visible menu/command verification pending. Task View remains Windows 11; Settings Display/Update and font/AppX icons incomplete.'"+s[end+1:]
path.write_text(s,encoding='utf-8')
(out/'freeze-authorized.json').write_text(json.dumps({'milestone':'b004-classic-menus-icons','authorizedBy':'root','reason':'All three agent source sets frozen; integrated preflight PASS; live OneClick Start and repeat Start passed. Runtime state directories excluded.','utc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2),encoding='utf-8')
