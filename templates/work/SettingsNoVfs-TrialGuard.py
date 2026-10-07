from pathlib import Path
import sys,json,time
state_path=Path(sys.argv[1]).resolve();state=json.loads(state_path.read_text(encoding='utf-8-sig'));directory=state_path.parent
lab=directory.parents[1];sys.path.insert(0,str(lab));import SessionController as S
deadline=time.monotonic()+150
while time.monotonic()<deadline:
    if (directory/'root-accepted').exists():
        (directory/'root-trial-guard.json').write_text(json.dumps(dict(Outcome='AcceptedUntilStop',SourceFilesModified=False)))
        raise SystemExit(0)
    if (directory/'root-stop').exists():break
    time.sleep(.2)
S.restore(state)
(directory/'root-trial-guard.json').write_text(json.dumps(dict(Outcome='Restored',Complete=(directory/'restored.json').exists())))
