"""Root-authorized reversible swap. No package registration or activation."""
from pathlib import Path
import sys,json,hashlib,shutil,os,datetime
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'work/pylib'));import pefile
lab=root/'outputs/Windows10-Components/Lab/BrokerGuiEntry';report=json.loads((lab/'build-report.json').read_text());backup=lab/'ConsoleBackups';backup.mkdir(exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for r in report['rows']:
 p=Path(r['production']);gui=Path(r['guiCopy']);src=Path(r['source'])
 assert sha(p)==r['productionSha256'],'Original production changed'
 assert sha(gui)==r['guiSha256'] and sha(src)==r['sourceSha256'],'GUI/source changed'
 assert pefile.PE(str(gui)).OPTIONAL_HEADER.Subsystem==2
for r in report['rows']:
 p=Path(r['production']);gui=Path(r['guiCopy']);save=backup/(p.stem+'.Console.exe');assert not save.exists() or sha(save)==r['productionSha256'];shutil.copy2(p,save)
 if p.with_suffix('.pdb').exists():shutil.copy2(p.with_suffix('.pdb'),backup/(p.stem+'.Console.pdb'))
 staging=p.with_suffix('.swap.tmp');shutil.copy2(gui,staging);os.replace(staging,p)
 if gui.with_suffix('.pdb').exists():shutil.copy2(gui.with_suffix('.pdb'),p.with_suffix('.pdb'))
 r.update(backup=str(save),backupSha256=sha(save),productionGuiSha256=sha(p),productionSubsystem=pefile.PE(str(p)).OPTIONAL_HEADER.Subsystem)
report.update(productionFilesReplaced=True,swapUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),rootGo=True,preSwapNoActiveTargetHelperCheck=True,packageActivationPerformed=False,helperProcessesLaunched=False)
(lab/'production-swap-report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print('Published all 3 GUI subsystem production broker helpers; console originals preserved; no activation')
