from pathlib import Path
import subprocess,json
H=Path(__file__).resolve().parent
source=(H/'ControlResourceProbe.cs').read_text().replace('class ControlResourceProbe','class TemplateResourceProbe').replace('new[]{"Taskbar","TaskBar","Display","NightLight","ColorProfile"}','new[]{"Templates"}')
(H/'TemplateResourceProbe.cs').write_text(source)
base=(H/'probe_resources.py').read_text().replace("source=HERE/'ControlResourceProbe.cs';exe=HERE/'ControlResourceProbe.exe'","source=HERE/'TemplateResourceProbe.cs';exe=HERE/'TemplateResourceProbe.exe'").replace("for mode in ['native','old']:","for mode in ['old']:").replace('directory=HERE/mode','directory=HERE/(mode+\'-templates\')').replace('resource-proof.json','template-proof.json')
exec(compile(base,str(H/'probe_templates.py'),'exec'))
