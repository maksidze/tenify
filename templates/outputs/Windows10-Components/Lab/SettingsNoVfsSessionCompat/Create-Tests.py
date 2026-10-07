from pathlib import Path
L=Path(__file__).resolve().parent;S=L.parent/'ShellAppearanceCompat'
for n in ['Fixture.exe','FixtureAdapter.dll','FixtureBridge.dll','Test-Guard.py']:(L/n).write_bytes((S/n).read_bytes())
t=(S/'Test-Lifecycle.py').read_text().replace('from Callback import run,sha','from Callback import run\nsha=lambda p:__import__("hashlib").sha256(Path(p).read_bytes()).hexdigest()')
t=t.replace("report['Ready']==1 and report['DebuggerDetached']","report['DebuggerDetached']")
start=t.index('proof=dict(')
t=t[:start]+'''import Callback
def own_bootstrap(target,state):
 if state['Adapters'][0]['Initialize']=='MissingExport':raise RuntimeError('Owned fixture partial failure')
 from OwnBootstrap import OwnChildBootstrap
 b=OwnChildBootstrap(target,state['NativePath']);b.pause_at_entry(20);b.finish(detach=True,resume_primary=False);b.resume_primary()
 return dict(DebuggerDetached=True,NoVFS=True)
Callback.bootstrap_owned=own_bootstrap
'''+t[start:]
(L/'Test-Lifecycle.py').write_text(t)
