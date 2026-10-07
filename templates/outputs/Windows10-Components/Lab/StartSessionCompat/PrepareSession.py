"""Read-only native package/shell preflight; writes only this prepared state."""
import sys,json,os
from pathlib import Path
import SessionController as D
S=D.S
p=Path(sys.argv[1]);state=json.loads(p.read_text(encoding='utf-8-sig'))
pid=D.owner_pid()
if state.get('RequestedExplorerPid') and state['RequestedExplorerPid']!=pid:raise RuntimeError('Requested Explorer does not own the shell')
h=S.open_process(0x101000,False,pid)
if not h:raise RuntimeError('Shell process is not readable')
try:state['Explorer']=dict(Pid=pid,**S.identity(h))
finally:S.close(h)
if state['Explorer']['Path'].casefold()!=str(D.BASE/'Runtime/Explorer10/explorer.exe').casefold():
    # The working layout is Runtime/explorer.exe on this host; pinned manifest
    # also verifies its bytes. Reject every unrelated executable/path.
    allowed=[str(p).casefold() for p in (D.BASE/'Runtime').glob('**/explorer.exe')]
    if state['Explorer']['Path'].casefold() not in allowed:raise RuntimeError('Shell is not an Explorer from this lab Runtime')
D.preflight(state);S.dump(p,state)
print(json.dumps(dict(Preflight=True,PackageDebuggingChanged=False,ActivationPerformed=False,Explorer=state['Explorer'],NativeBaselines=S.target_processes(state))))
