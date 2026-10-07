"""Staged API; no import-time actions. Caller supplies reviewed controller module."""
from pathlib import Path
import json,re
def recover_previous(controller,lab,expected_native):
    lab=Path(lab).resolve();marker=lab/'active-session.txt'
    if not marker.exists():return {'Outcome':'NoPriorSession'}
    mutex=controller.create_mutex(None,False,'Local\\Settings10ManualLauncher')
    acquired=controller.wait(mutex,0) in (0,0x80)
    try:
        if not acquired:raise RuntimeError('Another active SEH appearance owner holds the common lifetime mutex.')
        path=Path(marker.read_text(encoding='utf-8-sig').strip()).resolve()
        if path.name!='state.json' or path.parent.parent!=(lab/'sessions').resolve():raise RuntimeError('Prior state escaped owned sessions.')
        state=json.loads(path.read_text(encoding='utf-8-sig'));nonce=state['Nonce']
        if not re.fullmatch('[0-9a-f]{32}',nonce) or path.parent.name!=nonce or Path(state['Directory']).resolve()!=path.parent:raise RuntimeError('Prior session directory/nonce differs.')
        if Path(state['NativePath']).resolve()!=Path(expected_native).resolve():raise RuntimeError('Prior target differs.')
        expected_command=str(lab/'SettingsNoVfsEntry.exe')+' --session s_'+nonce+'.ini'
        if state['DebuggerCommand']!=expected_command or state['ConfigName']!='s_'+nonce+'.ini':raise RuntimeError('Prior callback command differs.')
        if Path(state['CancelFile']).resolve()!=path.parent/'cancel':raise RuntimeError('Prior cancellation path differs.')
        owner=state['Controller'];h=controller.open_process(0x101000,False,owner['Pid'])
        if not h and controller.C.get_last_error()!=87:raise RuntimeError('Prior owner cannot be inspected; no stale inference.')
        if h:
            try:
                actual=controller.identity(h)
                if controller.wait(h,0)==258 and actual and actual['Birth']==owner['Birth'] and actual['Path'].casefold()==owner['Path'].casefold():
                    return {'Outcome':'ActiveOwnerPreserved','Pid':owner['Pid']}
            finally:controller.close(h)
        snapshot=controller.debug_snapshot(state)
        if snapshot==[None,None]:
            # Registration may have vanished at sign-out/reboot while the durable
            # session still lacks its terminal receipt. Drain exact activation
            # records and publish completion even with no registry work remaining.
            controller.restore(state)
            return {'Outcome':'RecoveredUnregisteredSession','StatePath':str(path)}
        saved=path.parent/'registered.json'
        if not saved.exists() or snapshot!=json.loads(saved.read_text(encoding='utf-8-sig')) or not controller.registration_owned(snapshot,expected_command):
            raise RuntimeError('Foreign or unproven registration preserved.')
        if (path.parent/'restored.json').exists():raise RuntimeError('Terminal restore disagrees with current registration; explicit investigation required.')
        controller.restore(state)
        if controller.debug_snapshot(state)!=[None,None]:raise RuntimeError('Stale registration cleanup did not complete.')
        return {'Outcome':'RecoveredExactStaleSession','StatePath':str(path)}
    finally:
        if acquired:controller.release(mutex)
        controller.close(mutex)
