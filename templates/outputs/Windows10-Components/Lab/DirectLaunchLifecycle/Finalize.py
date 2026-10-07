"""Pin reviewed sources and existing proofs; never starts a child or shell."""
from pathlib import Path
import ast
import hashlib
import json

lab = Path(__file__).resolve().parent
base = lab.parents[1]
root_names = [
    'Start-Explorer10-Direct.ps1', 'Start-Windows10-DirectPersistent.ps1',
    'Stop-Windows10-DirectPersistent.ps1', 'Stop-Explorer10-Direct.ps1',
    'Windows10-DirectOneClick.ps1', 'Confirm-NativeExplorer.ps1',
    'Lab/NoVfsShellCompat/Launch-Explorer10-NoVFS.py',
]
paths = [p for p in lab.iterdir() if p.suffix.lower() in ('.py', '.ps1', '.cs')]
paths += [base/name for name in root_names]
for path in paths:
    if path.suffix == '.py':
        ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
python_paths = [str(p) for p in paths if p.suffix == '.py']
(lab/'python-syntax.json').write_text(json.dumps({'Passed': True, 'Files': python_paths}, indent=2), encoding='utf-8')
proof_names = ['own-proof.json', 'recovery-own-proof.json', 'recovery-race-proof.json',
               'publication-own-proof.json', 'status-own-proof.json', 'handshake-own-proof.json',
               'full-preflight-proof.json', 'python-syntax.json', 'powershell-syntax.json']
proofs = {name: json.loads((lab/name).read_text(encoding='utf-8-sig')) for name in proof_names}
for name, proof in proofs.items():
    if not proof.get('Passed'):
        raise RuntimeError('Missing successful evidence: '+name)
if len(proofs['handshake-own-proof.json']['Cases']) != 6:
    raise RuntimeError('Six handshake cases, including real parent death, required')
paths += [lab/name for name in proof_names] + [lab/'Readme.txt']
manifest = {
    'Version': 3, 'NoVFS': True, 'OwnProofPassed': True,
    'SystemFilesModified': False, 'LiveShellReplacementTested': False,
    'ActualHiddenPreflightPassed': True, 'AtomicJobAssignment': True,
    'LiveUserChildrenBreakAway': True, 'SameNativeRecoveryGate': True,
    'PreflightBeforeCompanionStop': True, 'ExactParentTransitionHandshake': True,
    'NetworkBeforeSettings': True,
    'OwnLifecycleCases': 11, 'OwnRecoveryCases': 3, 'OwnRecoveryRaceCases': 3,
    'OwnStatusCases': 3, 'OwnHandshakeCases': 6,
    'StartupDeadlineSeconds': 180, 'PreflightDeadlineSeconds': 55,
    'RegistryGuardDeadlineSeconds': 75, 'RecoveryGateWaitSeconds': 180,
    'AtomicStatusRetryMilliseconds': 250,
    'Files': [{'Path': str(p), 'SHA256': hashlib.sha256(p.read_bytes()).hexdigest()}
              for p in sorted(set(paths), key=lambda p: str(p).casefold())],
}
out = lab/'manifest.json'
out.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(json.dumps({'ManifestSHA256': hashlib.sha256(out.read_bytes()).hexdigest(), 'Files': len(paths)}))
