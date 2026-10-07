Start10 session UntilStop, 2026-10-05.

Integration (Windows PowerShell5.1):
  Enable-Start10-Session.ps1 -UntilStop [-TargetPid <current owned Explorer>]
  Enable-Start10-Session.ps1 -UntilStop -PreflightOnly
  Stop-Start10-Session.ps1 [-StatePath <sessions/nonce/state.json>]
  Status-Start10-Session.ps1 [-StatePath <sessions/nonce/state.json>]
Default mode is UntilStop. Explicit -Seconds5..3600 remains a separate bounded
parameter set for diagnostics. BASE/Maximum/oneclick launchers are not changed.

UntilStop means explicit Stop, normal session end/logoff, exact controller death,
or loss of the exact Explorer that owned GetShellWindow at startup. A healthy
Start process has no application deadline and is never restarted periodically.
All bootstrap work retains a finite30second watchdog. After both imports are
patched and DebugActiveProcessStop succeeds with remoteDebugger=false, only
that application's lifetime deadline is removed. Independent native watchdog
uses duplicated stable child/owner handles and durable cancellation; a blocked
main observer cannot extend bootstrap indefinitely. Normal disposal joins this
watchdog before handles or its stack storage are released.

The genuine native broker creates each Start process. Per callback we verify
native path, package, fresh creation time and primary-thread owner, then publish
an immutable16byte magic/PID/FILETIME record and per-activation INI. The original
target handle remains held through backend completion. Backend rechecks the
exact birth, path, package and thread ownership. Duplicate same-birth callbacks
leave the existing owner's suspend count untouched; malformed/unpublishable
records fail closed for the exact verified fresh target. Native signed EXE and
system files are unchanged. StartCompat's existing proven proxy/resources are
read only; no shared StartCompat.ini or BrokerStartCompat.ini is rewritten.

CREATE_THREAD debug-event handles are Windows-owned and no longer closed early.
This fixes aliasing with the separately owned remote loader thread handle.
ContinueDebugEvent failure aborts only the owned target. Debugger detaches after
bootstrap; no permanent debug gate affects the app. Logs are capped to8MiB per
activation and rolled within that file; ownership records remain separate.

If an owned app exits, the same registered callback supports the next genuine
activation. Controller proactively requests activation only while no owned
instance and no unclaimed native instance exist, with an8second quiet interval
and maximum3 attempts in60seconds. Repeated failures cancel the session, disable
only its exact registration, stop exact recorded targets and request native
Start if the original shell still exists. A healthy instance never enters this
recovery path. Visible UI is not inferred from activation success or a ready
marker; running.json means verified bootstrap only.

Registration lifetime is serialized by Local\StartMenu10Session and each
nonce-specific restore gate. Existing package debugger/IFEO configuration is
refused. Every short enable/disable controller is created suspended, assigned
to an anonymous kill-on-close Job, recorded, then resumed. An independent guard
is ready before EnableDebugging. Restore checks the exact command and saved
registration snapshot; a foreign change is preserved and reported. Stop is
durable and idempotent. Own process cleanup compares exact PID, birth, path and
package on the same open handle. It never terminates Explorer or a replacement
Start by process name. Native restoration is skipped when the shell ends or
logoff was observed.

Abrupt session termination can prevent any normal user process from finishing
cleanup. An orphaned callback whose owner identity no longer exists resumes its
still-native/unmodified fresh target. It also starts a GUI-subsystem bounded
SessionRepair helper. This helper disables registration only if DebugInformation
is absent and PackagedAppXDebug is exactly one default REG_SZ matching this
helper directory's Start10SessionDebugger command and exact nonce. Other values,
subkeys, commands or packages are refused. This recovery is not an autostart,
service, scheduled task, IFEO entry or a persistent binary replacement. The
real orphan DisableDebugging branch awaits a controlled live lifecycle test.

State and reuse:
active-session.txt points to sessions/<nonce>/state.json.
Controller and Explorer contain Pid, Birth (uint64 FILETIME), Path, Package.
UntilStop is Boolean. running.json has BootstrapReady, Instances and explicit
VisibleUIConfirmed=false. status.json describes current exact-owned instances.
restored.json marks registration/record cleanup complete. A controller remains
alive to own the session; reuse requires exact live Controller/Explorer identity,
no cancel/restored marker, current shell ownership, and expected registration.
Sources/EXEs and immutable dependencies are pinned in manifest.json Files.

Build/test:
Build.py builds only these private files with GUI subsystem2 and does not run
prepare_sources.py. That script is historical staging provenance and must not
overwrite the reviewed final sources. All process launches use CREATE_NO_WINDOW.
Test-Session.py runs only own harmless GUI-subsystem children assigned to a
kill-on-close Job before resume; no native package activation or debug registry
write occurs. Fixtures execute the actual backend import patch, loader/entry
breakpoint, detach and remoteDebugger check against two named own imports with
observable changed return values. UntilStop survives an accelerated2second
bootstrap horizon, whereas bounded mode terminates. Tests also cover repeated
immutable callbacks, duplicate suspend count, early/late cancel, wrong owner,
owner death, genuine failed/stalled loader, independent watchdog while observer
is blocked, exact-birth refusal and guard cleanup/idempotence. Registry-control
observations in the guard fixture are explicit substitutes; real ownership,
process handles, records and process termination are exercised. No own test
claims to prove the Windows Start UI or genuine broker registration lifecycle.

own-session-proof.json contains the latest exact fixture PIDs/results. Production
activation is reserved for root after coordination with the shell restart.
