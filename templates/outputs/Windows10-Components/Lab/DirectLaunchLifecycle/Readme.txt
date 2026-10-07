Direct shell launch lifetime — 2026-10-06

This is a separate implementation. Frozen Launch-NonUiProcess.ps1 and
NonUiProcess.cs are unchanged. No USVFS or package identity is used here.

Production entry points
  Start-Explorer10-Direct.ps1
  Start-Windows10-DirectPersistent.ps1
  Stop-Windows10-DirectPersistent.ps1
  Stop-Explorer10-Direct.ps1
  Windows10-DirectOneClick.ps1
  Confirm-NativeExplorer.ps1

Owned jobs
OwnedJobProcess.cs creates a non-inherited KILL_ON_JOB_CLOSE Job first, then
uses PROC_THREAD_ATTRIBUTE_JOB_LIST and CREATE_SUSPENDED|CREATE_NO_WINDOW.
Assignment is atomic with creation, verified using IsProcessInJob before the
initial thread is resumed. Job handles are not inherited. Dispose terminates
and drains only that Job, then closes handles. The Job also closes if its owner
is killed. ChildJob.py uses the same atomic creation mechanism for Explorer.

Preflight jobs contain the entire own test subtree. Live controller and Explorer
Jobs additionally set SILENT_BREAKAWAY_OK: ordinary user applications created
by Explorer escape both jobs. The controller's own Explorer is explicitly put
in its separate Job at creation. The live fake Explorer/fake user app proof
verified that the user app survives both normal disposal and owner death;
the fixture subsequently stops that exact own fake app using its held handle.
No real user application or system Explorer was launched by these fixtures.

Startup transaction and stop
State is atomically published under state-direct-launch/<nonce>/startup.json.
It contains exact parent PID, FILETIME birth, path, an absolute monotonic deadline
(180 seconds), and private preflight/continue/cancel/ready/commit/terminal markers. Parent identity
is checked once on a held process handle and that handle remains open.
Readiness uses the child's actual GetProcessTimes FILETIME, not a wall-clock
timestamp recorded after bootstrap. The launcher publishes an atomic ready
record only after desktop, tray, native PCS1 and USVFS0 are verified.

Startup format 2 separates hidden validation from the destructive transition.
The wrapper publishes preflight-ready.json only after the hidden child exits
successfully and its Job drains. The parent validates the exact wrapper's held
PID/birth/path plus the immutable preflight status path/hash and drained result.
Only then does it stop owned companion sessions. Stop's internal
PreserveStartupState exemption accepts only the exact current startup parent;
ordinary Stop still cancels every pending transaction. The parent publishes
transition-continue.json under the same cancellation gate. The wrapper checks
the parent's identity, deadline, cancellation and preflight hash before UAC or
shell replacement. Standalone launch explicitly self-approves after preflight.
PreflightOnly never approves. Preflight failure therefore preserves the old
shell AND companions; it no longer requests native recovery before validating
the replacement. No wrapper calls the persistent Stop while its parent owns
MaximumLaunch, avoiding cross-process mutex deadlock.

Companion order is monitor publisher, Start, network, Settings. Network's own
visibility helper obtains Settings package identity, so a fresh launch starts
it before installing the Settings debugger. Reuse with Settings already active
still requires the separate Settings auxiliary-activation bypass; changing
order is not a substitute for that fix. This change does not restart an already
compatible direct Explorer.

DirectPersistent retains the exact created launcher handle until readiness and
commit. On failure it writes durable cancellation, allows 30 seconds of cleanup,
then terminates that exact launcher if necessary and waits another 10 seconds.
Jobs clean up owned children; no process-name termination is used. A named
per-startup gate serializes cancellation with the final checks and shell-stop /
child-create operations. Committed sessions have no total runtime deadline.

Stop and OneClick Restore cancel pending startups before waiting for the common
bundle/shell transition locks. OneClick holds both locks throughout restoration,
so a pending standalone startup cannot replace the shell after Restore reports
completion. Ordinary successful components remain active if a later bundle
component fails; the report says partial-or-failed.

Recovery
Before any live replacement, an independent unelevated Recovery.py observer must
acknowledge the exact launcher identity. It waits for that launcher to exit or
its final cleanup marker. It never terminates a process. Only if this launch
recorded a shell transition, no shell currently exists, and the canonical native
Explorer image/path/hash still match may it start native Explorer, under a
separate recovery mutex. Normal cleanup delegates this one action to the same
observer, preventing duplicate native starts. A foreign/current shell is kept.
Every new standalone direct transition now holds that SAME
Local\Explorer10NativeRecovery mutex before stopping the previous shell or
creating its replacement, until new desktop readiness/commit or final owned-job
disposal. An older observer therefore waits for the new transition and then
keeps its completed shell. Its gate wait is bounded at 180 seconds. Recovery does
not acquire Windows10DirectShellLaunch, which Restore holds while waiting for
native readiness; this avoids a Restore/recovery deadlock.

The elevated AutoRestartShell guard checks exact unelevated owner birth/path
and startup cancellation before writing. A separate guard mutex serializes
overlapping guards. It retains the original value AND registry kind. Restore
only changes the value if the current value remains its DWORD0; a foreign value
is preserved. No elevated guard starts Explorer. Native recovery remains medium.
Confirm-NativeExplorer verifies both desktop and tray ownership through a held
native-process handle and reports its exact FILETIME birth.

Shared state
PS lease/state reads explicitly allow FILE_SHARE_READ|WRITE|DELETE and have a
short bounded retry for IO/access failures. No failed read extends a lease.
Read-DirectSharedJson closes its handle before ConvertFrom-Json. Find-Explorer
skips preflight directories before reading their status. AtomicStatus.write_json
is the real Python report writer, not just a test helper: after writing a complete
temporary JSON it retries os.replace only for Windows errors 5/32/33/303, for
at most 250 ms. Permanent denial raises; no stale publication is reported as
success. This is single-writer publication, not a multi-writer arbitration API.
This host still produced WinError5 for a writer while a shared reader was held
open; the own producer fixture therefore uses the real bounded-retry contract.
The Settings controller's own LeaseIO writer independently implements retry.
Settings reuse requires XamlFactory=true, the current XAML profile and factory
selector path/hash, and all current recorded dependency pins.

Evidence
own-proof.json: 11 own non-UI cases passed: whole-tree disposal, owner death,
nested preflight Jobs, two live breakaway cases, cancellation, startup timeout,
wrong parent birth, commit without lifetime timeout, cancelled mutation refusal,
and 300 genuine atomic lease replacements with simultaneous reads.
recovery-own-proof.json: normal finish, exact parent death, wrong birth refusal.
recovery-race-proof.json: genuine production mutex with simulated shell state:
new desktop preserved after 3046 ms blocked; failed transition requests simulated
fallback only after cleanup (3014 ms); recovery completes with the separate
Restore shell gate held (0 ms). No fixture starts native Explorer.
The observer did not start native Explorer in any fixture (no transition was
requested). All own fixture processes ended. PS syntax parsing passed.
status-own-proof.json: actual writer passed a transient lock (109 ms, 9 retries),
permanent denial (250 ms, old JSON preserved), and 400 replacements against 412
simultaneous shared-reader parses. No UI or system process was used.
handshake-own-proof.json records the exact executed positive/negative cases;
fixtures manipulate only private markers and fake companion state.
full-preflight-proof.json: actual hidden Explorer 8008, complete adapter/folder
proof, native PCS1/USVFS0, ownedJobDrained=true, 467 concurrent status reads.
Live Explorer13348 birth134357611701249700 remained the exact desktop owner.
The hidden wrapper emitted no transition approval and performed no UAC action.

Limits
No live shell replacement, UAC/HKLM mutation, or empty-desktop native recovery
was performed by this task. Those production paths still require the root's
coordinated migration. The hidden full preflight passed; direct Explorer 13348
was preserved. This does not claim the new live transition was executed.
The outer startup guard is 180 seconds including consent; a late UAC acceptance
after cancellation cannot pass the guard's parent/cancel checks.
Runtime monitor/generation guards still belong to the existing pinned adapters.

Integration
Re-pin the updated direct scripts and Launch-Explorer10-NoVFS.py in the root
NoVfsShellCompat manifest; add this lab's manifest as a pinned dependency.
Do not promote the old manifest hashes as matching these new files.
