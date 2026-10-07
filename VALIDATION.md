# Validation record — 2026-10-07

The initial package extracted 391 requested files (394 after the Settings dependency fixes) from a Russian Windows 10 Pro x64
19045.5487 WIM. Private resource generation, authored compilation, dependency checks
and a hidden own Explorer folder/theme/icon test passed using portable Python 3.12.10.
That test did not activate Start or Settings and did not prove their full sessions.

A subsequent user launch exposed a missing private Start AppContainer permission grant
and a corner watcher ownership conflict with an earlier still-running workspace.
Revision 2 adds journaled Start access and English launcher names, and discovers the
source image language. Fourteen tests cover masked matching, path containment, host
rejection and Russian/English image metadata selection. A full English ISO has not
been tested; no English resources are fabricated or bundled.

Current live validation and build results are recorded in the generated workspace,
not substituted into historical b013 proof files. See build-report.json,
signature-report.json, build-logs and state-oneclick-direct/status.json.

The full r2 launcher initially reported all controllers ready. Actual Settings activation
then exposed a missing isolated SettingsEnvironment.Desktop.dll dependency. The extraction,
copy, integrity and source-permission inventories now include that image file; a regression
test checks all four links. Controller readiness alone is not an application activation test.

Detailed initialization stages identified missing NT taskbar PRI resources after the
caption adapter completed. These resources and the power provider now have extraction
and AppContainer access entries. Diagnostics retain compatibility checks and stop only
the exact failed activation; they do not substitute successful return values.

After adding the missing resources and access entries, actual ms-settings:about
activation succeeded. The live process loaded the private old main/view-model,
caption/content/text/power adapters, SettingsEnvironment and old power provider.
A deliberate locked-backup fixture also passed for both ACL journal writers
(319 ms / 270 ms), with bounded retries and no permission mutation in the fixture.

Final r2 verification: the one-click launcher completed with status started and all
stages ready. StartMenuExperienceHost loaded private StartUI_.dll and WinCorHost.dll.
Settings was activated via ms-settings:about, its exact owned process was closed, and
ms-settings:taskbar reopened a new process with all eleven private old/adaptor modules.
The shell is left running. Visual appearance and every Settings page were not verified.
Runtime proof: build-logs/settings-reopen-proof.json and the newest one-click status.json.
