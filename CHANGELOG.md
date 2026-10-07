# b013 packaging revision 2 — 2026-10-07

- English launcher filenames and utility documentation/messages.
- Image metadata selects the locale; localized resources come from user media.
- Neutral executable/ABI checks stay separate from localized resource fingerprints.
- Private Start AppContainer RX grants are journaled before applying changes.
- Extract and grant access to SettingsEnvironment and NT taskbar PRI resources; include power provider access.
- Failed Settings initialization records adapter stages before exact-process recovery.
- Atomic ACL journal replacement retries temporary file locks for up to two seconds.
- Existing high-integrity corner watchers retain exclusive journal ownership.
- Start/Settings live session validation is recorded separately from hidden Explorer tests.

# Initial b013 source package — 2026-10-07

- Source Git repository, selective WIM/ESD extraction and private resource generation.
- Authored helper rebuilds, path relocation and regenerated integrity manifests.
- Portable tools/Python independent of Codex, masked code-site matching and hidden preflight.
- Stale Settings session stop recovery retained from b013.
