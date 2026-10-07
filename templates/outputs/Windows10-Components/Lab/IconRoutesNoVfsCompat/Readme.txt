No-VFS Windows 10 icon resource candidate

Status: own-process proof only; current released/live Explorer unchanged.

API
  IconRoutes.NoVfs.dll!NoVfsIconsInitialize(void*) -> DWORD
  IconRoutes.NoVfs.dll!NoVfsIconsRestore(void*) -> DWORD
  GetIconRoutePatchCount / GetIconRouteHits / GetFolderCacheKeyHits /
  GetNoVfsIconFailures(void*) -> DWORD

Install in the exact new owned signed Runtime/Explorer10/explorer.exe, before its
primary entry runs. The exact executable path/SHA is pinned. Physical native
Windows.Storage path, file SHA, original function bytes and vtable slot are
checked for the cache adapter. Resource dependencies are individually hash pinned.
Do not combine this candidate with old IconRoutes hooks or the 110 MUN overlays.
NoVfsIconsInitialize replaces both the old resource adapter and those icon MUN
mappings; this does not replace unrelated Explorer compatibility mappings.

240 canonical host paths map to data-only private resource containers. Normal
DLL loads keep native executable code. Paired DLL containers preserve all their
own non-icon resources in addition to the native MUN resource set and verified
old icon group replacements. Original b011 files are not modified.

Resource APIs match exact KERNEL32 or KERNELBASE implementation addresses.
Kernel32, KernelBase and ntdll consumer IATs are excluded; the helper's own imports
are excluded. USVFS DLL IATs are also skipped for ChildSafe compatibility, although
this candidate and its own launcher load no USVFS. GetProcAddress always returns
native LoadLibraryW/LoadLibraryExW/GetProcAddress addresses. The helper is pinned
before publishing callbacks. Resource data mappings are retained for outstanding
caller-owned icons/resources; LoadResource/SizeofResource identify mapped resource
backing without a growing HRSRC journal. Modules whose IATs are changed are held
until restoration. Foreign slot ownership is refused before restoration.

Folder cache scope
  Windows.Storage!CExtractIcon::IExtractIconW vtable RVA 0x652538, slot3.
  Native method first; only imageres.dll -3/-4; no custom icon changes.
  Preserve genuine error, flags and index. A buffer too short for the private
  path remains native. This changes the resource cache key, not the folder's
  desktop.ini or registry. No folded method/global export is patched.

Meaningful own proof
  - Resource extraction through 235 paths with numeric icon group IDs versus
    their private container. The remaining five named-only group routes retain
    build-time resource verification but were not painted by this C fixture.
  - Real native loader pointer and a bounded own child LoadLibrary operation.
  - Native non-icon resource unchanged; late DLL callbacks and concurrent loads.
  - Foreign IAT rejected by both reinitialize and restore; native import rollback.
  - Native / no-VFS / no-VFS-plus-private-folder-key image matrix on the SAME
    own folder. Native-first jumbo96 stays cached11 until the private key is used.
  - Private-key96 exactly matches genuine explicit private resource rendering.
  - Wrong icon ID, different resource path, short buffer, canaries remain native.
  - Targeted own IThumbnailCache force extraction changes the native cached
    preview; the next GetImage reads the new genuine old preview.
  - Actual explorer.exe path extraction equals genuine Windows 10 Explorer.
  - All created processes finish; never-switched desktop closes; no USVFS module.
  Exact DLL hashes, process IDs, results and pixel hashes are in own-proof.json.

The initializer does NOT clear shared icon caches or refresh user folders/pins.
Persisted user thumbnails need a separately coordinated, item-scoped refresh.
Delayed imports, ordinal resource calls or direct native internal calls may need
additional evidence; a route table is not proof of every Windows icon consumer.

Rollback/lifetime
  Restore is for a quiescent own fixture or entry-held bootstrap only.
  Live rollback terminates the exact owned Explorer and restores the previous
  launch profile. It is not a concurrent hot-uninstall API.
  Publication/protection failures are terminal; the parent must abort the exact
  newly created host. Do not continue an initializer that returned an error.
  A protection-restoration failure makes a repeated Restore refuse; it cannot
  report success merely because the pointer was already put back. Cache-slot
  restoration checks the CAS result and preserves a competing foreign pointer.
  These uncommon API-failure/race paths were reviewed statically; the fixture
  exercises ordinary restore and a pre-existing foreign pointer, not injected
  VirtualProtect failures or a precisely timed external CAS race.
  GetNoVfsIconFailures reports later resource-patching failures for diagnostics.

Build-Test.py builds only private files and launches bounded own children with
CREATE_NO_WINDOW. Frozen IconResourceMaximum and system files are read-only inputs.
