from pathlib import Path
import json,hashlib
lab=Path(__file__).resolve().parent
p=lab/'adapter-manifest.json';d=json.loads(p.read_text());d['ownFixture']=json.loads((lab/'own-adapter-fixture.json').read_text());d['ownFixture']['allAssertionsPassed']=True;d['ownFixture']['evidence']='own-adapter-fixture.log';d['semanticGuidMapping']='power-semantic-guid-proof.json';d['semanticGuidFlagsEqualCount']=4;d['readyForGuardedIntegration']=True;d['actualSettingsUITrialPerformed']=False;d['settersExercised']=False;d['initializerExport']='SettingsPowerInitialize';d['restoreExport']='SettingsPowerRestore';d['compositeOrder']='After existing resource/navigation/text initializer; abort owned activation if any initialization fails.';d['sourceSHA256']=hashlib.sha256((lab/'SettingsPowerCompat.c').read_bytes()).hexdigest();d['fixtureSHA256']=hashlib.sha256((lab/'PowerAdapterFixture.cs').read_bytes()).hexdigest();p.write_text(json.dumps(d,indent=2))
(lab/'Readme.txt').write_text('''Power/Sleep exact legacy provider repair, 05.10.2026

READY FOR GUARDED INTEGRATION; actual Settings UI not yet tested.
SettingsPowerCompat.dll: SHA256699f0fdea0ddcb12e9b3c5c9abc0fec0494f327ad72bd8d0d364be0f26ceb56c.
Call SettingsPowerInitialize(void*) after existing resource/navigation/text composite initialization, while this OWNED fresh Settings primary thread is paused. Nonzero failure means discard that child; do not continue partial initialization. No global provider/registration/system-file modification. SettingsPowerRestore is own-process diagnostic restore; never unload helper while patched thunks could execute.

Exact supported oldIDs:
SystemSettings_PowerAndSleep_DisplayOffTimeoutAC
SystemSettings_PowerAndSleep_DisplayOffTimeoutDC
SystemSettings_PowerAndSleep_SleepTimeoutAC
SystemSettings_PowerAndSleep_SleepTimeoutDC
Native handler renamed these to SystemSettings_PowerTimeouts_DisplayOff_AC/DC and Sleep_AC/DC. Old IDs give80070002; direct genuine old handler supplies the correct old objects.

Staged helper first calls native database. Only80070002 and exactfour IDs fall back to pinned old SettingsHandlers_OneCore_PowerAndSleep.dll/GetSetting. NativeS_OK has precedence even for an exactold ID. All other success/error cases preserve native behavior. Returned objects are genuine ISettingItem, no fabricatedDescription/Value/enumeration. Full old provider remains loaded for object/callback lifetime.

Hook four oldVM CALLsites240ae,243ad,24513,24834 inside SwitchableSettingsDatabase GetSetting/GetSettingForUser. Generic shared projections17d14/60c4 remain intact (COMDAT includes unrelated WinRT methods). Near owned-process thunks preserve direct-call ABI. Strict oldVM SHA, physical mapped-file identity, oldprovider SHA/identity and originalCALLbytes. Absolute workspacepaths: current-system build, not portable. SettingsPowerInitialize has no unconditionalfakeS_OK.

OWN FIXTURE PASS: PID13588 completedexit0 without UI/terminal. Reproduction Test-Adapter.py compiles PowerAdapterFixture.cs asGUI and runs CREATE_NO_WINDOW with25secguard. No real Settings activation and no power setters.
- Install4CALLs; actual execution of each patchedCALLtarget using nativeDB/real Windows.System.User.
- FourAC/DC IDs: QI40c037cc-d8bf-489e-8697-d66baa3221bf, exactGetId, Type6, localizedoldDescription, IPropertyValueString12 Value, IVectorView<IInspectable>16 nonempty String12 options; selectedValue occurs in options.
- ForUser reads use actual native user object. Output buffer canaries preserved.
- NativeTaskbar control parameter passes through. A nativeS_OK test double returns an actual genuine object and preserves its exactpointer; nofallback. Unrelated80070002 staysunchanged withoutfallback. IUnknown repeatedQI identity preserved.
- Restoreexact5bytes at4sites, idempotentRestore. DeliberatewrongCALLbyte onlyinownVMmemory causes8007051A before anyCALL ispatched; originalbytes restored inownfixture.
- Readonly PowerGetActiveScheme/PowerReadAC/DCValueIndex agrees with old selectedvalue indices, unitsseconds. No writes to plan/registry.

SEMANTIC STATIC PROOF4/4: exactold/new IDdescriptor chains refer to same subgroup+settingGUID andAC/DC flag. Native context GUIDs initialized atCRT, hence on-diskzero data are decoded through actualmovups/movdqu assignments. Display: subgroup7516b95f-f776-4464-8c53-06167f40cc99/setting3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e. Sleep: subgroup238c9fa8-0aad-41ed-83f4-97be242c8f20/setting29f6c1db-86da-48c5-9fdb-f2b67b1f44da. ACflag0/DCflag1 identical. Reportpower-semantic-guid-proof.json withdescriptor/CRTcodeRVAs.

LIMITS: ActualoldSettings UI refresh not yet observed. Setters are not exercised; no claim that every existingold power option/function works. AoAcIDs, Wi-Fi, lockscreen and other settings are deliberately outside fallback. Eventsubscription/scheduler lifetime in a long UI session still require guardedactual test. Textowner has separateDescriptionhook; composeinitializers ratherthan overwrite anyexistinghook. Working shell/Settingsproduction scripts have notbeenchanged by thiswork.

Evidence: adapter-manifest.json, own-adapter-fixture.json/log, power-semantic-guid-proof.json, oldVMdisassembly and ownquerylogs. Build-Adapter.py regenerates local DLL from strictImage snapshots; no system files touched.
''',encoding='utf-8-sig')
print('Manifest/doc ready, helper SHA',d['helperSHA256'])
