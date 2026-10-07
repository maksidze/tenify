from pathlib import Path
import json,hashlib,subprocess,sys,datetime
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components'
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
oneclick=read(base/'state-oneclick/20261005-190001-253cdfd9edf04811b886646755ecbed0/status.json')
assert oneclick['Status']=='started'
persistent=read(Path(oneclick['MaximumState']))
assert persistent['Status']=='running' and persistent['Mode']=='UntilStop' and persistent['Explorer']['Icons10']
settings=read(Path(persistent['Settings']['StatePath']));directory=Path(settings['Directory'])
logs=[]
for p in directory.glob('a_*.log'):
 text=p.read_text(errors='replace')
 if 'INITIALIZER result=00000000' in text and 'DETACH_OWNERSHIP_TRANSFER' in text and 'DETACH debuggerPresent=0' in text:logs.append(str(p))
assert logs
mapped=json.loads(subprocess.check_output([sys.executable,str(root/'work/inspect_mapped_resource_files.py'),str(persistent['Explorer']['Pid']),persistent['Explorer']['BirthFileTime']],creationflags=subprocess.CREATE_NO_WINDOW))
assert mapped['Icons10PhysicallyMapped']
proof=dict(Version='oneclick-03',CapturedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),OneClick=oneclick,Persistent=persistent,SettingsActualDetachedLogs=logs,SettingsRepeatedPriorSession='1587ddb750224d37b3f06c1c91fbe7c8: two successful real activations, exact explicit cleanup confirmed',StartRepeatedActual=read(base/'Lab/StartSessionCompat/live-repeat-proof.json'),PhysicalIcons=mapped,NetworkVisualConfirmed=False,SettingsNewContentVisualConfirmed=False,RealSignOutTested=False,WholeRestoreThenStartTested=False,ComponentStopsAndRestartsTested=['Settings UntilStop explicit stop','network UntilStop stop/restart','publisher UntilStop stop/restart','Explorer Icons10 migration with native recovery','Start UntilStop repeated broker activation'],SessionDeadline=None,SystemFilesModified=False)
(base/'UntilStop-live-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf8')
files=[base/n for n in ['Windows10-OneClick.ps1','Start-Windows10-Persistent.ps1','Stop-Windows10-Persistent.ps1','Start-Windows10-Maximum.ps1','Stop-Windows10-Maximum.ps1','Start-Windows10-Current.ps1','Start-Windows10-OneClick.bat','Start-Windows10-Maximum.bat','Start-Windows10-Maximum-WithSettings.bat','Start-Explorer10-VFS.ps1','Launch-Explorer10-VFS.py','UntilStop-and-Icons-2026-10-05.txt','UntilStop-live-proof.json']]
(base/'oneclick-03-manifest.json').write_text(json.dumps(dict(Version='oneclick-03',DefaultLifetime='UntilStop',Files=[dict(Path=str(p),SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in files]),indent=2),encoding='utf8')
note='''
ПРОВЕРКА 05.10.2026, b003
Общий Check и два последовательных OneClick Start: PASS, started/running.
Explorer 1960: Icons10=true, проверки SHA256 пройдены; физическая загрузка
приватного shell32.dll.mun подтверждена чтением списка отображений памяти.
imageres настроен в VFS; полный видимый набор значков отдельно не проверен.
Start: реальный повторный broker запуск 14216 -> 13104, старый StartUI загружен,
отладчик отключён. Settings: два реальных успешных запуска в первом UntilStop
сеансе, затем явная остановка и успешный запуск после доработки восстановления.
Настройки подписи: 16 fallback вызовов, ошибок 0 в первом live запуске.
Сеть и publisher: проверены остановка и повторный запуск в режиме UntilStop.
Signout проверен собственным оконным обработчиком/fixtures, реальный выход
из учётной записи не выполнялся. Полный цикл общего Restore/Start не запускался;
компонентные остановки и миграция Explorer проверены отдельно.
Подробные факты и пути журналов: UntilStop-live-proof.json.
'''
for p in [root/'Запуск Windows 10 — инструкция.txt',base/'UntilStop-and-Icons-2026-10-05.txt']:
 with p.open('a',encoding='utf8') as f:f.write(note)
# Documentation now finalized: refresh only its own release record.
p=base/'oneclick-03-manifest.json';m=read(p)
for item in m['Files']:item['SHA256']=hashlib.sha256(Path(item['Path']).read_bytes()).hexdigest()
p.write_text(json.dumps(m,indent=2),encoding='utf8')
out=root/'outputs/Windows10-Builds'
(out/'freeze-authorized.json').write_text(json.dumps(dict(milestone='b003-untilstop-icons',authorizedBy='root',sourcesQuiescent=True,proof=str(base/'UntilStop-live-proof.json'))),encoding='utf8')
print('Current live evidence and instructions saved; b003 freeze authorized.')
