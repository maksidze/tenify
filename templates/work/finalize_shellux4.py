from pathlib import Path
import json,hashlib,datetime
ROOT=Path(__file__).resolve().parent.parent
BASE=ROOT/'outputs/Windows10-Components'
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
oneclick=BASE/'state-oneclick/20261005-194340-40d434f2479e417eb7ea026316d05a91/status.json'
persistent=BASE/'state-persistent/0607d8d911764fcda4ab4d43e33f99df/status.json'
run=read(persistent);vfs_path=Path(run['Explorer']['VfsRun'])/'status.json';vfs=read(vfs_path)
assert read(oneclick)['Status']=='started' and run['Status']=='running'
assert vfs['shellUXRevision']==4 and vfs['classicContextHook']['Installed'] and vfs['winXHook']['stats']['hotkeyInstalled']==1
assert vfs['iconResourceHook']['result']==0 and vfs['iconResourceHook']['patches']>0
proof={
 'RecordedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'OneClick':str(oneclick),'Persistent':run,'VfsStatus':str(vfs_path),
 'IsolatedPreflight':read(Path((BASE/'Lab/IconResourceCompat/latest-isolated-preflight.txt').read_text())/'status.json')['status'],
 'Icons':vfs['icons10Validation'],'IconRouteHook':vfs['iconResourceHook'],
 'ClassicContextHook':vfs['classicContextHook'],'WinXHook':vfs['winXHook'],
 'NetworkIntegrationProof':read(BASE/'Lab/NetworkTrayVisibilityCompat/integration-proof.json'),
 'NetworkCurrentState':read(BASE/'shellux4-network-state.json'),
 'NetworkCurrentPreference':(BASE/'shellux4-network-visibility.txt').read_text(encoding='utf-8-sig'),
 'MappedResources':read(BASE/'shellux4-mapped-resources.json'),
 'PreflightGuard':read(BASE/'preflight-guard-proof.json'),
 'VisibleMenusUserConfirmed':False,'AllVisibleIconsReplaced':False,'SystemFilesModified':False,
 'Limitations':['Windows 11 Task View remains native','AppX assets, font glyphs and third-party application icons outside PE resource overlay','Visible menus and native command execution need user observation','Settings Display and Update incomplete']}
stats=BASE/'Lab/WinXCompat/live-proof.json'
if stats.is_file():proof['LiveWinXStats']=read(stats)
repeat=BASE/'shellux4-repeat-proof.json'
if repeat.is_file():proof['RepeatLaunch']=read(repeat)
(BASE/'b004-live-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8')
guide='''ЗАПУСК WINDOWS 10 НА WINDOWS 11 — oneclick-04, 5 октября 2026

ЗАПУСК
Дважды нажмите «Запустить Windows 10.bat» в папке проекта.
Альтернативный путь: outputs\\Windows10-Components\\Start-Windows10-OneClick.bat.
Запускайте обычным способом, не от имени администратора. Для защитного
контроллера при замене оболочки может появиться UAC. Перед первым включением
закройте штатные «Параметры» Windows 11. При обновлении набора перезапускается
только точный экземпляр лабораторного Explorer; его окна могут закрыться.
Повторный BAT проверяет версии активных адаптеров и использует готовые сеансы.

ЧТО ВКЛЮЧЕНО
Explorer 10; Пуск с плитками; старые Параметры с повторным открытием;
исправления подписей и списков питания; горизонтальный индикатор языка;
источник мониторов для Alt+Tab и представления задач; квадратные углы;
отключённая схема Snap Layouts при наведении на кнопку разворачивания.

В oneclick-04 добавлены:
— классический обработчик меню файлов и фона папки;
— восстановление меню правого клика по «Пуску» и отдельного пути Win+X;
— настоящий сетевой индикатор, автоматически выведенный на основную панель;
— 2620 групп значков Windows 10 в 130 частных ресурсных файлах.
Из них 110 MUN подключаются через VFS, ещё 20 DLL/EXE обслуживает адаптер
ресурсов. Исполняемый код этих DLL и неиконковые ресурсы остаются штатными.
Значки сторонних программ, шрифтовые символы WinUI и AppX assets этим набором
не заменяются. Отдельные хосты интерфейса требуют собственных маршрутов.
Глобальный кэш значков не удаляется. Полная визуальная идентичность не заявляется.

СРОК РАБОТЫ
Исправные компоненты работают UntilStop: часового выключения нет.
Выключение происходит по команде возврата, при выходе из учётной записи либо
потере своего контроллера. Пуск, мониторы и сеть привязаны к точному Explorer.
Тайм-ауты первоначальной загрузки и защита от зависаний сохранены.
Автозапуск после перезагрузки не установлен: снова нажмите BAT.

ВОЗВРАТ И ПРОВЕРКА
«Вернуть Windows 11.bat» останавливает сеансы проекта и возвращает штатный
Explorer, исходные углы и Snap. Для сетевого индикатора восстанавливается
его индивидуальная настройка видимости перед остановкой обработчика.
«Проверить запуск Windows 10.bat» проверяет зависимости и SHA256 без запуска.
Системные файлы не заменяются; используются частные копии, VFS, изменения
памяти собственных процессов и обратимые настройки пользователя.

ОГРАНИЧЕНИЯ
Представление задач пока от Windows 11. Не завершены Дисплей, Центр обновления
и планшетное автоскрытие в старых Параметрах. Theme10, полная палитра, старый
центр уведомлений, поиск, Диспетчер задач и Диспетчер устройств не включены.
Меню Win+X использует настоящий текущий список команд, включая Терминал.
Проверки загрузки адаптеров и собственной отрисовки пройдены; видимый результат
меню в рабочем сеансе и выполнение выбранных команд проверяются отдельно.

ЖУРНАЛЫ И СБОРКИ
Журналы общего запуска: outputs\\Windows10-Components\\state-oneclick
и state-persistent. Подробности изменений: Shell-Menus-and-Icons-2026-10-05.txt.
Проверенный состав текущего запуска: b004-live-proof.json.
Снимки хранятся в outputs\\Windows10-Builds. Они предназначены для этой
системы и восстановленных исходных путей; смотрите Инструкция.txt внутри.
Не перемещайте Image, Tools, Runtime, Lab и Python runtime.

ПОРЯДОК ДИАГНОСТИКИ
Полный Explorer preflight выполняйте до включения живого старого Пуска.
Отдельный рабочий стол не изолирует системную активацию пакетов. Обёртка
Run-IsolatedPreflight.py теперь отказывает при активном сеансе старого Пуска.
Рабочая оболочка оставлена без подключённого отладчика.
'''
(ROOT/'Запуск Windows 10 — инструкция.txt').write_text(guide,encoding='utf-8-sig')
(BASE/'OneClick-04-Instructions.txt').write_text(guide,encoding='utf-8-sig')
paths=[BASE/name for name in ['Windows10-OneClick.ps1','Start-Windows10-Persistent.ps1','Stop-Windows10-Persistent.ps1','Launch-Explorer10-VFS.py','Launch-ClassicContextMenuCompat.py','Launch-WinXCompat.py','Launch-IconResourceMaximum.py','Validate-ShellExtensions.py','Start-Explorer10-VFS.ps1','Start-Windows10-OneClick.bat','OneClick-04-Instructions.txt','Shell-Menus-and-Icons-2026-10-05.txt','b004-live-proof.json']]
manifest={'Version':'oneclick-04','DefaultLifetime':'UntilStop','Files':[{'Path':str(p),'SHA256':sha(p)} for p in paths]}
(BASE/'oneclick-04-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'Explorer':run['Explorer'],'ManifestSHA256':sha(BASE/'oneclick-04-manifest.json')},indent=2))
