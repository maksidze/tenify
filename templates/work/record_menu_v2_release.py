from pathlib import Path
import datetime, hashlib, json
ROOT=Path(__file__).resolve().parent.parent
B=ROOT/'outputs/Windows10-Components'
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
latest=lambda folder:max(folder.glob('*/status.json'),key=lambda p:p.stat().st_mtime)
one=read(latest(B/'state-oneclick'))
assert one['Version']=='oneclick-08' and one['Status']=='started',one
persistent=read(Path(one['MaximumState']))
assert persistent['Status']=='running' and persistent['SettingsIncluded']
vfs=read(Path(persistent['Explorer']['VfsRun'])/'status.json')
assert vfs['shellUXRevision']==8 and vfs['menuSquareHook']['version']==2
assert all(x['iatMatched'] for x in vfs['menuSquareHook']['callers'])
proof={'RecordedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'OneClick':one,'Persistent':persistent,'MenuSquare':vfs['menuSquareHook'],'WinX':vfs['winXHook'],'Icons':vfs['iconResourceHook'],'ElevatedCorners':read(B/'Lab/ElevatedCornersCompat/state/current.json'),'UserVisualVerification':{'WinXImmersiveRowsAndCommands':True,'ElevatedWindowCorners':True,'MenuSquareV2':'pending fresh user check'},'SystemFilesModified':False}
(B/'b007-live-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8')
old=read(B/'oneclick-06-manifest.json')
paths={Path(x['Path']) for x in old['Files']}
paths.discard(B/'Launch-MenuSquareCompat.py')
paths|={B/'Validate-ShellExtensions.py',B/'Launch-ResourceCompat.py',B/'Lab/MenuAppearanceCompatV2/manifest.json',B/'Lab/MenuAppearanceCompatV2/Launch-MenuSquareV2.py',B/'Lab/MenuAppearanceCompatV2/MenuSquareV2.dll',B/'Lab/ElevatedCornersCompat/manifest.json',B/'Lab/ElevatedCornersCompat/ElevatedCorners.ps1',B/'Lab/ElevatedCornersCompat/ElevatedCornerHost.exe'}
(B/'oneclick-08-manifest.json').write_text(json.dumps({'Version':'oneclick-08','DefaultLifetime':'UntilStop','Files':[{'Path':str(p),'SHA256':sha(p)}for p in sorted(paths)],'Proof':'b007-live-proof.json'},indent=2),encoding='utf-8')
doc=(B/'OneClick-07-Instructions.txt').read_text(encoding='utf-8-sig').replace('— oneclick-07,','— oneclick-08,')
doc=doc.replace('Готовность повышенного обработчика проверена; визуальный результат ожидает\nпроверки пользователя.','Пользователь подтвердил прямые углы административных окон и увеличенные строки Win+X.')
doc+='\nВ oneclick-08 исправлен повторный возврат скругления меню: адаптер V2 охватывает\nтри точных обработчика uxtheme, PCS и shell32. Подключается после WinX.\nСобственные 12 скрытых меню и подменю прошли проверку прямых углов, размеров,\nкоманд и восстановления. Общий запуск проверяет все три перехвата в памяти.\nВизуальная проверка текущего рабочего сеанса отмечается отдельно в b007-live-proof.json.\nПодробнее: Lab\\MenuAppearanceCompatV2\\Readme.txt.\n'
for p in [ROOT/'Запуск Windows 10 — инструкция.txt',B/'OneClick-08-Instructions.txt']:p.write_text(doc,encoding='utf-8-sig')
issues='''ТЕКУЩИЕ ОТКРЫТЫЕ ПРОБЛЕМЫ — 6 октября 2026

Текущая цепочка: oneclick-08, shell UX revision 8.
Пользователь подтвердил увеличенное оформление Win+X, работу его команд,
прямые углы административных окон, цвет и открытие сетевого индикатора.
Повторное скругление меню Explorer/Win+X исправлено адаптером V2 трёх
обработчиков. Изолированные меню и общий запуск проверены; новый видимый
результат требует отдельной проверки пользователя.

1. Поиск из Win+X и начало печати в старом Пуске вызывают Windows 11.
2. Сетевая панель и JumpView пока используют штатные компоненты Windows 11.
Кандидаты оформления и их общий контроллер ещё не включены в рабочую цепочку.
3. Не завершены Дисплей, Центр обновления, планшетное автоскрытие Параметров,
полная палитра, шрифтовые/AppX значки и старый центр уведомлений.
4. Первый холодный запрос Win+X иногда истекает по тайм-ауту; следующий работает.

Исторические b004/b005 имеют ошибку запуска дочерних процессов через
адаптер значков/USVFS; она исправлена в b006 и последующих версиях.
Системные файлы не изменяются. UntilStop действует до возврата/выхода;
автозапуск после перезагрузки не установлен.
'''
(B/'Open-Issues-2026-10-06.txt').write_text(issues,encoding='utf-8-sig')
print(json.dumps({'Explorer':persistent['Explorer'],'OneClickStatus':one['Status'],'MenuV2':vfs['menuSquareHook']['helperSHA256']},indent=2))
